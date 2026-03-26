<script>
        // Global state
        let conversations = [];
        let filteredConversations = [];
        let messages = [];
        let selectedConversationId = null;
        let currentUser = null;
        let refreshInterval = null;

        // WebSocket state
        let websocket = null;
        let globalWebSocket = null; // Global connection for all conversations
        let reconnectAttempts = 0;
        let maxReconnectAttempts = 10;
        let reconnectDelay = 1000; // Start with 1 second
        let typingTimeout = null;
        let isTyping = false;
        let activeUsers = new Set();
        let audioContext = null;
        let notificationQueue = [];
        let isAudioInitialized = false;
        
        // Enhanced connection state management
        let connectionState = 'disconnected'; // disconnected, connecting, connected, reconnecting, poor
        let connectionQuality = 'good'; // good, poor, offline
        let lastPingTime = null;
        let lastPongTime = null;
        let missedPings = 0;
        let connectionLatency = 0;
        
        // Enhanced message buffering for offline state
        let messageBuffer = [];
        let deliveryReceipts = new Map();
        let readReceipts = new Map();
        let pendingMessages = new Map(); // Track message delivery status
        let messageRetryQueue = [];
        let offlineMessageQueue = [];
        
        // Rate limiting
        let lastMessageTime = 0;
        let messagesSentInLastMinute = 0;
        let messageRateLimit = 30; // messages per minute
        
        // Typing indicators
        let typingUsers = new Map();
        let localTypingTimeout = null;
        
        // Enhanced notifications
        let notificationPermission = null;
        let soundEnabled = true;
        let desktopNotificationsEnabled = true;
        
        // Performance optimization
        let lastDOMUpdate = 0;
        let pendingDOMUpdates = new Set();
        let updateQueue = [];
        
        // Connection monitoring
        let pingInterval = null;
        let connectionMonitorInterval = null;
        let qualityCheckInterval = null;

        // Helper function to detect mobile
        function isMobile() {
            return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
        }

        // Enhanced fetch function that handles both cookies and tokens
        async function authenticatedFetch(url, options = {}) {
            const sessionToken = localStorage.getItem('sessionToken');
            
            const defaultOptions = {
                credentials: 'include',
                headers: {
                    'Content-Type': 'application/json',
                    ...options.headers
                }
            };
            
            if (isMobile() && sessionToken) {
                defaultOptions.headers['Authorization'] = `Bearer ${sessionToken}`;
            }
            
            return fetch(url, { ...defaultOptions, ...options });
        }

        // Enhanced auth check function
        async function enhancedCheckAuth() {
            try {
                const response = await authenticatedFetch('https://spear-exchange.lenny-paz123.workers.dev/api/me');
                
                if (response.ok) {
                    const data = await response.json();
                    return { success: true, user: data.user };
                } else {
                    localStorage.removeItem('user');
                    localStorage.removeItem('sessionToken');
                    return { success: false };
                }
            } catch (error) {
                console.error('Auth check failed:', error);
                localStorage.removeItem('user');
                localStorage.removeItem('sessionToken');
                return { success: false };
            }
        }

        // Enhanced logout function
        async function enhancedLogout() {
            try {
                await authenticatedFetch('https://spear-exchange.lenny-paz123.workers.dev/api/logout', {
                    method: 'POST'
                });
            } catch (error) {
                console.error('Logout error:', error);
            } finally {
                localStorage.removeItem('user');
                localStorage.removeItem('sessionToken');
                window.location.href = '../login';
            }
        }

        // Initialize the page
        document.addEventListener('DOMContentLoaded', async () => {
            await checkAuthentication();
            await initializeEnhancedFeatures();
            await loadConversations();
            setupEventListeners();
            startAutoRefresh();
            
            // Initialize global WebSocket connection
            connectGlobalWebSocket();
            
            // Initialize audio on first user interaction
            document.addEventListener('click', initializeAudioContext, { once: true });
            document.addEventListener('keydown', initializeAudioContext, { once: true });
            
            // Cleanup on page unload
			window.addEventListener('beforeunload', () => {
				// Stop typing indicators
				if (isTyping && websocket && websocket.readyState === WebSocket.OPEN) {
					sendWebSocketMessage('typing_stop');
				}

				// Close websocket cleanly
				if (websocket) {
					websocket.close(1000, 'Page unloading');
				}

				if (refreshInterval) {
					clearInterval(refreshInterval);
				}
			});
            
            // Handle visibility change to manage connections
            document.addEventListener('visibilitychange', handleVisibilityChange);
            
            // Handle network status changes
            window.addEventListener('online', handleNetworkOnline);
            window.addEventListener('offline', handleNetworkOffline);
            
            // Handle focus/blur for notifications
            window.addEventListener('focus', handleWindowFocus);
            window.addEventListener('blur', handleWindowBlur);
        });
        
        // Initialize enhanced features
        async function initializeEnhancedFeatures() {
            // Request notification permission
            if ('Notification' in window) {
                notificationPermission = await Notification.requestPermission();
                desktopNotificationsEnabled = notificationPermission === 'granted';
            }
            
            // Initialize connection status UI
            createConnectionStatusIndicator();
            
            // Start connection monitoring
            startConnectionMonitoring();
            
            // Load user preferences
            loadUserPreferences();
            
            console.log('✅ Enhanced messaging features initialized');
        }
        
        // Create connection status indicator
        function createConnectionStatusIndicator() {
            const indicator = document.createElement('div');
            indicator.id = 'connection-status';
            indicator.className = 'connection-status offline';
            indicator.innerHTML = `
                <i class="fas fa-circle"></i>
                <span>Connecting...</span>
            `;
            
            // Add to chat header
            const chatHeader = document.getElementById('chat-header');
            if (chatHeader) {
                chatHeader.appendChild(indicator);
            } else {
                // Add to page if no chat header
                document.body.appendChild(indicator);
            }
        }
        
        // Update connection status UI
        function updateConnectionStatus(state, options = {}) {
            connectionState = state;
            const indicator = document.getElementById('connection-status');
            if (!indicator) return;
            
            // Clear all state classes
            indicator.className = 'connection-status';
            
            let icon, text, className;
            switch (state) {
                case 'connected':
                    icon = 'fas fa-circle';
                    text = connectionQuality === 'poor' ? 'Poor connection' : 'Connected';
                    className = connectionQuality === 'poor' ? 'poor' : 'online';
                    break;
                case 'connecting':
                    icon = 'fas fa-circle-notch';
                    text = 'Connecting...';
                    className = 'connecting';
                    break;
                case 'reconnecting':
                    icon = 'fas fa-redo-alt';
                    text = `Reconnecting... (${reconnectAttempts}/${maxReconnectAttempts})`;
                    className = 'reconnecting';
                    break;
                case 'disconnected':
                case 'offline':
                default:
                    icon = 'fas fa-exclamation-circle';
                    text = 'Offline';
                    className = 'offline';
                    break;
            }
            
            indicator.className = `connection-status ${className}`;
            indicator.innerHTML = `
                <i class="${icon}"></i>
                <span>${text}</span>
            `;
            
            // Add latency info if available
            if (connectionLatency > 0 && state === 'connected') {
                const latencyText = connectionLatency < 100 ? 'Fast' : 
                                   connectionLatency < 300 ? 'Good' : 'Slow';
                indicator.innerHTML += ` <small>(${latencyText})</small>`;
            }
        }

        // Load user preferences
        function loadUserPreferences() {
            try {
                const prefs = JSON.parse(localStorage.getItem('messagePreferences') || '{}');
                soundEnabled = prefs.soundEnabled !== false;
                desktopNotificationsEnabled = prefs.desktopNotificationsEnabled !== false;
            } catch (error) {
                console.warn('Failed to load preferences:', error);
            }
        }
        
        // Save user preferences
        function saveUserPreferences() {
            try {
                localStorage.setItem('messagePreferences', JSON.stringify({
                    soundEnabled,
                    desktopNotificationsEnabled
                }));
            } catch (error) {
                console.warn('Failed to save preferences:', error);
            }
        }
        
        // Handle window visibility changes
        function handleVisibilityChange() {
            if (document.hidden) {
                console.log('🔄 Page hidden - reducing activity');
                // Reduce ping frequency when hidden
                if (pingInterval) {
                    clearInterval(pingInterval);
                    pingInterval = setInterval(sendPing, 60000); // 1 minute when hidden
                }
            } else {
                console.log('🔄 Page visible - resuming normal activity');
                // Resume normal ping frequency
                if (pingInterval) {
                    clearInterval(pingInterval);
                    pingInterval = setInterval(sendPing, 30000); // 30 seconds when visible
                }
                
                // Reconnect if needed
                if (!globalWebSocket || globalWebSocket.readyState !== WebSocket.OPEN) {
                    setTimeout(connectGlobalWebSocket, 1000);
                }
                if (selectedConversationId && (!websocket || websocket.readyState !== WebSocket.OPEN)) {
                    setTimeout(() => connectWebSocket(selectedConversationId), 1500);
                }
                
                // Clear any queued notifications
                clearNotificationQueue();
            }
        }
        
        // Handle network status changes
        function handleNetworkOnline() {
            console.log('📶 Network back online');
            connectionQuality = 'good';
            updateConnectionStatus('connecting');
            
            // Hide offline indicator
            hideOfflineIndicator();
            
            // Attempt to reconnect
            setTimeout(() => {
                connectGlobalWebSocket();
                if (selectedConversationId) {
                    connectWebSocket(selectedConversationId);
                }
                
                // Process any buffered messages
                setTimeout(processMessageBuffer, 2000);
            }, 1000);
        }
        
        function handleNetworkOffline() {
            console.log('📵 Network offline');
            connectionQuality = 'offline';
            updateConnectionStatus('offline');
        }
        
        // Handle window focus events for notifications
        function handleWindowFocus() {
            clearNotificationQueue();
        }
        
        function handleWindowBlur() {
            // Enable enhanced notifications when window is not focused
        }
        
        // Cleanup function
        function cleanup() {
            console.log('🧹 Cleaning up connections...');
            
            // Close WebSocket connections gracefully
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                websocket.close(1000, 'Page unload');
            }
            if (globalWebSocket && globalWebSocket.readyState === WebSocket.OPEN) {
                globalWebSocket.close(1000, 'Page unload');
            }
            
            // Clear intervals
            [refreshInterval, pingInterval, connectionMonitorInterval, qualityCheckInterval].forEach(interval => {
                if (interval) clearInterval(interval);
            });
            
            // Clear timeouts
            [typingTimeout, localTypingTimeout].forEach(timeout => {
                if (timeout) clearTimeout(timeout);
            });
        }
        // Update conversation unread count
        function updateConversationUnreadCount(conversationId) {
            const conversationElement = document.querySelector(`[data-conversation-id="${conversationId}"]`);
            if (conversationElement) {
                let unreadElement = conversationElement.querySelector('.unread-count');
                if (!unreadElement) {
                    unreadElement = document.createElement('span');
                    unreadElement.className = 'unread-count';
                    const metaElement = conversationElement.querySelector('.conversation-meta');
                    if (metaElement) {
                        metaElement.appendChild(unreadElement);
                    }
                }
                
                // Get current count and increment
                const currentCount = parseInt(unreadElement.textContent) || 0;
                unreadElement.textContent = currentCount + 1;
            }
        }
        
        // Enhanced WebSocket message handler for conversation
        function handleWebSocketMessage(data) {
            console.log('💬 WebSocket message:', data.type);
            
            switch (data.type) {
                case 'connection_established':
                    console.log('✅ Conversation connection established');
                    updateConnectionStatus('connected');
                    break;
                    
                case 'new_message':
                    if (data.conversationId === selectedConversationId) {
                        // Add message to current conversation
                        const messageElement = createMessageElement({
                            id: data.messageId,
                            sender_id: data.senderId,
                            sender_name: data.senderName,
                            message: data.content,
                            created_at: data.timestamp
                        }, 'delivered');
                        
                        const messagesArea = document.getElementById('messages-area');
                        if (messagesArea) {
                            messagesArea.appendChild(messageElement);
                            scrollToBottom(true);
                        }
                        
                        // Play sound for received messages
                        if (data.senderId !== currentUser.id) {
                            playNotificationSound('message');
                        }
                    }
                    break;
                    
                case 'typing_start':
                    if (data.userId !== currentUser.id) {
                        showTypingIndicator(data.userName);
                    }
                    break;
                    
                case 'typing_stop':
                    hideTypingIndicator(data.userId);
                    break;
                    
                case 'delivery_receipt':
                    updateMessageStatus(data.messageId, 'delivered');
                    break;
                    
                case 'read_receipt':
                    updateMessageStatus(data.messageId, 'read');
                    break;
                    
                case 'user_joined':
                    console.log(`User ${data.userName} joined the conversation`);
                    break;
                    
                case 'user_left':
                    console.log(`User ${data.userName} left the conversation`);
                    hideTypingIndicator(data.userId);
                    break;
                    
                case 'ping':
                    // Respond to server ping
                    if (websocket && websocket.readyState === WebSocket.OPEN) {
                        websocket.send(JSON.stringify({
                            type: 'pong',
                            timestamp: data.timestamp,
                            clientTime: Date.now()
                        }));
                    }
                    break;
                    
                case 'pong':
                    handlePongResponse(data);
                    break;
                    
                case 'catchup_start':
                    console.log(`🔄 Receiving ${data.messageCount} missed messages`);
                    break;
                    
                case 'missed_message':
                    // Handle missed message during catchup
                    const missedMessageElement = createMessageElement({
                        id: data.messageId,
                        sender_id: data.senderId,
                        sender_name: data.senderName,
                        message: data.content,
                        created_at: data.timestamp
                    });
                    
                    const messagesArea2 = document.getElementById('messages-area');
                    if (messagesArea2) {
                        messagesArea2.appendChild(missedMessageElement);
                    }
                    break;
                    
                case 'catchup_complete':
                    console.log('✅ Message catchup complete');
                    scrollToBottom();
                    break;
                    
                case 'error':
                    console.error('❌ WebSocket error:', data.message);
                    if (data.tempId) {
                        updateMessageStatus(data.tempId, 'failed');
                    }
                    showErrorFeedback(data.message);
                    break;
                    
                default:
                    console.log('🤷 Unknown message type:', data.type);
            }
        }
           
        // Check authentication
        async function checkAuthentication() {
            const authResult = await enhancedCheckAuth();
            
            if (authResult.success) {
                currentUser = authResult.user;
                document.getElementById('user-name').textContent = authResult.user.name || 'User';
                document.getElementById('user-avatar').textContent = (authResult.user.name || 'U').charAt(0).toUpperCase();
                document.getElementById('mobile-user-name').textContent = authResult.user.name || 'User';
                document.getElementById('mobile-user-avatar').textContent = (authResult.user.name || 'U').charAt(0).toUpperCase();
                console.log('✅ Authentication successful');
            } else {
                console.log('❌ Not authenticated, redirecting to login...');
                window.location.href = '../login';
            }
        }

        // Load conversations from API
        async function loadConversations() {
            try {
                showConversationsLoading(true);
                
                console.log('📥 Loading conversations from API...');
                const response = await authenticatedFetch('https://spear-exchange.lenny-paz123.workers.dev/api/conversations');
                
                if (response.ok) {
                    const data = await response.json();
                    conversations = data.conversations || [];
                    filteredConversations = [...conversations];
                    
                    console.log(`✅ Loaded ${conversations.length} conversations`);
                    
                    if (conversations.length > 0) {
                        displayConversations();
                        
                        // Auto-select first conversation if none selected
                        if (!selectedConversationId) {
                            selectConversation(conversations[0].id);
                        }
                    } else {
                        showEmptyConversations();
                    }
                } else {
                    console.error('Failed to load conversations:', response.status, response.statusText);
                    throw new Error('Failed to load conversations');
                }
            } catch (error) {
                console.error('Error loading conversations:', error);
                showEmptyConversations();
            } finally {
                showConversationsLoading(false);
            }
        }

        // Display conversations in sidebar
        function displayConversations() {
            const conversationsList = document.getElementById('conversations-list');
            
            if (filteredConversations.length === 0) {
                showEmptyConversations();
                return;
            }

            hideEmptyConversations();
            
            conversationsList.innerHTML = '';
            
            filteredConversations.forEach(conversation => {
                const conversationElement = createConversationElement(conversation);
                conversationsList.appendChild(conversationElement);
            });
            
            // Reapply active state after rebuilding the list
            if (selectedConversationId) {
                const activeItem = conversationsList.querySelector(`[data-conversation-id="${selectedConversationId}"]`);
                if (activeItem) {
                    activeItem.classList.add('active');
                }
            }
        }

        // Create conversation element
        function createConversationElement(conversation) {
            const element = document.createElement('div');
            element.className = `conversation-item ${conversation.id === selectedConversationId ? 'active' : ''}`;
            element.setAttribute('data-conversation-id', conversation.id);
            element.onclick = () => selectConversation(conversation.id);

            // Use the image URL from the API response (already parsed)
            const imageContent = conversation.listing.image_url
                ? `<img src="${conversation.listing.image_url}" alt="${conversation.listing.title}" onerror="this.style.display='none'">`
                : `<i class="fas fa-image"></i>`;

            element.innerHTML = `
                <div class="conversation-header">
                    <div class="conversation-listing">
                        <div class="listing-thumbnail">
                            ${imageContent}
                        </div>
                        <div class="conversation-details">
                            <div class="listing-title">${escapeHtml(conversation.listing.title)}</div>
                            <div class="other-user">
                                <i class="fas fa-user"></i>
                                ${escapeHtml(conversation.other_user.name)}
                                <i class="fas fa-check-circle verified-badge"></i>
                            </div>
                        </div>
                    </div>
                    <div class="conversation-time">${formatConversationTime(conversation.last_message_at)}</div>
                </div>
                <div class="last-message">${escapeHtml(conversation.last_message_preview || 'No messages yet')}</div>
                <div class="conversation-meta">
                    <span class="user-role ${conversation.other_user.role}">${capitalizeFirst(conversation.other_user.role)}</span>
                    ${conversation.unread_count > 0 ? `<span class="unread-count">${conversation.unread_count}</span>` : ''}
                </div>
            `;

            return element;
        }

        // Select a conversation
        async function selectConversation(conversationId) {
            if (selectedConversationId === conversationId) return;
            
            console.log(`🎯 Selecting conversation ${conversationId}`);
            selectedConversationId = conversationId;
            
            // Update active conversation in UI
            updateActiveConversation(conversationId);
            
            try {
                showChatLoading();
                
                // Load conversation details and messages
                const conversation = conversations.find(c => c.id === conversationId);
                if (conversation) {
                    loadConversationDetails(conversation);
                }
                
                await loadMessages(conversationId);
                
                // Connect WebSocket for this conversation
                connectWebSocket(conversationId);
                
                // Mark messages as read
                await markMessagesAsRead(conversationId);
                
                showChatInterface();
                
                // Enhanced auto-scroll for conversation load
                setTimeout(() => {
                    scrollToBottom();
                }, 100);
                
                // Focus message input
                const messageInput = document.getElementById('message-input');
                if (messageInput) {
                    messageInput.focus();
                }
                
                // Show mobile chat view on mobile
                if (window.innerWidth <= 800) {
                    showMobileChatView();
                }
                
            } catch (error) {
                console.error('❌ Error loading conversation:', error);
                showChatError();
            }
        }
        
        // Update active conversation in UI
        function updateActiveConversation(conversationId) {
            document.querySelectorAll('.conversation-item').forEach(item => {
                item.classList.remove('active');
            });
            
            const selectedItem = document.querySelector(`[data-conversation-id="${conversationId}"]`);
            if (selectedItem) {
                selectedItem.classList.add('active');
                
                // Clear unread count when entering conversation
                const unreadElement = selectedItem.querySelector('.unread-count');
                if (unreadElement) {
                    unreadElement.remove();
                }
            }
        }

        // Load conversation details
        async function loadConversationDetails(conversation) {
            console.log(`📄 Loading conversation details for ${conversation.id}`);
            
            console.log('📄 Found conversation:', conversation);

            // Update chat header
            const chatThumbnail = document.getElementById('chat-listing-thumbnail');
            const chatTitle = document.getElementById('chat-listing-title');
            const chatPrice = document.getElementById('chat-listing-price');
            const chatOtherUser = document.getElementById('chat-other-user-name');
            const chatUserRole = document.getElementById('chat-user-role');

            // Use the image URL from the API response
            const imageContent = conversation.listing.image_url
                ? `<img src="${conversation.listing.image_url}" alt="${conversation.listing.title}" onerror="this.style.display='none'">`
                : `<i class="fas fa-image"></i>`;

            if (chatThumbnail) chatThumbnail.innerHTML = imageContent;
            if (chatTitle) chatTitle.textContent = conversation.listing.title;
            if (chatPrice) chatPrice.textContent = `$${conversation.listing.price.toFixed(2)}`;
            if (chatOtherUser) chatOtherUser.textContent = conversation.other_user.name;
            if (chatUserRole) {
                chatUserRole.textContent = capitalizeFirst(conversation.other_user.role);
                chatUserRole.className = `user-role ${conversation.other_user.role}`;
            }
            
            console.log('✅ Conversation details loaded successfully');
        }

        // Load messages for conversation
        async function loadMessages(conversationId) {
            try {
                console.log(`📥 Loading messages for conversation ${conversationId}`);
                const response = await authenticatedFetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${conversationId}/messages`);
                
                if (response.ok) {
                    const data = await response.json();
                    messages = data.messages || [];
                    console.log(`✅ Loaded ${messages.length} messages`);
                    displayMessages();
                } else {
                    console.error('❌ Failed to load messages:', response.status, response.statusText);
                    throw new Error('Failed to load messages');
                }
            } catch (error) {
                console.error('❌ Error loading messages:', error);
                messages = [];
                displayMessages();
                throw error; // Re-throw to trigger error state
            }
        }

        // Display messages in chat area
        function displayMessages() {
            const messagesArea = document.getElementById('messages-area');
            messagesArea.innerHTML = '';

            messages.forEach(message => {
                const messageElement = createMessageElement(message);
                messagesArea.appendChild(messageElement);
            });

            // Enhanced auto-scroll with proper timing
            requestAnimationFrame(() => {
                requestAnimationFrame(() => {
                    scrollToBottom();
                });
            });
        }

        // Enhanced create message element with delivery status
        function createMessageElement(message, status = 'sent') {
            const element = document.createElement('div');
            const isSent = message.sender_id === currentUser.id;
            element.className = `message ${isSent ? 'sent' : 'received'}`;
            element.setAttribute('data-message-id', message.id || message.tempId || Date.now());

            let statusHtml = '';
            if (isSent) {
                statusHtml = `<div class="message-status" id="status-${message.id || message.tempId}">${getStatusIndicator(status)}</div>`;
            }

            element.innerHTML = `
                <div class="message-content">${escapeHtml(message.message)}</div>
                <div class="message-time">${formatMessageTime(message.created_at)}</div>
                ${statusHtml}
            `;

            return element;
        }
        
        // Get status indicator HTML
        function getStatusIndicator(status) {
            switch (status) {
                case 'sending':
                    return '<span class="status-sending"><i class="fas fa-clock"></i> Sending...</span>';
                case 'sent':
                    return '<span class="status-sent"><i class="fas fa-check"></i> Sent</span>';
                case 'delivered':
                    return '<span class="status-delivered"><i class="fas fa-check-double"></i> Delivered</span>';
                case 'read':
                    return '<span class="status-read"><i class="fas fa-check-double"></i> Read</span>';
                case 'failed':
                    return '<span class="status-failed" onclick="retryMessage(this)"><i class="fas fa-exclamation-triangle"></i> Failed - Tap to retry</span>';
                default:
                    return '<span class="status-sent"><i class="fas fa-check"></i> Sent</span>';
            }
        }
        
        // Update message status
        function updateMessageStatus(messageId, status) {
            const statusElement = document.getElementById(`status-${messageId}`);
            if (statusElement) {
                statusElement.innerHTML = getStatusIndicator(status);
            }
        }

        // Enhanced send message with buffering and status tracking
        async function sendMessage() {
            const messageInput = document.getElementById('message-input');
            const sendButton = document.getElementById('send-button');
            const messageText = messageInput.value.trim();

            if (!messageText || !selectedConversationId) return;
            
            // Check rate limiting
            if (!checkRateLimit()) return;
            
            const tempId = Date.now() + Math.random();
            const messageData = {
                id: tempId,
                tempId: tempId,
                sender_id: currentUser.id,
                sender_name: currentUser.name,
                message: messageText,
                created_at: new Date().toISOString()
            };

            try {
                sendButton.disabled = true;
                sendButton.innerHTML = '<i class="fas fa-spinner fa-spin"></i>';
                
                // Clear input immediately for better UX
                messageInput.value = '';
                
                // Track message as pending
                pendingMessages.set(tempId, 'sending');
                
                // Add message to UI optimistically with sending status
                const messageElement = createMessageElement(messageData, 'sending');
                const messagesArea = document.getElementById('messages-area');
                messagesArea.appendChild(messageElement);
                scrollToBottom(true);
                
                // Update rate limiting
                lastMessageTime = Date.now();
                messagesSentInLastMinute++;
                
                // Try to send via WebSocket first, then HTTP
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    // Send via WebSocket for real-time delivery
                    sendWebSocketMessage('new_message', {
                        content: messageText,
                        conversationId: selectedConversationId,
                        tempId: tempId
                    });
                    
                    // Update status to sent (will be updated to delivered/read via WebSocket)
                    setTimeout(() => {
                        if (pendingMessages.get(tempId) === 'sending') {
                            updateMessageStatus(tempId, 'sent');
                            pendingMessages.set(tempId, 'sent');
                        }
                    }, 1000);
                    
                } else if (connectionState !== 'offline') {
                    // Try HTTP API when WebSocket unavailable but online
                    try {
                        const response = await authenticatedFetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${selectedConversationId}/messages`, {
                            method: 'POST',
                            body: JSON.stringify({ message: messageText })
                        });

                        if (response.ok) {
                            const result = await response.json();
                            console.log('✅ Message sent via HTTP:', result.message);
                            updateMessageStatus(tempId, 'sent');
                            pendingMessages.set(tempId, 'sent');
                            
                            // Update conversation list
                            await loadConversations();
                        } else {
                            throw new Error('HTTP send failed');
                        }
                    } catch (httpError) {
                        console.error('HTTP send failed, buffering message:', httpError);
                        bufferMessage(messageData, selectedConversationId);
                        updateMessageStatus(tempId, 'failed');
                    }
                } else {
                    // Offline - buffer the message
                    console.log('📴 Offline - buffering message');
                    bufferMessage(messageData, selectedConversationId);
                    updateMessageStatus(tempId, 'failed');
                }
                
            } catch (error) {
                console.error('Error sending message:', error);
                
                // Buffer the message on any error
                bufferMessage(messageData, selectedConversationId);
                updateMessageStatus(tempId, 'failed');
                
                showErrorFeedback('Message failed to send. It will be retried automatically.');
            } finally {
                sendButton.disabled = false;
                sendButton.innerHTML = '<i class="fas fa-paper-plane"></i>';
                messageInput.focus();
            }
        }

        // Mark messages as read
        async function markMessagesAsRead(conversationId) {
            try {
                await authenticatedFetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${conversationId}/read`, {
                    method: 'PUT'
                });
            } catch (error) {
                console.error('Error marking messages as read:', error);
            }
        }

        // Setup event listeners
        function setupEventListeners() {
            // Search conversations
            const searchInput = document.getElementById('search-conversations');
            searchInput.addEventListener('input', filterConversations);

            // Message input
            const messageInput = document.getElementById('message-input');
            messageInput.addEventListener('keypress', (e) => {
                if (e.key === 'Enter' && !e.shiftKey) {
                    e.preventDefault();
                    sendMessage();
                }
            });

            // Auto-resize textarea
            messageInput.addEventListener('input', autoResizeTextarea);
            
            // Window resize handler
            window.addEventListener('resize', handleWindowResize);
            
            // Keyboard shortcut for demo refresh (backtick key)
            document.addEventListener('keydown', (e) => {
                if (e.key === '`' && !e.ctrlKey && !e.altKey && !e.shiftKey) {
                    e.preventDefault();
                    refreshChatForDemo();
                }
            });
        }

        // Filter conversations based on search
        function filterConversations() {
            const searchTerm = document.getElementById('search-conversations').value.toLowerCase();
            
            filteredConversations = conversations.filter(conversation => {
                return conversation.listing.title.toLowerCase().includes(searchTerm) ||
                       conversation.other_user.name.toLowerCase().includes(searchTerm) ||
                       (conversation.last_message_preview && conversation.last_message_preview.toLowerCase().includes(searchTerm));
            });

            displayConversations();
        }

        // Auto-resize textarea
        function autoResizeTextarea() {
            const textarea = document.getElementById('message-input');
            textarea.style.height = 'auto';
            textarea.style.height = Math.min(textarea.scrollHeight, 120) + 'px';
        }

        // Show/hide UI elements
        function showChatInterface() {
            console.log('🎯 showChatInterface called');
            
            document.getElementById('empty-chat').style.display = 'none';
            const chatLoading = document.getElementById('chat-loading');
            if (chatLoading) chatLoading.style.display = 'none';
            const chatError = document.getElementById('chat-error');
            if (chatError) chatError.style.display = 'none';
            
            const chatHeader = document.getElementById('chat-header');
            const messagesArea = document.getElementById('messages-area');
            const messageInputArea = document.getElementById('message-input-area');
            
            if (chatHeader) {
                chatHeader.style.display = 'block';
                chatHeader.style.visibility = 'visible';
                chatHeader.style.opacity = '1';
                console.log('✅ Chat header shown');
            } else {
                console.error('❌ Chat header element not found');
            }
            
            if (messagesArea) {
                messagesArea.style.display = 'flex';
                messagesArea.style.visibility = 'visible';
                messagesArea.style.opacity = '1';
                messagesArea.style.height = 'auto';
                messagesArea.style.flex = '1';
                console.log('✅ Messages area shown');
            } else {
                console.error('❌ Messages area element not found');
            }
            
            if (messageInputArea) {
                messageInputArea.style.display = 'block';
                messageInputArea.style.visibility = 'visible';
                messageInputArea.style.opacity = '1';
                messageInputArea.style.height = 'auto';
                messageInputArea.style.minHeight = '80px';
                messageInputArea.style.position = 'relative';
                messageInputArea.style.zIndex = '1';
                
                // Force reflow
                void messageInputArea.offsetHeight;
                
                console.log('✅ Message input area shown');
                console.log('🔍 Message input area computed styles:', {
                    display: window.getComputedStyle(messageInputArea).display,
                    visibility: window.getComputedStyle(messageInputArea).visibility,
                    opacity: window.getComputedStyle(messageInputArea).opacity,
                    height: window.getComputedStyle(messageInputArea).height,
                    position: window.getComputedStyle(messageInputArea).position
                });
            } else {
                console.error('❌ Message input area element not found');
            }
        }
        
        function showChatLoading() {
            document.getElementById('empty-chat').style.display = 'none';
            const chatError = document.getElementById('chat-error');
            if (chatError) chatError.style.display = 'none';
            document.getElementById('chat-header').style.display = 'none';
            document.getElementById('messages-area').style.display = 'none';
            document.getElementById('message-input-area').style.display = 'none';
            
            // Show or create loading state
            let loadingElement = document.getElementById('chat-loading');
            if (!loadingElement) {
                loadingElement = document.createElement('div');
                loadingElement.id = 'chat-loading';
                loadingElement.className = 'chat-loading';
                loadingElement.innerHTML = '<div class="spinner"></div><span>Loading conversation...</span>';
                document.getElementById('chat-area').appendChild(loadingElement);
            }
            loadingElement.style.display = 'flex';
        }
        
        function showChatError() {
            document.getElementById('empty-chat').style.display = 'none';
            const chatLoading = document.getElementById('chat-loading');
            if (chatLoading) chatLoading.style.display = 'none';
            document.getElementById('chat-header').style.display = 'none';
            document.getElementById('messages-area').style.display = 'none';
            document.getElementById('message-input-area').style.display = 'none';
            
            // Show or create error state
            let errorElement = document.getElementById('chat-error');
            if (!errorElement) {
                errorElement = document.createElement('div');
                errorElement.id = 'chat-error';
                errorElement.className = 'empty-chat';
                errorElement.innerHTML = `
                    <i class="fas fa-exclamation-triangle"></i>
                    <h3>Failed to load conversation</h3>
                    <p>Please try selecting the conversation again</p>
                `;
                document.getElementById('chat-area').appendChild(errorElement);
            }
            errorElement.style.display = 'flex';
        }
		
         // ===== ENHANCED AUDIO & NOTIFICATIONS =====
        
        // Initialize audio context for notifications
        function initializeAudioContext() {
            if (isAudioInitialized) return;
            
            try {
                audioContext = new (window.AudioContext || window.webkitAudioContext)();
                isAudioInitialized = true;
                console.log('🔊 Audio context initialized');
            } catch (error) {
                console.warn('Failed to initialize audio context:', error);
            }
        }
        
        // Enhanced notification sound
        function playNotificationSound(type = 'message') {
            if (!soundEnabled || !isAudioInitialized || !audioContext) return;
            
            try {
                const oscillator = audioContext.createOscillator();
                const gainNode = audioContext.createGain();
                
                oscillator.connect(gainNode);
                gainNode.connect(audioContext.destination);
                
                // Different sounds for different types
                switch (type) {
                    case 'message':
                        oscillator.frequency.setValueAtTime(800, audioContext.currentTime);
                        oscillator.frequency.setValueAtTime(600, audioContext.currentTime + 0.1);
                        break;
                    case 'typing':
                        oscillator.frequency.setValueAtTime(400, audioContext.currentTime);
                        break;
                    case 'error':
                        oscillator.frequency.setValueAtTime(300, audioContext.currentTime);
                        oscillator.frequency.setValueAtTime(200, audioContext.currentTime + 0.2);
                        break;
                    case 'connected':
                        oscillator.frequency.setValueAtTime(600, audioContext.currentTime);
                        oscillator.frequency.setValueAtTime(800, audioContext.currentTime + 0.1);
                        break;
                }
                
                oscillator.type = 'sine';
                gainNode.gain.setValueAtTime(0, audioContext.currentTime);
                gainNode.gain.linearRampToValueAtTime(0.1, audioContext.currentTime + 0.01);
                gainNode.gain.linearRampToValueAtTime(0, audioContext.currentTime + 0.3);
                
                oscillator.start(audioContext.currentTime);
                oscillator.stop(audioContext.currentTime + 0.3);
            } catch (error) {
                console.warn('Failed to play notification sound:', error);
            }
        }
        
        // Enhanced desktop notifications
        function showDesktopNotification(title, body, options = {}) {
            if (!desktopNotificationsEnabled || notificationPermission !== 'granted') {
                return;
            }
            
            // Don't show notifications if window is focused
            if (!document.hidden) return;
            
            const notification = new Notification(title, {
                body: body,
                icon: '../assets/logo-192.png',
                badge: '../assets/badge-72.png',
                tag: options.tag || 'spear-exchange-message',
                requireInteraction: false,
                silent: false,
                ...options
            });
            
            // Auto-close after 5 seconds
            setTimeout(() => {
                notification.close();
            }, 5000);
            
            // Handle click to focus window
            notification.onclick = () => {
                window.focus();
                if (options.conversationId) {
                    selectConversation(options.conversationId);
                }
                notification.close();
            };
            
            return notification;
        }
        
        // Clear notification queue
        function clearNotificationQueue() {
            notificationQueue.forEach(notification => {
                if (notification && typeof notification.close === 'function') {
                    notification.close();
                }
            });
            notificationQueue = [];
        }
        
        // Connection monitoring system
        function startConnectionMonitoring() {
            // Monitor connection quality every 10 seconds
            qualityCheckInterval = setInterval(() => {
                checkConnectionQuality();
            }, 10000);
            
            // Overall connection monitoring
            connectionMonitorInterval = setInterval(() => {
                monitorConnectionHealth();
            }, 5000);
        }
        
        // Check connection quality based on ping times
        function checkConnectionQuality() {
            if (!lastPingTime || !lastPongTime) return;
            
            const now = Date.now();
            const timeSinceLastPong = now - lastPongTime;
            
            if (timeSinceLastPong > 90000) { // 90 seconds
                connectionQuality = 'offline';
                updateConnectionStatus('offline');
            } else if (connectionLatency > 1000 || timeSinceLastPong > 45000) {
                connectionQuality = 'poor';
                updateConnectionStatus('connected');
            } else {
                connectionQuality = 'good';
                updateConnectionStatus('connected');
            }
        }
        
        // Monitor overall connection health
        function monitorConnectionHealth() {
            // Check global WebSocket
            if (globalWebSocket && globalWebSocket.readyState !== WebSocket.OPEN) {
                if (connectionState !== 'reconnecting' && connectionState !== 'connecting') {
                    console.log('🔄 Global WebSocket disconnected, attempting reconnect...');
                    connectGlobalWebSocket();
                }
            }
            
            // Check conversation WebSocket
            if (selectedConversationId && websocket && websocket.readyState !== WebSocket.OPEN) {
                if (connectionState !== 'reconnecting' && connectionState !== 'connecting') {
                    console.log('🔄 Conversation WebSocket disconnected, attempting reconnect...');
                    connectWebSocket(selectedConversationId);
                }
            }
        }
        
        // Send ping to measure latency
        function sendPing() {
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                lastPingTime = Date.now();
                const pingData = {
                    type: 'ping',
                    timestamp: lastPingTime,
                    clientId: currentUser?.id
                };
                websocket.send(JSON.stringify(pingData));
            }
        }
        
        // Handle pong response
        function handlePongResponse(pongData) {
            lastPongTime = Date.now();
            if (pongData.timestamp) {
                connectionLatency = lastPongTime - pongData.timestamp;
                console.log(`🏓 Ping: ${connectionLatency}ms`);
            }
            missedPings = 0;
        }
        
        // Enhanced rate limiting
        function checkRateLimit() {
            const now = Date.now();
            const timeSinceLastMessage = now - lastMessageTime;
            
            // Reset counter every minute
            if (timeSinceLastMessage > 60000) {
                messagesSentInLastMinute = 0;
            }
            
            if (messagesSentInLastMinute >= messageRateLimit) {
                const timeUntilReset = 60000 - timeSinceLastMessage;
                const secondsRemaining = Math.ceil(timeUntilReset / 1000);
                
                showErrorFeedback(`Rate limit exceeded. Try again in ${secondsRemaining} seconds.`);
                return false;
            }
            
            return true;
        }
        
        // Enhanced message buffering for offline/failed states
        function bufferMessage(message, conversationId) {
            const bufferedMessage = {
                ...message,
                tempId: Date.now() + Math.random(),
                conversationId,
                timestamp: Date.now(),
                retryCount: 0
            };
            
            messageBuffer.push(bufferedMessage);
            pendingMessages.set(bufferedMessage.tempId, 'buffered');
            
            console.log('📦 Message buffered for later delivery:', bufferedMessage.tempId);
            
            // Show offline indicator if not already shown
            if (connectionState === 'offline' && !document.getElementById('offline-indicator')) {
                showOfflineIndicator();
            }
            
            return bufferedMessage;
        }
        
        // Process buffered messages when connection is restored
        function processMessageBuffer() {
            if (messageBuffer.length === 0) return;
            
            console.log(`🔄 Processing ${messageBuffer.length} buffered messages`);
            
            const messagesToProcess = [...messageBuffer];
            messageBuffer = [];
            
            messagesToProcess.forEach(async (bufferedMessage) => {
                try {
                    await sendBufferedMessage(bufferedMessage);
                } catch (error) {
                    console.error('Failed to send buffered message:', error);
                    // Re-add to buffer with incremented retry count
                    if (bufferedMessage.retryCount < 3) {
                        bufferedMessage.retryCount++;
                        messageBuffer.push(bufferedMessage);
                        updateMessageStatus(bufferedMessage.tempId, 'failed');
                    } else {
                        updateMessageStatus(bufferedMessage.tempId, 'failed');
                        pendingMessages.delete(bufferedMessage.tempId);
                    }
                }
            });
        }
        
        // Send a buffered message
        async function sendBufferedMessage(bufferedMessage) {
            updateMessageStatus(bufferedMessage.tempId, 'sending');
            
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                // Send via WebSocket
                sendWebSocketMessage('new_message', {
                    content: bufferedMessage.message,
                    conversationId: bufferedMessage.conversationId,
                    tempId: bufferedMessage.tempId
                });
            } else {
                // Send via HTTP API
                const response = await authenticatedFetch(
                    `https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${bufferedMessage.conversationId}/messages`,
                    {
                        method: 'POST',
                        body: JSON.stringify({ message: bufferedMessage.message })
                    }
                );
                
                if (response.ok) {
                    const result = await response.json();
                    updateMessageStatus(bufferedMessage.tempId, 'sent');
                    pendingMessages.delete(bufferedMessage.tempId);
                } else {
                    throw new Error('Failed to send buffered message');
                }
            }
        }
        
        // Retry failed message
        function retryMessage(statusElement) {
            const messageElement = statusElement.closest('.message');
            const messageId = messageElement.getAttribute('data-message-id');
            const messageContent = messageElement.querySelector('.message-content').textContent;
            
            console.log('🔄 Retrying message:', messageId);
            
            // Find and retry the buffered message
            const bufferedMessage = messageBuffer.find(m => m.tempId == messageId);
            if (bufferedMessage) {
                sendBufferedMessage(bufferedMessage).catch(error => {
                    console.error('Retry failed:', error);
                    showErrorFeedback('Message retry failed. Please check your connection.');
                });
            } else {
                // Create new buffered message for retry
                const retryMessage = {
                    message: messageContent,
                    tempId: messageId,
                    conversationId: selectedConversationId,
                    retryCount: 0
                };
                sendBufferedMessage(retryMessage).catch(error => {
                    console.error('Retry failed:', error);
                    showErrorFeedback('Message retry failed. Please check your connection.');
                });
            }
        }
        
        // Show offline indicator
        function showOfflineIndicator() {
            if (document.getElementById('offline-indicator')) return;
            
            const indicator = document.createElement('div');
            indicator.id = 'offline-indicator';
            indicator.className = 'offline-indicator';
            indicator.innerHTML = `
                📵 You're offline
                <button class="retry-button" onclick="processMessageBuffer()">Retry Messages</button>
            `;
            
            document.body.appendChild(indicator);
        }
        
        // Hide offline indicator
        function hideOfflineIndicator() {
            const indicator = document.getElementById('offline-indicator');
            if (indicator) {
                indicator.remove();
            }
        }
        
        // Show error feedback to user
        function showErrorFeedback(message) {
            const errorDiv = document.createElement('div');
            errorDiv.className = 'error-feedback';
            errorDiv.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                background: #ef4444;
                color: white;
                padding: 12px 16px;
                border-radius: 8px;
                font-size: 14px;
                font-weight: 500;
                z-index: 1000;
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
                animation: slideIn 0.3s ease;
            `;
            errorDiv.textContent = message;
            
            document.body.appendChild(errorDiv);
            
            setTimeout(() => {
                errorDiv.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => {
                    if (errorDiv.parentNode) {
                        errorDiv.parentNode.removeChild(errorDiv);
                    }
                }, 300);
            }, 5000);
        }
        
        // Stop ping interval for a session
        function stopPingInterval(session) {
            if (session && session.pingInterval) {
                clearInterval(session.pingInterval);
                session.pingInterval = null;
            }
        }
        
        // Send WebSocket message safely
        function sendWebSocketMessage(type, data) {
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                try {
                    websocket.send(JSON.stringify({
                        type: type,
                        ...data,
                        timestamp: new Date().toISOString()
                    }));
                    return true;
                } catch (error) {
                    console.error('Failed to send WebSocket message:', error);
                    return false;
                }
            }
            return false;
        }
        
        // Initialize global WebSocket connection for all conversations
        function connectGlobalWebSocket() {
            if (!currentUser) return;
            
            console.log('🌐 Connecting to global WebSocket for all conversations');
            
            const wsUrl = `wss://spear-exchange.lenny-paz123.workers.dev/api/chat/connect?userId=${currentUser.id}&userName=${encodeURIComponent(currentUser.name)}&global=true`;
            
            globalWebSocket = new WebSocket(wsUrl);
            
            globalWebSocket.onopen = () => {
                console.log('✅ Global WebSocket connected');
                reconnectAttempts = 0;
                reconnectDelay = 1000;
                updateConnectionStatus('connected');
                playNotificationSound('connected');
            };
            
            globalWebSocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleGlobalWebSocketMessage(data);
                } catch (error) {
                    console.error('❌ Failed to parse global WebSocket message:', error);
                }
            };
            
            globalWebSocket.onclose = (event) => {
                console.log('❌ Global WebSocket disconnected:', event.code, event.reason);
                updateConnectionStatus('disconnected');
                
                // Attempt to reconnect if not intentionally closed
                if (event.code !== 1000 && reconnectAttempts < maxReconnectAttempts) {
                    updateConnectionStatus('reconnecting');
                    setTimeout(() => {
                        reconnectAttempts++;
                        console.log(`🔄 Reconnecting global WebSocket... (${reconnectAttempts}/${maxReconnectAttempts})`);
                        connectGlobalWebSocket();
                    }, reconnectDelay);
                    
                    reconnectDelay = Math.min(reconnectDelay * 2, 30000); // Max 30 seconds
                }
            };
            
            globalWebSocket.onerror = (error) => {
                console.error('❌ Global WebSocket error:', error);
                updateConnectionStatus('disconnected');
            };
        }
        
        // Handle global WebSocket messages
        function handleGlobalWebSocketMessage(data) {
            console.log('🌐 Global WebSocket message:', data.type);
            
            switch (data.type) {
                case 'connection_established':
                    console.log('✅ Global connection established');
                    updateConnectionStatus('connected');
                    break;
                    
                case 'new_message':
                    // Handle cross-conversation notifications
                    if (data.conversationId !== selectedConversationId) {
                        playNotificationSound('message');
                        showDesktopNotification(
                            'New Message',
                            `${data.senderName}: ${data.content}`,
                            { conversationId: data.conversationId }
                        );
                        
                        // Update unread count in conversations list
                        updateConversationUnreadCount(data.conversationId);
                    }
                    break;
                    
                case 'ping':
                    // Respond to server ping
                    if (globalWebSocket && globalWebSocket.readyState === WebSocket.OPEN) {
                        globalWebSocket.send(JSON.stringify({
                            type: 'pong',
                            timestamp: data.timestamp,
                            clientTime: Date.now()
                        }));
                    }
                    break;
                    
                case 'pong':
                    // Handle server pong response
                    handlePongResponse(data);
                    break;
                    
                default:
                    console.log('🤷 Unknown global message type:', data.type);
            }
        }
        function connectWebSocket(conversationId) {
            if (!conversationId || !currentUser) return;
            
            // Close existing connection
            if (websocket) {
                websocket.close(1000, 'Switching conversations');
            }
            
            // Don't reconnect if already connecting
            if (websocket && websocket.readyState === WebSocket.CONNECTING) {
                console.log('🔄 WebSocket already connecting, skipping...');
                return;
            }
            
            updateConnectionStatus('connecting');
            console.log('🔌 Connecting to WebSocket for conversation:', conversationId);
            
            const wsUrl = `wss://spear-exchange.lenny-paz123.workers.dev/api/chat/connect?conversationId=${conversationId}&userId=${currentUser.id}&userName=${encodeURIComponent(currentUser.name)}`;
            
            websocket = new WebSocket(wsUrl);
            
            // Connection timeout
            const connectionTimeout = setTimeout(() => {
                if (websocket.readyState === WebSocket.CONNECTING) {
                    console.log('⏰ WebSocket connection timeout');
                    websocket.close();
                }
            }, 10000);
            
            websocket.onopen = () => {
                clearTimeout(connectionTimeout);
                console.log('✅ WebSocket connected');
                reconnectAttempts = 0;
                reconnectDelay = 1000;
                updateConnectionStatus('connected');
                
                // Start ping interval
                startPingInterval();
                
                // Send initial join message
                sendWebSocketMessage('join_conversation', {
                    conversationId: conversationId,
                    userId: currentUser.id,
                    userName: currentUser.name
                });
                
                // Process any buffered messages for this conversation
                processMessageBuffer(conversationId);
                
                // Play connection sound
                playNotificationSound('connected');
            };
            
            websocket.onmessage = (event) => {
                try {
                    const data = JSON.parse(event.data);
                    handleWebSocketMessage(data);
                } catch (error) {
                    console.error('❌ Failed to parse WebSocket message:', error);
                }
            };
            
            websocket.onclose = (event) => {
                clearTimeout(connectionTimeout);
                stopPingInterval(session);
                console.log('❌ WebSocket disconnected:', event.code, event.reason);
                updateConnectionStatus('disconnected');
                
                // Only attempt to reconnect if not intentionally closed and we have a conversation selected
                if (event.code !== 1000 && reconnectAttempts < maxReconnectAttempts && selectedConversationId === conversationId) {
                    updateConnectionStatus('reconnecting');
                    setTimeout(() => {
                        reconnectAttempts++;
                        console.log(`🔄 Reconnecting... (${reconnectAttempts}/${maxReconnectAttempts})`);
                        connectWebSocket(conversationId);
                    }, reconnectDelay);
                    
                    // Exponential backoff
                    reconnectDelay = Math.min(reconnectDelay * 1.5, 30000);
                } else if (reconnectAttempts >= maxReconnectAttempts) {
                    console.log('❌ Max reconnection attempts reached');
                    updateConnectionStatus('offline');
                    showErrorFeedback('Connection lost. Please refresh the page.');
                }
            };
            
            websocket.onerror = (error) => {
                clearTimeout(connectionTimeout);
                console.error('❌ WebSocket error:', error);
                updateConnectionStatus('disconnected');
                playNotificationSound('error');
            };
        }

        // Handle global WebSocket messages (for all conversations)
        function handleGlobalWebSocketMessage(data) {
            console.log('🌐 Global WebSocket message received:', data);
            
            switch (data.type) {
                case 'connection_established':
                    console.log('🎉 Connected to global chat system');
                    break;
                    
                case 'new_message':
                    handleGlobalNewMessage(data);
                    break;
                    
                case 'conversation_updated':
                    handleConversationUpdate(data);
                    break;
                    
                case 'ping':
                    // Respond to ping with pong
                    sendGlobalWebSocketMessage('pong', { timestamp: new Date().toISOString() });
                    break;
                    
                case 'pong':
                    console.log('🏓 Global pong received');
                    break;
                    
                default:
                    console.log('Unknown global message type:', data.type);
            }
        }
        
        // Handle new messages from any conversation
        function handleGlobalNewMessage(data) {
            const conversationId = data.conversationId;
            
            // If this is for the currently active conversation, let the regular handler deal with it
            if (conversationId === selectedConversationId) {
                return;
            }
            
            // Update conversation in sidebar with real-time data
            updateConversationInSidebar(data);
            
            // Show notification for non-active conversations
            showCrossConversationNotification(data);
            
            // Play notification sound
            playNotificationSound();
        }
        
        // Update conversation in sidebar with new message
        function updateConversationInSidebar(messageData) {
            const conversationId = messageData.conversationId;
            const conversationItem = document.querySelector(`[data-conversation-id="${conversationId}"]`);
            
            if (conversationItem) {
                // Update last message preview
                const lastMessageElement = conversationItem.querySelector('.last-message');
                if (lastMessageElement) {
                    const preview = messageData.content.length > 50 
                        ? messageData.content.substring(0, 50) + '...' 
                        : messageData.content;
                    lastMessageElement.textContent = preview;
                }
                
                // Update time
                const timeElement = conversationItem.querySelector('.conversation-time');
                if (timeElement) {
                    timeElement.textContent = formatConversationTime(messageData.timestamp);
                }
                
                // Update or add unread count
                updateUnreadCount(conversationId, conversationItem);
                
                // Move conversation to top
                moveConversationToTop(conversationItem);
                
                // Add visual emphasis
                conversationItem.style.backgroundColor = 'rgba(139, 38, 53, 0.05)';
                setTimeout(() => {
                    conversationItem.style.backgroundColor = '';
                }, 2000);
            } else {
                // Conversation not in current list - reload conversations
                console.log('🔄 New conversation detected, reloading list...');
                loadConversations();
            }
        }
        
        // Update unread count for a conversation
        function updateUnreadCount(conversationId, conversationItem) {
            let unreadElement = conversationItem.querySelector('.unread-count');
            
            if (!unreadElement) {
                // Create unread count element
                unreadElement = document.createElement('span');
                unreadElement.className = 'unread-count';
                unreadElement.textContent = '1';
                
                const metaElement = conversationItem.querySelector('.conversation-meta');
                if (metaElement) {
                    metaElement.appendChild(unreadElement);
                }
            } else {
                // Increment existing count
                const currentCount = parseInt(unreadElement.textContent) || 0;
                unreadElement.textContent = (currentCount + 1).toString();
            }
            
            // Add pulse animation
            unreadElement.style.animation = 'none';
            void unreadElement.offsetHeight; // Force reflow
            unreadElement.style.animation = 'unreadPulse 0.5s ease-in-out 3';
        }
        
        // Move conversation to top of list with smooth animation
        function moveConversationToTop(conversationItem) {
            const conversationsList = document.getElementById('conversations-list');
            const firstChild = conversationsList.firstChild;
            
            // Only move if it's not already at the top
            if (firstChild !== conversationItem) {
                // Create a smooth transition effect
                const originalHeight = conversationItem.offsetHeight;
                conversationItem.style.transition = 'all 0.3s ease';
                
                // Move to top
                conversationsList.insertBefore(conversationItem, firstChild);
                
                // Add subtle highlight animation
                conversationItem.style.transform = 'translateX(4px)';
                conversationItem.style.boxShadow = '0 4px 12px rgba(139, 38, 53, 0.15)';
                
                setTimeout(() => {
                    conversationItem.style.transform = '';
                    conversationItem.style.boxShadow = '';
                    conversationItem.style.transition = '';
                }, 300);
            }
        }
        
        // Show enhanced notification for messages in other conversations
        function showCrossConversationNotification(messageData) {
            // Don't show notifications if already in the conversation
            if (messageData.conversationId === selectedConversationId) {
                return;
            }
            
            // Remove any existing notification for this conversation
            const existingNotification = document.querySelector(`[data-notification-conversation="${messageData.conversationId}"]`);
            if (existingNotification) {
                existingNotification.remove();
            }
            
            // Create new notification element
            const notification = document.createElement('div');
            notification.className = 'cross-conversation-notification';
            notification.setAttribute('data-notification-conversation', messageData.conversationId);
            notification.style.cssText = `
                position: fixed;
                top: 100px;
                right: 20px;
                background: linear-gradient(135deg, var(--primary-color), var(--primary-dark));
                color: white;
                padding: 14px 18px;
                border-radius: 16px;
                box-shadow: 0 6px 25px rgba(139, 38, 53, 0.4);
                z-index: 1002;
                max-width: 350px;
                opacity: 0;
                transform: translateX(100%) scale(0.8);
                transition: all 0.4s cubic-bezier(0.34, 1.56, 0.64, 1);
                cursor: pointer;
                border: 1px solid rgba(255, 255, 255, 0.2);
                backdrop-filter: blur(10px);
            `;
            
            // Get conversation details from sidebar
            const conversationItem = document.querySelector(`[data-conversation-id="${messageData.conversationId}"]`);
            let listingTitle = 'Unknown Listing';
            if (conversationItem) {
                const titleElement = conversationItem.querySelector('.listing-title');
                if (titleElement) {
                    listingTitle = titleElement.textContent;
                }
            }
            
            // Truncate message for notification
            const maxLength = 60;
            const truncatedMessage = messageData.content.length > maxLength 
                ? messageData.content.substring(0, maxLength) + '...' 
                : messageData.content;
            
            notification.innerHTML = `
                <div style="display: flex; align-items: flex-start; gap: 12px;">
                    <div style="
                        width: 40px;
                        height: 40px;
                        background: rgba(255, 255, 255, 0.2);
                        border-radius: 50%;
                        display: flex;
                        align-items: center;
                        justify-content: center;
                        font-size: 18px;
                        flex-shrink: 0;
                    ">💬</div>
                    <div style="flex: 1; min-width: 0;">
                        <div style="font-weight: 600; margin-bottom: 4px; font-size: 14px;">
                            New message • ${listingTitle}
                        </div>
                        <div style="font-size: 13px; opacity: 0.95; margin-bottom: 6px;">
                            <strong>${escapeHtml(messageData.senderName)}:</strong> ${escapeHtml(truncatedMessage)}
                        </div>
                        <div style="font-size: 11px; opacity: 0.8;">
                            Click to view conversation
                        </div>
                    </div>
                    <button onclick="event.stopPropagation(); this.parentElement.parentElement.remove();" style="
                        background: none;
                        border: none;
                        color: rgba(255, 255, 255, 0.8);
                        cursor: pointer;
                        padding: 4px;
                        font-size: 16px;
                        line-height: 1;
                        border-radius: 4px;
                        transition: all 0.2s ease;
                    " onmouseover="this.style.background='rgba(255,255,255,0.2)'" onmouseout="this.style.background='none'">&times;</button>
                </div>
            `;
            
            // Click to open conversation
            notification.onclick = (e) => {
                if (e.target.tagName !== 'BUTTON') {
                    selectConversation(messageData.conversationId);
                    notification.remove();
                }
            };
            
            document.body.appendChild(notification);
            
            // Animate in
            requestAnimationFrame(() => {
                notification.style.opacity = '1';
                notification.style.transform = 'translateX(0) scale(1)';
            });
            
            // Auto-remove after 8 seconds
            setTimeout(() => {
                if (notification.parentNode) {
                    notification.style.opacity = '0';
                    notification.style.transform = 'translateX(100%) scale(0.8)';
                    setTimeout(() => {
                        if (notification.parentNode) {
                            notification.remove();
                        }
                    }, 400);
                }
            }, 8000);
        }
        function handleWebSocketMessage(data) {
            console.log('📨 WebSocket message received:', data);
            
            switch (data.type) {
                case 'connection_established':
                    console.log('🎉 Connected to chat room');
                    updateConnectionStatus(true);
                    break;
                    
                case 'ping':
                    // Respond to ping with pong
                    sendWebSocketMessage('pong', { timestamp: new Date().toISOString() });
                    break;
                    
                case 'pong':
                    console.log('🏓 Received pong from server');
                    // Don't trigger user_left for pong responses
                    break;
                    
                case 'new_message':
                    handleNewMessageReceived(data);
                    break;
                    
                case 'typing_start':
                    handleTypingStart(data);
                    break;
                    
                case 'typing_stop':
                    handleTypingStop(data);
                    break;
                    
                case 'user_joined':
                    handleUserJoined(data);
                    break;
                    
                case 'user_left':
                    // Only handle if it's not a ping-pong related disconnect
                    if (!data.isPingPong) {
                        handleUserLeft(data);
                    } else {
                        console.log('🏓 Ignoring ping-pong related user_left event');
                    }
                    break;
                    
                case 'messages_read':
                    handleMessagesRead(data);
                    break;
                    
                case 'error':
                    console.error('WebSocket error:', data.message);
                    break;
                    
                default:
                    console.log('Unknown WebSocket message type:', data.type);
            }
        }

        // Handle new message received via WebSocket with enhanced features
        function handleNewMessageReceived(data) {
            // Only add if it's not from current user (avoid duplicates)
            if (data.senderId !== currentUser.id) {
                // Add message to the UI
                const messagesArea = document.getElementById('messages-area');
                if (messagesArea) {
                    const messageElement = createMessageElement({
                        id: data.messageId,
                        sender_id: data.senderId,
                        sender_name: data.senderName,
                        message: data.content,
                        created_at: data.timestamp
                    });
                    
                    // Add with animation
                    messageElement.style.opacity = '0';
                    messageElement.style.transform = 'translateY(20px)';
                    messagesArea.appendChild(messageElement);
                    
                    // Animate in
                    requestAnimationFrame(() => {
                        messageElement.style.transition = 'all 0.3s ease';
                        messageElement.style.opacity = '1';
                        messageElement.style.transform = 'translateY(0)';
                    });
                    
                    scrollToBottom(true); // Smooth scroll for received messages
                    
                    // Play notification sound for received messages in active conversation
                    playNotificationSound();
                    
                    // Update conversation list without full reload
                    updateConversationPreview(selectedConversationId, data.content, data.timestamp);
                }
            }
        }
        
        // Update conversation preview without full reload
        function updateConversationPreview(conversationId, messageContent, timestamp) {
            const conversationItem = document.querySelector(`[data-conversation-id="${conversationId}"]`);
            if (conversationItem) {
                // Update last message preview
                const lastMessageElement = conversationItem.querySelector('.last-message');
                if (lastMessageElement) {
                    const preview = messageContent.length > 50 
                        ? messageContent.substring(0, 50) + '...' 
                        : messageContent;
                    lastMessageElement.textContent = preview;
                }
                
                // Update timestamp
                const timeElement = conversationItem.querySelector('.conversation-time');
                if (timeElement) {
                    timeElement.textContent = formatConversationTime(timestamp);
                }
                
                // Move to top if not already there
                const conversationsList = document.getElementById('conversations-list');
                const firstChild = conversationsList.firstChild;
                if (firstChild !== conversationItem) {
                    conversationsList.insertBefore(conversationItem, firstChild);
                }
            }
        }

        // Handle typing indicators
        function handleTypingStart(data) {
            if (data.userId !== currentUser.id) {
                showTypingIndicator(data.userName);
            }
        }

        function handleTypingStop(data) {
            if (data.userId !== currentUser.id) {
                hideTypingIndicator();
            }
        }

        // Handle user presence
        function handleUserJoined(data) {
            if (data.userId !== currentUser.id) {
                activeUsers.add(data.userId);
                updateActiveUsersDisplay();
                console.log(`👋 ${data.userName} joined the conversation`);
            }
        }

        function handleUserLeft(data) {
            activeUsers.delete(data.userId);
            updateActiveUsersDisplay();
            hideTypingIndicator();
            console.log(`👋 ${data.userName} left the conversation`);
        }

        // Handle read receipts
        function handleMessagesRead(data) {
            console.log(`✓ User ${data.userId} read messages`);
        }
        
        // Update active users display
        function updateActiveUsersDisplay() {
            // This could be implemented to show active user count
            console.log('Active users:', Array.from(activeUsers));
        }
        
        // Show WebSocket error to user
        function showWebSocketError(message = 'Connection failed') {
            // Create or update error indicator
            let errorIndicator = document.getElementById('websocket-error');
            if (!errorIndicator) {
                errorIndicator = document.createElement('div');
                errorIndicator.id = 'websocket-error';
                errorIndicator.style.cssText = `
                    position: fixed;
                    top: 100px;
                    right: 20px;
                    background: #fee2e2;
                    color: #dc2626;
                    padding: 12px 16px;
                    border-radius: 8px;
                    border: 1px solid #fecaca;
                    z-index: 9999;
                    font-size: 14px;
                    max-width: 300px;
                    box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);
                `;
                document.body.appendChild(errorIndicator);
            }
            
            errorIndicator.innerHTML = `
                <div style="display: flex; align-items: center; gap: 8px;">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span>Real-time messaging unavailable: ${message}</span>
                </div>
            `;
            
            // Auto-hide after 5 seconds
            setTimeout(() => {
                if (errorIndicator && errorIndicator.parentNode) {
                    errorIndicator.remove();
                }
            }, 5000);
        }

        // Send global WebSocket message
        function sendGlobalWebSocketMessage(type, data = {}) {
            if (globalWebSocket && globalWebSocket.readyState === WebSocket.OPEN) {
                const message = { type, ...data };
                globalWebSocket.send(JSON.stringify(message));
                return true;
            } else {
                console.warn('⚠️ Cannot send global WebSocket message: connection not open');
                return false;
            }
        }
        
        // Start ping mechanism for global WebSocket
        function startGlobalPingMechanism() {
            if (pingInterval) {
                clearInterval(pingInterval);
            }
            
            pingInterval = setInterval(() => {
                if (globalWebSocket && globalWebSocket.readyState === WebSocket.OPEN) {
                    lastPingTime = Date.now();
                    globalWebSocket.send(JSON.stringify({
                        type: 'ping',
                        timestamp: new Date().toISOString(),
                        clientId: 'global-client'
                    }));
                    
                    // Set timeout for pong response
                    if (pongTimeout) clearTimeout(pongTimeout);
                    pongTimeout = setTimeout(() => {
                        console.warn('⚠️ Global pong timeout - connection may be unstable');
                        connectionQuality = 'poor';
                        updateConnectionStatus();
                    }, 10000); // 10 second timeout
                    
                    console.log('🏓 Sent global ping to server');
                } else {
                    clearInterval(pingInterval);
                    pingInterval = null;
                }
            }, 30000); // Ping every 30 seconds
        }
        
        // Start ping mechanism for conversation WebSocket
        function startConversationPingMechanism() {
            if (websocket && websocket.pingInterval) {
                clearInterval(websocket.pingInterval);
            }
            
            websocket.pingInterval = setInterval(() => {
                if (websocket && websocket.readyState === WebSocket.OPEN) {
                    websocket.send(JSON.stringify({
                        type: 'ping',
                        timestamp: new Date().toISOString(),
                        clientId: 'conversation-client'
                    }));
                    console.log('🏓 Sent conversation ping to server');
                } else {
                    clearInterval(websocket.pingInterval);
                    websocket.pingInterval = null;
                }
            }, 30000); // Ping every 30 seconds
        }
        
        // Enhanced Connection Status Management
        function updateConnectionStatus() {
            const statusElement = document.getElementById('connection-status');
            const isGlobalConnected = connectionState.global === 'connected';
            const isConversationConnected = connectionState.conversation === 'connected' || !selectedConversationId;
            
            // Create status element if it doesn't exist
            if (!statusElement) {
                const newStatusElement = document.createElement('div');
                newStatusElement.id = 'connection-status';
                newStatusElement.className = 'connection-status';
                
                // Add to appropriate location
                const chatHeader = document.getElementById('chat-header');
                if (chatHeader) {
                    chatHeader.appendChild(newStatusElement);
                } else {
                    // Fallback to conversations header if chat header not available
                    const conversationsHeader = document.querySelector('.conversations-header');
                    if (conversationsHeader) {
                        conversationsHeader.appendChild(newStatusElement);
                    }
                }
            }
            
            const statusEl = document.getElementById('connection-status');
            if (!statusEl) return;
            
            // Determine overall connection status
            let status, text, className;
            
            if (connectionState.global === 'connecting' || connectionState.conversation === 'connecting') {
                status = 'connecting';
                text = 'Connecting...';
                className = 'connection-status connecting';
            } else if (connectionState.global === 'reconnecting' || connectionState.conversation === 'reconnecting') {
                status = 'reconnecting';
                text = 'Reconnecting...';
                className = 'connection-status reconnecting';
            } else if (isGlobalConnected && isConversationConnected) {
                if (connectionQuality === 'poor') {
                    status = 'poor';
                    text = 'Poor connection';
                    className = 'connection-status poor';
                } else {
                    status = 'connected';
                    text = 'Connected';
                    className = 'connection-status online';
                }
            } else {
                status = 'disconnected';
                text = 'Disconnected';
                className = 'connection-status offline';
            }
            
            statusEl.className = className;
            statusEl.innerHTML = `
                <i class="fas fa-circle"></i>
                <span>${text}</span>
            `;
            
            // Auto-hide if connected and good quality
            if (status === 'connected' && connectionQuality === 'good') {
                setTimeout(() => {
                    if (statusEl && statusEl.className.includes('online')) {
                        statusEl.style.opacity = '0.5';
                        setTimeout(() => {
                            if (statusEl && statusEl.className.includes('online')) {
                                statusEl.style.display = 'none';
                            }
                        }, 2000);
                    }
                }, 3000);
            } else {
                statusEl.style.opacity = '1';
                statusEl.style.display = 'flex';
            }
        }
        
		// Clear WebSocket error indicator
        function clearWebSocketError() {
            const errorIndicator = document.getElementById('websocket-error');
            if (errorIndicator) {
                errorIndicator.remove();
            }
        }
		
        // Show connection error to user
        function showConnectionError(message) {
            // Remove any existing error
            const existingError = document.getElementById('connection-error');
            if (existingError) {
                existingError.remove();
            }
            
            const errorDiv = document.createElement('div');
            errorDiv.id = 'connection-error';
            errorDiv.style.cssText = `
                position: fixed;
                top: 90px;
                right: 20px;
                background: linear-gradient(135deg, #fee2e2, #fecaca);
                color: #dc2626;
                padding: 12px 16px;
                border-radius: 12px;
                border: 1px solid #f87171;
                box-shadow: 0 4px 12px rgba(220, 38, 38, 0.15);
                z-index: 1001;
                max-width: 300px;
                font-size: 14px;
                animation: slideIn 0.3s ease;
                display: flex;
                align-items: center;
                gap: 8px;
            `;
            
            errorDiv.innerHTML = `
                <i class="fas fa-exclamation-triangle"></i>
                <div>
                    <div style="font-weight: 600; margin-bottom: 2px;">Connection Issue</div>
                    <div style="font-size: 13px; opacity: 0.9;">${message}</div>
                </div>
                <button onclick="this.parentElement.remove()" style="
                    background: none;
                    border: none;
                    color: #dc2626;
                    cursor: pointer;
                    padding: 4px;
                    margin-left: 8px;
                    font-size: 16px;
                ">&times;</button>
            `;
            
            document.body.appendChild(errorDiv);
            
            // Auto-remove after 10 seconds
            setTimeout(() => {
                if (errorDiv && errorDiv.parentNode) {
                    errorDiv.style.animation = 'slideOut 0.3s ease';
                    setTimeout(() => errorDiv.remove(), 300);
                }
            }, 10000);
        }
        function sendWebSocketMessage(type, data = {}) {
            if (websocket && websocket.readyState === WebSocket.OPEN) {
                const message = { type, ...data };
                console.log('📤 Sending WebSocket message:', message);
                websocket.send(JSON.stringify(message));
                return true;
            } else {
                console.warn('⚠️ Cannot send WebSocket message: connection not open');
                return false;
            }
        }

        // Typing indicator functions
        function showTypingIndicator(userName) {
            let indicator = document.getElementById('typing-indicator');
            if (!indicator) {
                indicator = document.createElement('div');
                indicator.id = 'typing-indicator';
                indicator.className = 'typing-indicator';
                indicator.innerHTML = `
                    <span class="typing-user"></span> is typing
                    <div class="typing-dots">
                        <span></span>
                        <span></span>
                        <span></span>
                    </div>
                `;
                
                const messagesArea = document.getElementById('messages-area');
                if (messagesArea) {
                    messagesArea.appendChild(indicator);
                }
            }
            
            const typingUser = indicator.querySelector('.typing-user');
            if (typingUser) {
                typingUser.textContent = userName;
            }
            
            scrollToBottom(true);
        }
        
        function hideTypingIndicator() {
            const indicator = document.getElementById('typing-indicator');
            if (indicator) {
                indicator.remove();
            }
        }
        
        // Typing start/stop functions
        function sendTypingStart() {
            if (!isTyping && websocket && websocket.readyState === WebSocket.OPEN) {
                sendWebSocketMessage('typing_start', {
                    conversationId: selectedConversationId,
                    userId: currentUser.id,
                    userName: currentUser.name
                });
                isTyping = true;
            }
            
            // Clear existing timeout
            if (localTypingTimeout) {
                clearTimeout(localTypingTimeout);
            }
            
            // Send typing stop after 3 seconds of inactivity
            localTypingTimeout = setTimeout(() => {
                sendTypingStop();
            }, 3000);
        }
        
        function sendTypingStop() {
            if (isTyping && websocket && websocket.readyState === WebSocket.OPEN) {
                sendWebSocketMessage('typing_stop', {
                    conversationId: selectedConversationId,
                    userId: currentUser.id
                });
                isTyping = false;
            }
            
            if (localTypingTimeout) {
                clearTimeout(localTypingTimeout);
                localTypingTimeout = null;
            }
        }
        
        // Enhanced scroll to bottom
        function scrollToBottom(smooth = false) {
            const messagesArea = document.getElementById('messages-area');
            if (!messagesArea) return;
            
            const scrollOptions = {
                top: messagesArea.scrollHeight,
                behavior: smooth ? 'smooth' : 'auto'
            };
            
            messagesArea.scrollTo(scrollOptions);
        }
        
        // Utility functions
        function showConversationsLoading(show) {
            const loading = document.getElementById('conversations-loading');
            const empty = document.getElementById('empty-conversations');
            
            if (show) {
                if (loading) loading.style.display = 'flex';
                if (empty) empty.style.display = 'none';
            } else {
                if (loading) loading.style.display = 'none';
            }
        }
        
        function showEmptyConversations() {
            const loading = document.getElementById('conversations-loading');
            const empty = document.getElementById('empty-conversations');
            
            if (loading) loading.style.display = 'none';
            if (empty) empty.style.display = 'flex';
        }
        
        function hideEmptyConversations() {
            const empty = document.getElementById('empty-conversations');
            if (empty) empty.style.display = 'none';
        }
        
        // Start auto-refresh - DISABLED when using WebSockets
        function startAutoRefresh() {
            // WebSocket handles real-time updates, so we don't need polling
            // Only enable refresh as fallback if WebSocket fails
            console.log('🔄 Auto-refresh disabled - using WebSocket for real-time updates');
            
            // Optional: Enable a much slower fallback refresh (5 minutes) only for conversations list
            // in case WebSocket connection fails
            refreshInterval = setInterval(async () => {
                if (!websocket || websocket.readyState !== WebSocket.OPEN) {
                    console.log('🔄 WebSocket not connected, refreshing conversations list...');
                    await loadConversations();
                    
                    // Try to reconnect WebSocket if we have a selected conversation
                    if (selectedConversationId) {
                        console.log('🔄 Attempting to reconnect WebSocket...');
                        connectWebSocket(selectedConversationId);
                    }
                }
            }, 300000); // 5 minutes instead of 30 seconds
        }
        
        // Format conversation time
        function formatConversationTime(timestamp) {
            if (!timestamp) return '';
            
            const date = new Date(timestamp);
            const now = new Date();
            const diffMs = now - date;
            const diffMins = Math.floor(diffMs / 60000);
            const diffHours = Math.floor(diffMs / 3600000);
            const diffDays = Math.floor(diffMs / 86400000);
            
            if (diffMins < 1) return 'Just now';
            if (diffMins < 60) return `${diffMins}m ago`;
            if (diffHours < 24) return `${diffHours}h ago`;
            if (diffDays < 7) return `${diffDays}d ago`;
            
            return date.toLocaleDateString();
        }
        
        // Format message time
        function formatMessageTime(timestamp) {
            if (!timestamp) return '';
            
            const date = new Date(timestamp);
            const now = new Date();
            
            // If today, show time
            if (date.toDateString() === now.toDateString()) {
                return date.toLocaleTimeString('en-US', {
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true
                });
            }
            
            // If this week, show day and time
            const diffDays = Math.floor((now - date) / 86400000);
            if (diffDays < 7) {
                return date.toLocaleDateString('en-US', {
                    weekday: 'short',
                    hour: 'numeric',
                    minute: '2-digit',
                    hour12: true
                });
            }
            
            // Otherwise show date and time
            return date.toLocaleDateString('en-US', {
                month: 'short',
                day: 'numeric',
                hour: 'numeric',
                minute: '2-digit',
                hour12: true
            });
        }
        
        // Escape HTML
        function escapeHtml(text) {
            if (!text) return '';
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }
        
        // Capitalize first letter
        function capitalizeFirst(str) {
            if (!str) return '';
            return str.charAt(0).toUpperCase() + str.slice(1);
        }
        
        // Mobile navigation functions
        function showMobileChatView() {
            const conversationsSidebar = document.querySelector('.conversations-sidebar');
            const chatArea = document.querySelector('.chat-area');
            
            conversationsSidebar.classList.add('mobile-hidden');
            chatArea.classList.add('mobile-visible');
            
            // Add back button to chat header if not already present
            addMobileBackButton();
        }
        
        function showMobileConversationsView() {
            const conversationsSidebar = document.querySelector('.conversations-sidebar');
            const chatArea = document.querySelector('.chat-area');
            
            conversationsSidebar.classList.remove('mobile-hidden');
            chatArea.classList.remove('mobile-visible');
        }
        
        function addMobileBackButton() {
            const chatHeader = document.getElementById('chat-header');
            
            // Check if back button already exists
            if (chatHeader.querySelector('.mobile-chat-back')) {
                return;
            }
            
            const backButton = document.createElement('div');
            backButton.className = 'mobile-chat-back';
            backButton.innerHTML = '<i class="fas fa-arrow-left"></i> Back to conversations';
            backButton.onclick = showMobileConversationsView;
            
            chatHeader.insertBefore(backButton, chatHeader.firstChild);
        }
        
        function hideMobileChatView() {
            const sidebar = document.querySelector('.conversations-sidebar');
            const chatArea = document.querySelector('.chat-area');
            
            if (sidebar) sidebar.classList.remove('mobile-hidden');
            if (chatArea) chatArea.classList.remove('mobile-visible');
            
            // Remove mobile back button
            const backButton = document.querySelector('.mobile-chat-back');
            if (backButton) {
                backButton.remove();
            }
        }
        
        function handleWindowResize() {
            if (window.innerWidth > 800) {
                // Reset mobile classes on desktop
                const sidebar = document.querySelector('.conversations-sidebar');
                const chatArea = document.querySelector('.chat-area');
                
                if (sidebar) sidebar.classList.remove('mobile-hidden');
                if (chatArea) chatArea.classList.remove('mobile-visible');
                
                const backButton = document.querySelector('.mobile-chat-back');
                if (backButton) {
                    backButton.remove();
                }
            }
        }
        
        // Navigation functions
        function toggleUserMenu() {
            const dropdown = document.getElementById('user-dropdown');
            if (dropdown) {
                dropdown.classList.toggle('show');
            }
        }
        
        // Close user menu when clicking outside
        document.addEventListener('click', (e) => {
            const userMenu = document.querySelector('.user-menu');
            const dropdown = document.getElementById('user-dropdown');
            
            if (userMenu && dropdown && !userMenu.contains(e.target)) {
                dropdown.classList.remove('show');
            }
        });
        
        // Mobile menu functions
        function toggleMobileMenu() {
            const sidebar = document.getElementById('mobile-sidebar');
            const overlay = document.querySelector('.mobile-overlay');

            sidebar.classList.toggle('open');
            overlay.classList.toggle('active');
            document.body.style.overflow = sidebar.classList.contains('open') ? 'hidden' : '';
        }
        
        function closeMobileMenu() {
            const sidebar = document.getElementById('mobile-sidebar');
            const overlay = document.querySelector('.mobile-overlay');

            sidebar.classList.remove('open');
            overlay.classList.remove('active');
            document.body.style.overflow = '';
        }
        
		// Toggle user menu
        function toggleUserMenu() {
            const dropdown = document.getElementById('user-dropdown');
            dropdown.classList.toggle('show');
            
            document.addEventListener('click', function closeDropdown(e) {
                if (!e.target.closest('.user-menu')) {
                    dropdown.classList.remove('show');
                    document.removeEventListener('click', closeDropdown);
                }
            });
        }
		
        function logout() {
            document.getElementById('user-dropdown').classList.remove('show');
            enhancedLogout();
        }
        
        // Demo function
        function refreshChatForDemo() {
            console.log('🔄 Demo refresh triggered');
            
            // Add a demo message
            if (selectedConversationId) {
                const demoMessage = {
                    id: Date.now(),
                    sender_id: currentUser.id === 1 ? 2 : 1, // Opposite user
                    sender_name: 'Demo User',
                    message: 'This is a demo message! 👋',
                    created_at: new Date().toISOString()
                };
                
                const messageElement = createMessageElement(demoMessage);
                const messagesArea = document.getElementById('messages-area');
                if (messagesArea) {
                    messagesArea.appendChild(messageElement);
                    scrollToBottom(true);
                }
                
                playNotificationSound('message');
                showTypingIndicator('Demo User');
                
                setTimeout(() => {
                    hideTypingIndicator();
                }, 2000);
            }
        }
        
        // Enhanced message input setup
        function setupEnhancedMessageInput() {
            const messageInput = document.getElementById('message-input');
            if (!messageInput) return;
            
            // Typing indicators
            messageInput.addEventListener('input', () => {
                if (selectedConversationId && messageInput.value.trim()) {
                    sendTypingStart();
                } else {
                    sendTypingStop();
                }
            });
            
            // Stop typing when focus is lost
            messageInput.addEventListener('blur', () => {
                sendTypingStop();
            });
            
            // Handle paste events
            messageInput.addEventListener('paste', (e) => {
                // Allow paste but limit length
                setTimeout(() => {
                    if (messageInput.value.length > 1000) {
                        messageInput.value = messageInput.value.substring(0, 1000);
                        showErrorFeedback('Message too long. Maximum 1000 characters.');
                    }
                }, 10);
            });
        }
        
        // Setup keyboard navigation
        function setupKeyboardNavigation() {
            document.addEventListener('keydown', (e) => {
                // Escape key to close mobile menu
                if (e.key === 'Escape') {
                    closeMobileMenu();
                    
                    const dropdown = document.getElementById('user-dropdown');
                    if (dropdown) dropdown.classList.remove('show');
                }
                
                // Ctrl/Cmd + Enter to send message
                if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
                    e.preventDefault();
                    sendMessage();
                }
                
                // Alt + 1-9 to switch conversations
                if (e.altKey && e.key >= '1' && e.key <= '9') {
                    e.preventDefault();
                    const index = parseInt(e.key) - 1;
                    if (conversations[index]) {
                        selectConversation(conversations[index].id);
                    }
                }
            });
        }
        
        // Setup ARIA labels and roles for accessibility
        function setupAccessibility() {
            // Add ARIA labels to key elements
            const elements = {
                'conversations-list': 'Conversations list',
                'messages-area': 'Messages',
                'message-input': 'Type your message',
                'send-button': 'Send message',
                'search-conversations': 'Search conversations'
            };
            
            Object.entries(elements).forEach(([id, label]) => {
                const element = document.getElementById(id);
                if (element) {
                    element.setAttribute('aria-label', label);
                }
            });
            
            // Add live region for status updates
            const liveRegion = document.createElement('div');
            liveRegion.id = 'status-live-region';
            liveRegion.setAttribute('aria-live', 'polite');
            liveRegion.setAttribute('aria-atomic', 'true');
            liveRegion.style.position = 'absolute';
            liveRegion.style.left = '-10000px';
            liveRegion.style.width = '1px';
            liveRegion.style.height = '1px';
            liveRegion.style.overflow = 'hidden';
            document.body.appendChild(liveRegion);
        }
		// Refresh chat for demo purposes (triggered by backtick key)
        async function refreshChatForDemo() {
            console.log('🔄 Demo refresh triggered by backtick key...');
            
            try {
                // Store current conversation ID
                const currentConversationId = selectedConversationId;
                
                // Reload conversations (same as 30-second refresh)
                await loadConversations();
                
                // If we were in a conversation, reload its messages
                if (currentConversationId) {
                    console.log(`🔄 Refreshing messages for conversation ${currentConversationId}`);
                    await loadMessages(currentConversationId);
                    
                    // Ensure the conversation stays highlighted
                    const activeItem = document.querySelector(`[data-conversation-id="${currentConversationId}"]`);
                    if (activeItem) {
                        activeItem.classList.add('active');
                    }
                }
                
                console.log('✅ Demo refresh completed!');
            } catch (error) {
                console.error('❌ Demo refresh failed:', error);
            }
        }
        
        // Announce status changes for screen readers
        function announceStatusChange(message) {
            const liveRegion = document.getElementById('status-live-region');
            if (liveRegion) {
                liveRegion.textContent = message;
            }
        }
        
        // Initialize ping interval
        function startPingInterval() {
            if (pingInterval) {
                clearInterval(pingInterval);
            }
            
            pingInterval = setInterval(() => {
                sendPing();
            }, 30000); // Ping every 30 seconds
        }
        
        // Stop ping interval
        function stopPingInterval() {
            if (pingInterval) {
                clearInterval(pingInterval);
                pingInterval = null;
            }
        }
        
        // Enhanced setup after DOM loaded
        document.addEventListener('DOMContentLoaded', () => {
            setupEnhancedMessageInput();
            console.log('✅ All enhanced messaging features initialized');
        });
        
        // Export functions for debugging (only in development)
        if (window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1') {
            window.messagingDebug = {
                connectGlobalWebSocket,
                connectWebSocket,
                sendWebSocketMessage,
                processMessageBuffer,
                showTypingIndicator,
                hideTypingIndicator,
                playNotificationSound,
                updateConnectionStatus,
                checkConnectionQuality: () => checkConnectionQuality()
            };
        }
    </script>