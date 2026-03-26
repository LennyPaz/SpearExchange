// Complete the missing functions file

// Hide typing indicator
function hideTypingIndicator(userName) {
    const typingElement = document.getElementById(`typing-${userName}`);
    if (typingElement) {
        typingElement.remove();
    }
}

// Send typing start notification
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

// Send typing stop notification
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

// ===== RATE LIMITING =====

// Check rate limiting
function checkRateLimit() {
    const now = Date.now();
    
    // Reset counter every minute
    if (now - lastMessageTime > 60000) {
        messagesSentInLastMinute = 0;
    }
    
    if (messagesSentInLastMinute >= messageRateLimit) {
        showErrorFeedback('You are sending messages too quickly. Please wait a moment.');
        return false;
    }
    
    return true;
}

// ===== ERROR HANDLING =====

// Show error feedback
function showErrorFeedback(message) {
    // Remove existing error banner
    const existingBanner = document.getElementById('error-banner');
    if (existingBanner) {
        existingBanner.remove();
    }
    
    const banner = document.createElement('div');
    banner.id = 'error-banner';
    banner.className = 'error-banner';
    banner.innerHTML = `
        ${escapeHtml(message)}
        <button class="retry-button" onclick="this.parentElement.remove()">Dismiss</button>
    `;
    
    document.body.appendChild(banner);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
        if (banner && banner.parentElement) {
            banner.remove();
        }
    }, 5000);
    
    playNotificationSound('error');
}

// Show offline indicator
function showOfflineIndicator() {
    if (document.getElementById('offline-indicator')) return;
    
    const indicator = document.createElement('div');
    indicator.id = 'offline-indicator';
    indicator.className = 'offline-indicator';
    indicator.innerHTML = `
        📴 You're offline. Messages will be sent when connection is restored.
        <button class="retry-button" onclick="processMessageBuffer()">Retry Now</button>
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

// Retry message sending
function retryMessage(element) {
    const messageElement = element.closest('.message');
    if (!messageElement) return;
    
    const messageId = messageElement.getAttribute('data-message-id');
    const messageContent = messageElement.querySelector('.message-content').textContent;
    
    // Find the message in pending messages
    const tempId = Date.now() + Math.random();
    const messageData = {
        id: tempId,
        tempId: tempId,
        sender_id: currentUser.id,
        sender_name: currentUser.name,
        message: messageContent,
        created_at: new Date().toISOString()
    };
    
    // Update status to sending
    updateMessageStatus(messageId, 'sending');
    
    // Try to send again
    if (websocket && websocket.readyState === WebSocket.OPEN) {
        sendWebSocketMessage('new_message', {
            content: messageContent,
            conversationId: selectedConversationId,
            tempId: tempId
        });
    } else {
        bufferMessage(messageData, selectedConversationId);
    }
}

// ===== UI UPDATE HELPERS =====

// Update conversation in sidebar
function updateConversationInSidebar(data) {
    const conversationElement = document.querySelector(`[data-conversation-id="${data.conversationId}"]`);
    if (conversationElement) {
        // Update last message and time
        const lastMessageElement = conversationElement.querySelector('.last-message');
        const timeElement = conversationElement.querySelector('.conversation-time');
        
        if (lastMessageElement) {
            lastMessageElement.textContent = data.lastMessage || 'No messages yet';
        }
        if (timeElement) {
            timeElement.textContent = formatConversationTime(data.lastMessageAt);
        }
        
        // Move to top of list
        const conversationsList = document.getElementById('conversations-list');
        if (conversationsList.firstChild !== conversationElement) {
            conversationsList.insertBefore(conversationElement, conversationsList.firstChild);
        }
    }
}

// Update conversation last message
function updateConversationLastMessage(conversationId, message) {
    const conversationElement = document.querySelector(`[data-conversation-id="${conversationId}"]`);
    if (conversationElement) {
        const lastMessageElement = conversationElement.querySelector('.last-message');
        if (lastMessageElement) {
            lastMessageElement.textContent = message;
        }
    }
}

// Add new conversation to sidebar
function addNewConversationToSidebar(data) {
    // Add to conversations array
    conversations.unshift(data.conversation);
    filteredConversations = [...conversations];
    
    // Rebuild conversations list
    displayConversations();
}

// Update user online status
function updateUserOnlineStatus(userId, isOnline) {
    // Could add online indicators next to user names
    console.log(`User ${userId} is now ${isOnline ? 'online' : 'offline'}`);
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

// ===== UTILITY FUNCTIONS =====

// Show/hide conversations loading
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

// Show/hide empty conversations
function showEmptyConversations() {
    document.getElementById('conversations-loading').style.display = 'none';
    document.getElementById('empty-conversations').style.display = 'flex';
}

function hideEmptyConversations() {
    document.getElementById('empty-conversations').style.display = 'none';
}

// Start auto-refresh for conversations
function startAutoRefresh() {
    // Refresh conversations every 30 seconds
    refreshInterval = setInterval(async () => {
        try {
            await loadConversations();
        } catch (error) {
            console.error('Auto-refresh failed:', error);
        }
    }, 30000);
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

// ===== MOBILE SUPPORT =====

// Show mobile chat view
function showMobileChatView() {
    if (window.innerWidth <= 800) {
        document.querySelector('.conversations-sidebar').classList.add('mobile-hidden');
        document.querySelector('.chat-area').classList.add('mobile-visible');
        
        // Add mobile back button
        const chatHeader = document.getElementById('chat-header');
        if (chatHeader && !chatHeader.querySelector('.mobile-chat-back')) {
            const backButton = document.createElement('div');
            backButton.className = 'mobile-chat-back';
            backButton.innerHTML = `
                <i class="fas fa-arrow-left"></i>
                <span>Back to conversations</span>
            `;
            backButton.onclick = hideMobileChatView;
            
            chatHeader.insertBefore(backButton, chatHeader.firstChild);
        }
    }
}

// Hide mobile chat view
function hideMobileChatView() {
    document.querySelector('.conversations-sidebar').classList.remove('mobile-hidden');
    document.querySelector('.chat-area').classList.remove('mobile-visible');
    
    // Remove mobile back button
    const backButton = document.querySelector('.mobile-chat-back');
    if (backButton) {
        backButton.remove();
    }
}

// Handle window resize
function handleWindowResize() {
    if (window.innerWidth > 800) {
        // Reset mobile classes on desktop
        document.querySelector('.conversations-sidebar').classList.remove('mobile-hidden');
        document.querySelector('.chat-area').classList.remove('mobile-visible');
        
        const backButton = document.querySelector('.mobile-chat-back');
        if (backButton) {
            backButton.remove();
        }
    }
}

// ===== NAVIGATION FUNCTIONS =====

// Toggle user menu
function toggleUserMenu() {
    const dropdown = document.getElementById('user-dropdown');
    dropdown.classList.toggle('show');
}

// Close user menu when clicking outside
document.addEventListener('click', (e) => {
    const userMenu = document.querySelector('.user-menu');
    const dropdown = document.getElementById('user-dropdown');
    
    if (!userMenu.contains(e.target)) {
        dropdown.classList.remove('show');
    }
});

// Toggle mobile menu
function toggleMobileMenu() {
    const sidebar = document.getElementById('mobile-sidebar');
    const overlay = document.querySelector('.mobile-overlay');
    
    sidebar.classList.add('open');
    overlay.classList.add('active');
}

// Close mobile menu
function closeMobileMenu() {
    const sidebar = document.getElementById('mobile-sidebar');
    const overlay = document.querySelector('.mobile-overlay');
    
    sidebar.classList.remove('open');
    overlay.classList.remove('active');
}

// Logout function
function logout() {
    enhancedLogout();
}

// ===== DEMO FUNCTIONS =====

// Refresh chat for demo (backtick key)
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
            hideTypingIndicator('Demo User');
        }, 2000);
    }
}

// ===== ENHANCED MESSAGE INPUT =====

// Setup enhanced message input listeners
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

// Enhanced message input setup on conversation load
document.addEventListener('DOMContentLoaded', () => {
    setupEnhancedMessageInput();
});

// Re-setup when showing chat interface
const originalShowChatInterface = showChatInterface;
showChatInterface = function() {
    originalShowChatInterface();
    setTimeout(setupEnhancedMessageInput, 100);
};

// ===== PERFORMANCE OPTIMIZATIONS =====

// Debounced DOM updates
function debouncedUpdate(updateFunction, delay = 100) {
    return function(...args) {
        clearTimeout(this.debounceTimer);
        this.debounceTimer = setTimeout(() => updateFunction.apply(this, args), delay);
    };
}

// Throttled scroll handling
function throttledScrollHandler(handler, delay = 16) {
    let lastTime = 0;
    return function(...args) {
        const now = Date.now();
        if (now - lastTime > delay) {
            lastTime = now;
            handler.apply(this, args);
        }
    };
}

// ===== ACCESSIBILITY IMPROVEMENTS =====

// Setup keyboard navigation
function setupKeyboardNavigation() {
    document.addEventListener('keydown', (e) => {
        // Escape key to close mobile menu
        if (e.key === 'Escape') {
            closeMobileMenu();
            
            const dropdown = document.getElementById('user-dropdown');
            dropdown.classList.remove('show');
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

// Setup ARIA labels and roles
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

// Announce status changes for screen readers
function announceStatusChange(message) {
    const liveRegion = document.getElementById('status-live-region');
    if (liveRegion) {
        liveRegion.textContent = message;
    }
}

// ===== INITIALIZATION COMPLETION =====

// Setup additional features after DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    setupKeyboardNavigation();
    setupAccessibility();
    
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
        checkConnectionHealth
    };
}