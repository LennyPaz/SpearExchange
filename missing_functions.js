// Missing functions to add to the messages index.html file

// Add this function after line 2310 (after handleUserLeft function):
function updateActiveUsersDisplay() {
    // This could be implemented to show active user count
    console.log('Active users:', Array.from(activeUsers));
}

// Add this function to show WebSocket errors:
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

// Improved handleWebSocketMessage function:
function handleWebSocketMessage(data) {
    console.log('📨 WebSocket message received:', data);
    
    switch (data.type) {
        case 'connection_established':
            console.log('🎉 Connected to chat room');
            clearWebSocketError(); // Clear any existing error indicators
            break;
            
        case 'ping':
            // Respond to ping with pong
            sendWebSocketMessage('pong', { timestamp: new Date().toISOString() });
            break;
            
        case 'pong':
            console.log('🏓 Received pong from server');
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
            handleUserLeft(data);
            break;
            
        case 'messages_read':
            handleMessagesRead(data);
            break;
            
        case 'error':
            console.error('WebSocket error:', data.message);
            showWebSocketError(data.message);
            break;
            
        default:
            console.log('Unknown WebSocket message type:', data.type);
    }
}

// Improved scrollToBottom function:
function scrollToBottom() {
    const messagesArea = document.getElementById('messages-area');
    if (messagesArea) {
        // Use requestAnimationFrame to ensure DOM is updated
        requestAnimationFrame(() => {
            messagesArea.scrollTop = messagesArea.scrollHeight;
        });
    }
}

// Update displayMessages to use the improved scroll function:
function displayMessages() {
    const messagesArea = document.getElementById('messages-area');
    messagesArea.innerHTML = '';

    messages.forEach(message => {
        const messageElement = createMessageElement(message);
        messagesArea.appendChild(messageElement);
    });

    // Auto-scroll to bottom
    scrollToBottom();
}
