// chat-room.js - Enhanced Durable Object for handling WebSocket connections
export class ChatRoom {
  constructor(controller, env) {
    this.controller = controller;
    this.env = env;
    this.sessions = new Map(); // Store active WebSocket connections
    this.storage = controller.storage; // Persistent storage
    
    // Enhanced features
    this.typingUsers = new Map(); // Track typing users
    this.messageRateLimit = new Map(); // Rate limiting per user
    this.connectionHealth = new Map(); // Connection health tracking
    this.userActivity = new Map(); // Track user activity
    this.startTime = Date.now();
    
    // Enhanced message buffering for reconnecting clients
    this.messageBuffer = new Map(); // Store recent messages per conversation
    this.deliveryReceipts = new Map(); // Track message delivery status
    this.readReceipts = new Map(); // Track message read status
    this.recentMessages = new Map(); // Cache recent messages for catchup
    
    // Initialize maintenance scheduler
    this.initMaintenanceScheduler();
  }
  
  // Buffer message for catchup functionality
  bufferMessageForCatchup(conversationId, messageData) {
    if (!this.recentMessages.has(conversationId)) {
      this.recentMessages.set(conversationId, []);
    }
    
    const messages = this.recentMessages.get(conversationId);
    messages.push({
      ...messageData,
      bufferedAt: Date.now()
    });
    
    // Keep only the last 50 messages for catchup
    if (messages.length > 50) {
      messages.splice(0, messages.length - 50);
    }
    
    this.recentMessages.set(conversationId, messages);
  }
  
  // Send missed messages to reconnecting user
  async sendMissedMessages(websocket, session) {
    if (!session.conversationId) return;
    
    const recentMessages = this.recentMessages.get(session.conversationId) || [];
    const cutoffTime = Date.now() - (5 * 60 * 1000); // Last 5 minutes
    
    const missedMessages = recentMessages.filter(msg => 
      msg.bufferedAt > cutoffTime && msg.senderId !== session.userId
    );
    
    if (missedMessages.length > 0) {
      console.log(`Sending ${missedMessages.length} missed messages to user ${session.userId}`);
      
      // Send catchup notification
      websocket.send(JSON.stringify({
        type: 'catchup_start',
        messageCount: missedMessages.length,
        timestamp: new Date().toISOString()
      }));
      
      // Send each missed message
      for (const message of missedMessages) {
        websocket.send(JSON.stringify({
          ...message,
          type: 'missed_message'
        }));
      }
      
      // Send catchup complete notification
      websocket.send(JSON.stringify({
        type: 'catchup_complete',
        timestamp: new Date().toISOString()
      }));
    }
  }
  
  // Simple spam detection
  isSpamMessage(content, userId) {
    const now = Date.now();
    const userActivity = this.userActivity.get(userId) || { messages: [], lastReset: now };
    
    // Reset if more than a minute has passed
    if (now - userActivity.lastReset > 60000) {
      userActivity.messages = [];
      userActivity.lastReset = now;
    }
    
    // Check for repeated identical messages
    const recentIdentical = userActivity.messages.filter(
      msg => msg.content === content && now - msg.timestamp < 10000
    ).length;
    
    if (recentIdentical >= 3) {
      return true; // Same message sent 3+ times in 10 seconds
    }
    
    // Add current message to tracking
    userActivity.messages.push({ content, timestamp: now });
    
    // Keep only last 10 messages
    if (userActivity.messages.length > 10) {
      userActivity.messages.shift();
    }
    
    this.userActivity.set(userId, userActivity);
    return false;
  }
  
  // Track delivery receipts
  trackDeliveryReceipt(messageId, conversationId) {
    if (!this.deliveryReceipts.has(conversationId)) {
      this.deliveryReceipts.set(conversationId, new Map());
    }
    
    const conversationReceipts = this.deliveryReceipts.get(conversationId);
    conversationReceipts.set(messageId, {
      delivered: new Set(),
      read: new Set(),
      timestamp: Date.now()
    });
    
    // Broadcast delivery receipt to sender
    this.broadcastToRoom(conversationId, {
      type: 'delivery_receipt',
      messageId: messageId,
      status: 'delivered',
      timestamp: new Date().toISOString()
    });
  }
  
  // Initialize maintenance scheduler
  initMaintenanceScheduler() {
    // Schedule maintenance every 5 minutes
    this.maintenanceInterval = setInterval(() => {
      this.performMaintenance();
    }, 300000); // 5 minutes
  }

  // Handle HTTP requests (WebSocket upgrades and room management)
  async fetch(request) {
    const url = new URL(request.url);
    
    // Handle WebSocket upgrade
    if (request.headers.get("Upgrade") === "websocket") {
      return this.handleWebSocketUpgrade(request);
    }
    
    // Handle getting active users
    if (url.pathname.includes("active-users")) {
      return new Response(JSON.stringify(this.getActiveUsers()), {
        headers: { 'Content-Type': 'application/json' }
      });
    }
    
    // Handle typing indicators
    if (url.pathname.includes("typing")) {
      return this.handleTypingRequest(request);
    }
    
    // Handle read receipts
    if (url.pathname.includes("read-receipt")) {
      return this.handleReadReceiptRequest(request);
    }
    
    // Handle connection health check
    if (url.pathname.includes("health")) {
      return this.handleHealthCheck(request);
    }
    
    return new Response("Enhanced Chat Room Durable Object", { status: 200 });
  }

  // Enhanced WebSocket connection upgrade
  async handleWebSocketUpgrade(request) {
    const url = new URL(request.url);
    const conversationId = url.searchParams.get('conversationId');
    const userId = url.searchParams.get('userId');
    const userName = url.searchParams.get('userName');
    const isGlobal = url.searchParams.get('global') === 'true';
    
    // Get enhanced headers from worker
    const userIdFromHeader = request.headers.get('X-User-ID');
    const userNameFromHeader = request.headers.get('X-User-Name');
    const rateLimit = parseInt(request.headers.get('X-Rate-Limit') || '30');
    const connectionTime = request.headers.get('X-Connection-Time');

    if (!userId && !userIdFromHeader) {
      return new Response("Missing required parameters", { status: 400 });
    }

    const finalUserId = parseInt(userIdFromHeader || userId);
    const finalUserName = userNameFromHeader || userName || 'User';

    // Create WebSocket pair
    const [client, server] = Object.values(new WebSocketPair());

    // Accept the WebSocket connection with enhanced configuration
    server.accept();
    
    // Enhanced session tracking
    const session = {
      websocket: server,
      userId: finalUserId,
      userName: finalUserName,
      conversationId: conversationId ? parseInt(conversationId) : null,
      isGlobal: isGlobal,
      joinedAt: new Date().toISOString(),
      lastPingTime: Date.now(),
      lastPongTime: Date.now(),
      lastActivityTime: Date.now(),
      missedPings: 0,
      isActive: true,
      rateLimit: rateLimit,
      messageCount: 0,
      lastMessageTime: 0,
      connectionQuality: 'good'
    };

    // Store the session
    this.sessions.set(server, session);
    
    // Initialize rate limiting for this user
    this.messageRateLimit.set(finalUserId, {
      count: 0,
      resetTime: Date.now() + 60000, // Reset every minute
      limit: rateLimit
    });
    
    // Track connection health
    this.connectionHealth.set(server, {
      connectTime: Date.now(),
      pingCount: 0,
      pongCount: 0,
      avgLatency: 0,
      lastLatency: 0
    });

    // Set up enhanced WebSocket event handlers
    server.addEventListener("message", (event) => {
      this.handleWebSocketMessage(server, event.data);
    });

    server.addEventListener("close", (event) => {
      console.log(`WebSocket closed: code=${event.code}, reason=${event.reason}`);
      this.handleWebSocketClose(server, event);
    });

    server.addEventListener("error", (error) => {
      console.error("WebSocket error:", error);
      this.handleWebSocketClose(server, { code: 1006, reason: 'error' });
    });

    // Start enhanced ping interval for this connection
    this.startEnhancedPingInterval(server, session);

    if (isGlobal) {
      // Send welcome message to global connection
      server.send(JSON.stringify({
        type: 'connection_established',
        message: 'Connected to global chat system',
        timestamp: new Date().toISOString(),
        connectionId: `global-${finalUserId}`,
        features: ['typing_indicators', 'read_receipts', 'connection_monitoring']
      }));
    } else if (conversationId) {
      // Notify other users that someone joined this specific conversation
      this.broadcastToRoom(conversationId, {
        type: 'user_joined',
        userId: finalUserId,
        userName: finalUserName,
        timestamp: new Date().toISOString()
      }, [finalUserId]);

      // Send welcome message to the new user
      server.send(JSON.stringify({
        type: 'connection_established',
        message: 'Connected to chat room',
        timestamp: new Date().toISOString(),
        connectionId: `conversation-${conversationId}`,
        features: ['typing_indicators', 'read_receipts', 'connection_monitoring']
      }));
      
      // Send missed messages to reconnecting user (catchup)
      await this.sendMissedMessages(server, session);
    }

      return new Response(null, {
        status: 101,
        webSocket: client,
      });
    }


  // Enhanced WebSocket message handling with rate limiting
  async handleWebSocketMessage(websocket, data) {
    try {
      const session = this.sessions.get(websocket);
      if (!session) {
        console.error('No session found for websocket');
        return;
      }

      // Update last activity time
      session.lastActivityTime = Date.now();
      
      const message = JSON.parse(data);
      console.log('Received WebSocket message:', message.type, 'from user:', session.userId);
      
      // Rate limiting check for message-type events
      if (message.type === 'new_message') {
        const rateLimitData = this.messageRateLimit.get(session.userId);
        if (rateLimitData) {
          const now = Date.now();
          
          // Reset counter if time window has passed
          if (now > rateLimitData.resetTime) {
            rateLimitData.count = 0;
            rateLimitData.resetTime = now + 60000; // Next minute
          }
          
          // Check if rate limit exceeded
          if (rateLimitData.count >= rateLimitData.limit) {
            websocket.send(JSON.stringify({
              type: 'error',
              message: `Rate limit exceeded. Maximum ${rateLimitData.limit} messages per minute.`,
              timestamp: new Date().toISOString(),
              code: 'RATE_LIMIT_EXCEEDED'
            }));
            return;
          }
          
          rateLimitData.count++;
        }
      }
      
      switch (message.type) {
        case 'ping':
          // Client is pinging us - respond with pong and update health metrics
          const health = this.connectionHealth.get(websocket);
          session.lastPingTime = Date.now();
          session.missedPings = 0; // Reset missed ping counter
          
          if (health && message.timestamp) {
            const latency = Date.now() - message.timestamp;
            health.lastLatency = latency;
            health.avgLatency = health.avgLatency > 0 
              ? (health.avgLatency + latency) / 2 
              : latency;
          }
          
          websocket.send(JSON.stringify({
            type: 'pong',
            timestamp: new Date().toISOString(),
            serverId: 'chat-room',
            latency: health ? health.lastLatency : 0
          }));
          console.log(`Responded to ping from user ${session.userId}`);
          break;
          
        case 'pong':
          // Client is responding to our ping - update health metrics
          const pongHealth = this.connectionHealth.get(websocket);
          session.lastPongTime = Date.now();
          session.missedPings = 0; // Reset missed ping counter
          session.isActive = true;
          
          if (pongHealth && message.timestamp) {
            const latency = session.lastPongTime - message.timestamp;
            pongHealth.lastLatency = latency;
            pongHealth.avgLatency = pongHealth.avgLatency > 0 
              ? (pongHealth.avgLatency + latency) / 2 
              : latency;
            pongHealth.pongCount++;
            
            // Update connection quality based on latency
            if (latency > 2000) {
              session.connectionQuality = 'poor';
            } else if (latency > 1000) {
              session.connectionQuality = 'fair';
            } else {
              session.connectionQuality = 'good';
            }
          }
          
          console.log(`Received pong from user ${session.userId}`);
          break;
          
        case 'join_conversation':
          // Handle explicit join conversation message
          console.log(`User ${session.userId} explicitly joined conversation ${session.conversationId}`);
          session.joinedAt = new Date().toISOString();
          
          // Send current active users to the joining user
          const activeUsers = this.getActiveUsers(session.conversationId);
          websocket.send(JSON.stringify({
            type: 'active_users',
            users: activeUsers,
            timestamp: new Date().toISOString()
          }));
          break;
          
        case 'new_message':
          await this.handleNewMessage(session, message);
          break;
          
        case 'typing_start':
          this.handleEnhancedTypingStart(session);
          break;
          
        case 'typing_stop':
          this.handleEnhancedTypingStop(session);
          break;
          
        case 'mark_read':
          await this.handleMarkRead(session, message);
          break;
          
        case 'request_active_users':
          // Send current active users
          const currentUsers = this.getActiveUsers(session.conversationId);
          websocket.send(JSON.stringify({
            type: 'active_users',
            users: currentUsers,
            timestamp: new Date().toISOString()
          }));
          break;
          
        case 'connection_quality_check':
          // Send connection quality information
          const sessionHealth = this.connectionHealth.get(websocket);
          websocket.send(JSON.stringify({
            type: 'connection_quality',
            quality: session.connectionQuality,
            latency: sessionHealth ? sessionHealth.lastLatency : 0,
            avgLatency: sessionHealth ? Math.round(sessionHealth.avgLatency) : 0,
            uptime: Date.now() - sessionHealth?.connectTime || 0,
            timestamp: new Date().toISOString()
          }));
          break;

        default:
          console.log('Unknown message type:', message.type);
          // Send error response for unknown message types
          websocket.send(JSON.stringify({
            type: 'error',
            message: `Unknown message type: ${message.type}`,
            timestamp: new Date().toISOString(),
            code: 'UNKNOWN_MESSAGE_TYPE'
          }));
      }
    } catch (error) {
      console.error('Error handling WebSocket message:', error);
      // Send error response to client
      try {
        websocket.send(JSON.stringify({
          type: 'error',
          message: 'Failed to process message',
          timestamp: new Date().toISOString(),
          code: 'MESSAGE_PROCESSING_ERROR'
        }));
      } catch (sendError) {
        console.error('Failed to send error response:', sendError);
      }
    }
  }

  // Handle new chat messages with enhanced buffering
  async handleNewMessage(session, message) {
    // Validate message content
    if (!message.content || typeof message.content !== 'string' || message.content.trim().length === 0) {
      session.websocket.send(JSON.stringify({
        type: 'error',
        message: 'Message content is required',
        timestamp: new Date().toISOString()
      }));
      return;
    }
    
    // Enhanced validation
    if (message.content.length > 2000) {
      session.websocket.send(JSON.stringify({
        type: 'error',
        message: 'Message too long. Maximum 2000 characters allowed.',
        timestamp: new Date().toISOString(),
        code: 'MESSAGE_TOO_LONG'
      }));
      return;
    }
    
    // Check for spam/abuse patterns
    if (this.isSpamMessage(message.content, session.userId)) {
      session.websocket.send(JSON.stringify({
        type: 'error',
        message: 'Message flagged as spam. Please vary your messages.',
        timestamp: new Date().toISOString(),
        code: 'SPAM_DETECTED'
      }));
      return;
    }
    
    // Save message to database through the main worker
    try {
      const dbResponse = await this.saveMessageToDatabase(
        session.conversationId,
        session.userId,
        message.content.trim()
      );

      if (dbResponse.success) {
        const messageData = {
          type: 'new_message',
          messageId: dbResponse.messageId,
          conversationId: session.conversationId,
          senderId: session.userId,
          senderName: session.userName,
          content: message.content.trim(),
          timestamp: new Date().toISOString(),
          tempId: message.tempId // For client-side message tracking
        };
        
        // Buffer message for catchup functionality
        this.bufferMessageForCatchup(session.conversationId, messageData);
        
        // Broadcast the new message to all users in the conversation
        this.broadcastToRoom(session.conversationId, messageData);
        
        // Also broadcast to global connections for cross-conversation notifications
        this.broadcastToGlobalConnections(messageData, session.userId);
        
        // Track delivery receipts
        this.trackDeliveryReceipt(messageData.messageId, session.conversationId);
        
        console.log(`Message ${dbResponse.messageId} broadcasted to conversation ${session.conversationId}`);
      } else {
        // Send error back to sender
        session.websocket.send(JSON.stringify({
          type: 'error',
          message: dbResponse.error || 'Failed to save message',
          timestamp: new Date().toISOString(),
          tempId: message.tempId
        }));
      }
    } catch (error) {
      console.error('Error saving message:', error);
      session.websocket.send(JSON.stringify({
        type: 'error',
        message: 'Internal server error',
        timestamp: new Date().toISOString(),
        tempId: message.tempId
      }));
    }
  }

  // Enhanced typing indicators with user tracking
  handleEnhancedTypingStart(session) {
    // Track typing user
    this.typingUsers.set(session.userId, {
      userName: session.userName,
      conversationId: session.conversationId,
      startTime: Date.now()
    });
    
    this.broadcastToRoom(session.conversationId, {
      type: 'typing_start',
      userId: session.userId,
      userName: session.userName,
      timestamp: new Date().toISOString()
    }, [session.userId]); // Exclude the sender
    
    // Auto-clear typing indicator after 5 seconds
    setTimeout(() => {
      if (this.typingUsers.has(session.userId)) {
        this.handleEnhancedTypingStop(session);
      }
    }, 5000);
  }

  handleEnhancedTypingStop(session) {
    // Remove from typing users
    this.typingUsers.delete(session.userId);
    
    this.broadcastToRoom(session.conversationId, {
      type: 'typing_stop',
      userId: session.userId,
      timestamp: new Date().toISOString()
    }, [session.userId]); // Exclude the sender
  }

  // Handle marking messages as read
  async handleMarkRead(session, message) {
    try {
      // Call database to mark messages as read
      await this.markMessagesAsRead(session.conversationId, session.userId);
      
      // Notify other users that messages were read
      this.broadcastToRoom(session.conversationId, {
        type: 'messages_read',
        userId: session.userId,
        conversationId: session.conversationId,
        timestamp: new Date().toISOString()
      }, [session.userId]);
    } catch (error) {
      console.error('Error marking messages as read:', error);
    }
  }

  // Enhanced WebSocket disconnection handling
  handleWebSocketClose(websocket, event = {}) {
    const session = this.sessions.get(websocket);
    if (session) {
      console.log(`User ${session.userId} disconnected: code=${event.code}, quality=${session.connectionQuality}`);
      
      // Clear any ping interval for this session
      if (session.pingInterval) {
        clearInterval(session.pingInterval);
      }
      
      // Clean up typing indicators
      if (this.typingUsers.has(session.userId)) {
        this.typingUsers.delete(session.userId);
        // Notify others that user stopped typing
        if (session.conversationId) {
          this.broadcastToRoom(session.conversationId, {
            type: 'typing_stop',
            userId: session.userId,
            timestamp: new Date().toISOString()
          }, [session.userId]);
        }
      }
      
      // Clean up rate limiting
      this.messageRateLimit.delete(session.userId);
      
      // Calculate session duration and quality metrics
      const health = this.connectionHealth.get(websocket);
      const sessionDuration = Date.now() - (health?.connectTime || Date.now());
      const avgLatency = health?.avgLatency || 0;
      
      // Determine disconnect reason and if we should notify other users
      const isGracefulDisconnect = event.code === 1000 || event.code === 1001;
      const isConnectionTimeout = session.connectionQuality === 'timeout';
      const isNetworkIssue = event.code === 1006 || avgLatency > 3000;
      
      // Only notify of user left if it's not a temporary connection issue
      if (session.conversationId && !session.isGlobal && isGracefulDisconnect) {
        this.broadcastToRoom(session.conversationId, {
          type: 'user_left',
          userId: session.userId,
          userName: session.userName,
          timestamp: new Date().toISOString(),
          reason: isConnectionTimeout ? 'timeout' : 
                  isNetworkIssue ? 'network' : 'disconnect',
          sessionDuration: sessionDuration
        }, [session.userId]);
      }

      // Clean up all tracking data
      this.sessions.delete(websocket);
      this.connectionHealth.delete(websocket);
      this.userActivity.delete(session.userId);
      
      // Log session statistics
      console.log(`Session ended for user ${session.userId}: duration=${Math.round(sessionDuration/1000)}s, quality=${session.connectionQuality}, avgLatency=${Math.round(avgLatency)}ms`);
    }
  }
  
  // Enhanced active users with connection quality
  getActiveUsers(conversationId = null) {
    const users = [];
    const now = Date.now();
    
    for (const [websocket, session] of this.sessions) {
      // Only include active sessions (responded to ping recently)
      const timeSinceLastActivity = now - Math.max(session.lastPongTime, session.lastPingTime, session.lastActivityTime);
      const isActive = timeSinceLastActivity < 90000; // 90 seconds
      
      if (isActive && (!conversationId || session.conversationId === conversationId)) {
        const health = this.connectionHealth.get(websocket);
        
        users.push({
          userId: session.userId,
          userName: session.userName,
          joinedAt: session.joinedAt,
          lastActivity: Math.max(session.lastPongTime, session.lastPingTime, session.lastActivityTime),
          connectionQuality: session.connectionQuality,
          latency: health?.lastLatency || 0,
          isTyping: this.typingUsers.has(session.userId)
        });
      }
    }
    
    return users;
  }
  
  // Cleanup inactive connections, typing indicators, and old buffered messages
  performMaintenance() {
    const now = Date.now();
    const inactiveThreshold = 300000; // 5 minutes
    const typingThreshold = 10000; // 10 seconds
    const messageBufferThreshold = 600000; // 10 minutes
    
    // Clean up inactive sessions
    for (const [websocket, session] of this.sessions) {
      const timeSinceActivity = now - Math.max(session.lastPongTime, session.lastActivityTime);
      
      if (timeSinceActivity > inactiveThreshold) {
        console.log(`Cleaning up inactive session for user ${session.userId}`);
        websocket.close(1000, 'Inactive session cleanup');
      }
    }
    
    // Clean up stale typing indicators
    for (const [userId, typingData] of this.typingUsers) {
      if (now - typingData.startTime > typingThreshold) {
        console.log(`Cleaning up stale typing indicator for user ${userId}`);
        this.typingUsers.delete(userId);
        
        // Notify that typing stopped
        this.broadcastToRoom(typingData.conversationId, {
          type: 'typing_stop',
          userId: userId,
          timestamp: new Date().toISOString()
        }, [userId]);
      }
    }
    
    // Clean up old buffered messages
    for (const [conversationId, messages] of this.recentMessages) {
      const filteredMessages = messages.filter(msg => 
        now - msg.bufferedAt < messageBufferThreshold
      );
      
      if (filteredMessages.length !== messages.length) {
        console.log(`Cleaned up ${messages.length - filteredMessages.length} old buffered messages for conversation ${conversationId}`);
        this.recentMessages.set(conversationId, filteredMessages);
      }
    }
    
    // Clean up old delivery receipts
    for (const [conversationId, receipts] of this.deliveryReceipts) {
      for (const [messageId, receiptData] of receipts) {
        if (now - receiptData.timestamp > messageBufferThreshold) {
          receipts.delete(messageId);
        }
      }
      
      if (receipts.size === 0) {
        this.deliveryReceipts.delete(conversationId);
      }
    }
    
    // Clean up old user activity data
    for (const [userId, activity] of this.userActivity) {
      if (now - activity.lastReset > messageBufferThreshold) {
        this.userActivity.delete(userId);
      }
    }
  }

  // Broadcast message to all users in a conversation
  broadcastToRoom(conversationId, message, excludeUserIds = []) {
    const messageStr = JSON.stringify(message);
    
    for (const [websocket, session] of this.sessions) {
      if (session.conversationId === conversationId && 
          !excludeUserIds.includes(session.userId)) {
        try {
          websocket.send(messageStr);
        } catch (error) {
          console.error('Error sending message to websocket:', error);
          // Remove broken connections
          this.sessions.delete(websocket);
        }
      }
    }
  }
  
  // Broadcast message to global connections for cross-conversation notifications
  broadcastToGlobalConnections(messageData, excludeUserId) {
    const messageStr = JSON.stringify(messageData);
    
    for (const [websocket, session] of this.sessions) {
      // Send to global connections, but exclude the sender
      if (session.isGlobal && session.userId !== excludeUserId) {
        try {
          websocket.send(messageStr);
        } catch (error) {
          console.error('Error sending message to global websocket:', error);
          this.sessions.delete(websocket);
        }
      }
    }
  }

  // Save message to database via HTTP call to main worker
  async saveMessageToDatabase(conversationId, userId, messageContent) {
    try {
      const response = await fetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${conversationId}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Request': 'true', // Special header for internal requests
          'X-User-ID': userId.toString() // Pass user ID for auth
        },
        body: JSON.stringify({ message: messageContent })
      });

      if (response.ok) {
        const result = await response.json();
        return { success: true, messageId: result.messageId };
      } else {
        return { success: false, error: 'Database save failed' };
      }
    } catch (error) {
      console.error('Error calling database API:', error);
      return { success: false, error: error.message };
    }
  }

  // Mark messages as read via HTTP call to main worker
  async markMessagesAsRead(conversationId, userId) {
    try {
      await fetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${conversationId}/read`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Request': 'true',
          'X-User-ID': userId.toString()
        }
      });
    } catch (error) {
      console.error('Error marking messages as read:', error);
    }
  }

  // Enhanced ping interval with connection health monitoring
  startEnhancedPingInterval(websocket, session) {
    // Clear any existing interval
    if (session.pingInterval) {
      clearInterval(session.pingInterval);
    }
    
    // Ping every 30 seconds with health monitoring
    session.pingInterval = setInterval(() => {
      if (websocket.readyState === WebSocket.OPEN) {
        const now = Date.now();
        const timeSinceLastPong = now - session.lastPongTime;
        const health = this.connectionHealth.get(websocket);
        
        // Check if we've missed too many pings (connection quality degraded)
        if (timeSinceLastPong > 120000) { // 2 minutes = 4 missed pings
          console.log(`Closing inactive connection for user ${session.userId}`);
          session.missedPings = 999; // Mark as timed out
          session.connectionQuality = 'timeout';
          websocket.close(1000, 'Ping timeout');
          return;
        }
        
        // Update connection quality based on response times
        if (health && health.avgLatency > 2000) {
          session.connectionQuality = 'poor';
        } else if (health && health.avgLatency < 500) {
          session.connectionQuality = 'good';
        }
        
        // Send enhanced ping with timestamp
        try {
          const pingData = {
            type: 'ping',
            timestamp: now,
            serverId: 'chat-room',
            sequenceId: health ? health.pingCount : 0
          };
          websocket.send(JSON.stringify(pingData));
          session.lastPingTime = now;
          session.missedPings++;
          
          if (health) {
            health.pingCount++;
          }
          
          console.log(`Sent enhanced ping to user ${session.userId} (missed: ${session.missedPings})`);
        } catch (error) {
          console.error(`Failed to ping user ${session.userId}:`, error);
          websocket.close(1006, 'Ping failed');
        }
      } else {
        // WebSocket is not open, clean up
        clearInterval(session.pingInterval);
        this.sessions.delete(websocket);
        this.connectionHealth.delete(websocket);
      }
    }, 30000); // 30 seconds
  }
  
  // Handle typing indicator requests
  async handleTypingRequest(request) {
    try {
      const userId = parseInt(request.headers.get('X-User-ID'));
      const userName = request.headers.get('X-User-Name');
      const { isTyping, conversationId } = await request.json();
      
      if (isTyping) {
        this.typingUsers.set(userId, {
          userName: userName,
          conversationId: parseInt(conversationId),
          startTime: Date.now()
        });
        
        // Broadcast typing start to other users in the conversation
        this.broadcastToRoom(parseInt(conversationId), {
          type: 'typing_start',
          userId: userId,
          userName: userName,
          timestamp: new Date().toISOString()
        }, [userId]);
        
        // Auto-clear typing indicator after 5 seconds
        setTimeout(() => {
          if (this.typingUsers.has(userId)) {
            this.typingUsers.delete(userId);
            this.broadcastToRoom(parseInt(conversationId), {
              type: 'typing_stop',
              userId: userId,
              timestamp: new Date().toISOString()
            }, [userId]);
          }
        }, 5000);
      } else {
        // Stop typing
        this.typingUsers.delete(userId);
        this.broadcastToRoom(parseInt(conversationId), {
          type: 'typing_stop',
          userId: userId,
          timestamp: new Date().toISOString()
        }, [userId]);
      }
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('Typing request error:', error);
      return new Response(JSON.stringify({ error: 'Failed to process typing indicator' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Handle read receipt requests
  async handleReadReceiptRequest(request) {
    try {
      const userId = parseInt(request.headers.get('X-User-ID'));
      const { messageId, conversationId, readBy } = await request.json();
      
      // Broadcast read receipt to other users in the conversation
      this.broadcastToRoom(parseInt(conversationId), {
        type: 'message_read',
        messageId: parseInt(messageId),
        readBy: readBy,
        timestamp: new Date().toISOString()
      }, [readBy]);
      
      return new Response(JSON.stringify({ success: true }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (error) {
      console.error('Read receipt error:', error);
      return new Response(JSON.stringify({ error: 'Failed to process read receipt' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  }
  
  // Handle connection health check
  async handleHealthCheck(request) {
    const activeConnections = this.sessions.size;
    const typingUsers = this.typingUsers.size;
    
    // Calculate average connection quality
    let totalLatency = 0;
    let connectionCount = 0;
    
    for (const [websocket, health] of this.connectionHealth) {
      if (health.avgLatency > 0) {
        totalLatency += health.avgLatency;
        connectionCount++;
      }
    }
    
    const avgLatency = connectionCount > 0 ? totalLatency / connectionCount : 0;
    
    return new Response(JSON.stringify({
      activeConnections,
      typingUsers,
      avgLatency: Math.round(avgLatency),
      uptime: Date.now() - (this.startTime || Date.now()),
      timestamp: new Date().toISOString()
    }), {
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

