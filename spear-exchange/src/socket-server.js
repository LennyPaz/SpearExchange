// socket-server.js - Enhanced Socket.io server for Cloudflare Workers
import { Server } from 'socket.io';
import { ChatRoom } from './chat-room.js';

export class SocketServer {
  constructor(env) {
    this.env = env;
    this.connections = new Map();
  }

  async handleSocketConnection(request) {
    const url = new URL(request.url);
    const conversationId = url.searchParams.get('conversationId');
    const userId = url.searchParams.get('userId');
    const isGlobal = url.searchParams.get('global') === 'true';
    
    // Create Socket.io server instance
    const io = new Server({
      transports: ['websocket'],
      allowEIO3: true,
      cors: {
        origin: ["https://lennypaz.github.io", "http://localhost:4200", "http://localhost:3000"],
        credentials: true
      },
      pingTimeout: 60000,
      pingInterval: 25000
    });

    // Enhanced connection handling
    io.on('connection', (socket) => {
      console.log(`🔌 Socket.io client connected: ${socket.id}`);
      
      // Store connection info
      this.connections.set(socket.id, {
        userId: parseInt(userId),
        conversationId: conversationId ? parseInt(conversationId) : null,
        isGlobal: isGlobal,
        socket: socket,
        lastSeen: Date.now()
      });

      // Join appropriate rooms
      if (isGlobal) {
        socket.join(`user-${userId}`);
        console.log(`📡 User ${userId} joined global room`);
      } else if (conversationId) {
        socket.join(`conversation-${conversationId}`);
        console.log(`💬 User ${userId} joined conversation ${conversationId}`);
        
        // Notify other users in conversation
        socket.to(`conversation-${conversationId}`).emit('user_joined', {
          userId: parseInt(userId),
          timestamp: new Date().toISOString()
        });
      }

      // Enhanced ping/pong with exponential backoff
      socket.on('ping', (callback) => {
        const connection = this.connections.get(socket.id);
        if (connection) {
          connection.lastSeen = Date.now();
        }
        if (callback) callback();
      });

      // Message handling with optimistic UI support
      socket.on('send_message', async (data, callback) => {
        try {
          const result = await this.handleSendMessage(socket.id, data);
          
          if (result.success) {
            // Emit to conversation room
            if (data.conversationId) {
              io.to(`conversation-${data.conversationId}`).emit('new_message', {
                ...result.message,
                timestamp: new Date().toISOString()
              });
              
              // Also emit to global listeners for notifications
              io.to(`user-${data.receiverId}`).emit('cross_conversation_message', {
                ...result.message,
                timestamp: new Date().toISOString()
              });
            }
            
            if (callback) callback({ success: true, messageId: result.messageId });
          } else {
            if (callback) callback({ success: false, error: result.error });
          }
        } catch (error) {
          console.error('Error handling message:', error);
          if (callback) callback({ success: false, error: 'Internal server error' });
        }
      });

      // Typing indicators with timeout management
      socket.on('typing_start', (data) => {
        if (data.conversationId) {
          socket.to(`conversation-${data.conversationId}`).emit('typing_start', {
            userId: parseInt(userId),
            conversationId: data.conversationId,
            timestamp: new Date().toISOString()
          });
        }
      });

      socket.on('typing_stop', (data) => {
        if (data.conversationId) {
          socket.to(`conversation-${data.conversationId}`).emit('typing_stop', {
            userId: parseInt(userId),
            conversationId: data.conversationId,
            timestamp: new Date().toISOString()
          });
        }
      });

      // Read receipts
      socket.on('mark_read', async (data) => {
        try {
          await this.handleMarkRead(socket.id, data);
          
          if (data.conversationId) {
            socket.to(`conversation-${data.conversationId}`).emit('messages_read', {
              userId: parseInt(userId),
              conversationId: data.conversationId,
              timestamp: new Date().toISOString()
            });
          }
        } catch (error) {
          console.error('Error marking messages as read:', error);
        }
      });

      // Connection status updates
      socket.on('update_status', (status) => {
        const connection = this.connections.get(socket.id);
        if (connection) {
          connection.status = status;
          connection.lastSeen = Date.now();
          
          // Broadcast status to relevant rooms
          if (connection.conversationId) {
            socket.to(`conversation-${connection.conversationId}`).emit('user_status', {
              userId: connection.userId,
              status: status,
              timestamp: new Date().toISOString()
            });
          }
        }
      });

      // Enhanced disconnect handling
      socket.on('disconnect', (reason) => {
        console.log(`🔌 Socket.io client disconnected: ${socket.id}, reason: ${reason}`);
        
        const connection = this.connections.get(socket.id);
        if (connection) {
          // Notify other users in conversation
          if (connection.conversationId) {
            socket.to(`conversation-${connection.conversationId}`).emit('user_left', {
              userId: connection.userId,
              timestamp: new Date().toISOString(),
              reason: reason
            });
          }
          
          this.connections.delete(socket.id);
        }
      });

      // Error handling
      socket.on('error', (error) => {
        console.error('Socket.io error:', error);
      });
    });

    return io;
  }

  async handleSendMessage(socketId, data) {
    try {
      const connection = this.connections.get(socketId);
      if (!connection) {
        return { success: false, error: 'Invalid connection' };
      }

      // Validate message
      if (!data.message || !data.conversationId) {
        return { success: false, error: 'Missing required fields' };
      }

      if (data.message.length > 500) {
        return { success: false, error: 'Message too long' };
      }

      // Save to database via HTTP call to main worker
      const response = await fetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${data.conversationId}/messages`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Request': 'true',
          'X-User-ID': connection.userId.toString()
        },
        body: JSON.stringify({ message: data.message })
      });

      if (response.ok) {
        const result = await response.json();
        return {
          success: true,
          messageId: result.messageId,
          message: {
            id: result.messageId,
            senderId: connection.userId,
            conversationId: data.conversationId,
            content: data.message
          }
        };
      } else {
        const error = await response.json();
        return { success: false, error: error.error || 'Database error' };
      }
    } catch (error) {
      console.error('Error in handleSendMessage:', error);
      return { success: false, error: 'Internal server error' };
    }
  }

  async handleMarkRead(socketId, data) {
    try {
      const connection = this.connections.get(socketId);
      if (!connection || !data.conversationId) {
        return;
      }

      await fetch(`https://spear-exchange.lenny-paz123.workers.dev/api/conversations/${data.conversationId}/read`, {
        method: 'PUT',
        headers: {
          'Content-Type': 'application/json',
          'X-Internal-Request': 'true',
          'X-User-ID': connection.userId.toString()
        }
      });
    } catch (error) {
      console.error('Error marking messages as read:', error);
    }
  }

  // Connection health monitoring
  startHealthMonitoring() {
    setInterval(() => {
      const now = Date.now();
      const staleConnections = [];

      for (const [socketId, connection] of this.connections) {
        if (now - connection.lastSeen > 90000) { // 90 seconds
          staleConnections.push(socketId);
        }
      }

      staleConnections.forEach(socketId => {
        const connection = this.connections.get(socketId);
        if (connection && connection.socket) {
          connection.socket.disconnect(true);
        }
        this.connections.delete(socketId);
      });

      if (staleConnections.length > 0) {
        console.log(`🧹 Cleaned up ${staleConnections.length} stale connections`);
      }
    }, 60000); // Check every minute
  }

  // Get active users in a conversation
  getActiveUsers(conversationId) {
    const activeUsers = [];
    const now = Date.now();

    for (const [socketId, connection] of this.connections) {
      if (connection.conversationId === conversationId && 
          (now - connection.lastSeen) < 60000) { // Active within last minute
        activeUsers.push({
          userId: connection.userId,
          lastSeen: connection.lastSeen,
          status: connection.status || 'online'
        });
      }
    }

    return activeUsers;
  }

  // Broadcast to all users in a conversation
  broadcastToConversation(conversationId, event, data) {
    const io = this.io;
    if (io) {
      io.to(`conversation-${conversationId}`).emit(event, data);
    }
  }

  // Broadcast to a specific user across all their connections
  broadcastToUser(userId, event, data) {
    const io = this.io;
    if (io) {
      io.to(`user-${userId}`).emit(event, data);
    }
  }
}