import { Injectable } from '@angular/core';
import { Observable, Subject } from 'rxjs';
import { io, Socket } from 'socket.io-client';
import { Message } from '../models/message.model';
import { ConversationUpdate } from '../models/conversation.model';

@Injectable({
  providedIn: 'root'
})
export class SocketService {
  private socket?: Socket;
  private readonly url = 'wss://spear-exchange.lenny-paz123.workers.dev';
  
  // Event subjects
  private connectionSubject = new Subject<boolean>();
  private messageSubject = new Subject<Message>();
  private typingStartSubject = new Subject<any>();
  private typingStopSubject = new Subject<any>();
  private conversationUpdateSubject = new Subject<ConversationUpdate>();
  private notificationSubject = new Subject<any>();
  private errorSubject = new Subject<string>();
  
  // Connection state
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;
  private reconnectDelay = 1000;
  private pingInterval?: any;
  
  constructor() {
    // Initialize connection on service creation
    this.setupBeforeUnloadHandler();
  }
  
  connect(userId: number, userName: string): void {
    if (this.socket?.connected) {
      console.log('Socket already connected');
      return;
    }
    
    console.log('🔌 Connecting to Socket.io server...');
    
    // Create socket connection with auth
    this.socket = io(this.url, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionAttempts: this.maxReconnectAttempts,
      reconnectionDelay: this.reconnectDelay,
      reconnectionDelayMax: 10000,
      timeout: 20000,
      auth: {
        userId,
        userName
      },
      query: {
        userId: userId.toString(),
        userName: encodeURIComponent(userName)
      }
    });
    
    this.setupEventListeners();
    this.startPingInterval();
  }
  
  private setupEventListeners(): void {
    if (!this.socket) return;
    
    // Connection events
    this.socket.on('connect', () => {
      console.log('✅ Socket.io connected');
      this.reconnectAttempts = 0;
      this.reconnectDelay = 1000;
      this.connectionSubject.next(true);
    });
    
    this.socket.on('disconnect', (reason: string) => {
      console.log('❌ Socket.io disconnected:', reason);
      this.connectionSubject.next(false);
      
      if (reason === 'io server disconnect') {
        // Server disconnected, manually reconnect
        this.socket?.connect();
      }
    });
    
    this.socket.on('connect_error', (error: Error) => {
      console.error('Socket connection error:', error);
      this.errorSubject.next('Connection failed. Retrying...');
      
      this.reconnectAttempts++;
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        this.errorSubject.next('Failed to connect after multiple attempts');
      }
    });
    
    // Message events
    this.socket.on('new_message', (data: any) => {
      console.log('📨 New message received:', data);
      const message: Message = {
        id: data.id || data.messageId,
        sender_id: data.senderId || data.sender_id,
        sender_name: data.senderName || data.sender_name,
        message: data.content || data.message,
        created_at: data.timestamp || data.created_at,
        conversation_id: data.conversationId || data.conversation_id,
        status: 'sent'
      };
      this.messageSubject.next(message);
    });
    
    // Typing events
    this.socket.on('typing_start', (data: any) => {
      console.log('⌨️ User started typing:', data);
      this.typingStartSubject.next(data);
    });
    
    this.socket.on('typing_stop', (data: any) => {
      console.log('⌨️ User stopped typing:', data);
      this.typingStopSubject.next(data);
    });
    
    // Conversation updates
    this.socket.on('conversation_updated', (data: ConversationUpdate) => {
      console.log('🔄 Conversation updated:', data);
      this.conversationUpdateSubject.next(data);
    });
    
    // Cross-conversation notifications
    this.socket.on('notification', (data: any) => {
      console.log('🔔 Notification received:', data);
      this.notificationSubject.next(data);
    });
    
    // User events
    this.socket.on('user_joined', (data: any) => {
      console.log('👤 User joined:', data);
    });
    
    this.socket.on('user_left', (data: any) => {
      console.log('👤 User left:', data);
    });
    
    // Ping/Pong for keeping connection alive
    this.socket.on('ping', () => {
      console.log('🏓 Ping received from server');
      this.socket?.emit('pong', { timestamp: new Date().toISOString() });
    });
    
    this.socket.on('pong', () => {
      console.log('🏓 Pong received from server');
    });
  }
  
  private startPingInterval(): void {
    // Clear existing interval
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
    }
    
    // Ping every 30 seconds to keep connection alive
    this.pingInterval = setInterval(() => {
      if (this.socket?.connected) {
        this.socket.emit('ping', { timestamp: new Date().toISOString() });
        console.log('🏓 Ping sent to server');
      }
    }, 30000);
  }
  
  private setupBeforeUnloadHandler(): void {
    window.addEventListener('beforeunload', () => {
      this.disconnect();
    });
  }
  
  // Emit events
  emit(event: string, data?: any): void {
    if (this.socket?.connected) {
      this.socket.emit(event, data);
      console.log(`📤 Emitted ${event}:`, data);
    } else {
      console.warn(`Cannot emit ${event}, socket not connected`);
      this.errorSubject.next('Not connected to server');
    }
  }
  
  // Send message via socket
  sendMessage(conversationId: number, content: string, userId: number, userName: string): void {
    this.emit('send_message', {
      conversationId,
      content,
      userId,
      userName,
      timestamp: new Date().toISOString()
    });
  }
  
  // Join conversation room
  joinConversation(conversationId: number, userId: number, userName: string): void {
    this.emit('join_conversation', {
      conversationId,
      userId,
      userName
    });
  }
  
  // Leave conversation room
  leaveConversation(conversationId: number): void {
    this.emit('leave_conversation', {
      conversationId
    });
  }
  
  // Typing indicators
  startTyping(conversationId: number, userId: number, userName: string): void {
    this.emit('typing_start', {
      conversationId,
      userId,
      userName
    });
  }
  
  stopTyping(conversationId: number, userId: number): void {
    this.emit('typing_stop', {
      conversationId,
      userId
    });
  }
  
  // Observable getters
  onConnect(): Observable<boolean> {
    return this.connectionSubject.asObservable();
  }
  
  onDisconnect(): Observable<boolean> {
    return this.connectionSubject.asObservable();
  }
  
  onMessage(): Observable<Message> {
    return this.messageSubject.asObservable();
  }
  
  onTypingStart(): Observable<any> {
    return this.typingStartSubject.asObservable();
  }
  
  onTypingStop(): Observable<any> {
    return this.typingStopSubject.asObservable();
  }
  
  onConversationUpdate(): Observable<ConversationUpdate> {
    return this.conversationUpdateSubject.asObservable();
  }
  
  onNotification(): Observable<any> {
    return this.notificationSubject.asObservable();
  }
  
  onError(): Observable<string> {
    return this.errorSubject.asObservable();
  }
  
  // Connection management
  disconnect(): void {
    if (this.pingInterval) {
      clearInterval(this.pingInterval);
      this.pingInterval = undefined;
    }
    
    if (this.socket) {
      this.socket.disconnect();
      this.socket = undefined;
      console.log('🔌 Socket disconnected');
    }
  }
  
  isConnected(): boolean {
    return this.socket?.connected || false;
  }
  
  reconnect(): void {
    if (!this.socket?.connected) {
      this.socket?.connect();
    }
  }
}
