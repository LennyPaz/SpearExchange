import { Component, OnInit, OnDestroy } from '@angular/core';
import { Router } from '@angular/router';
import { Subscription } from 'rxjs';
import { SocketService } from './services/socket.service';
import { MessagingApiService } from './services/messaging-api.service';
import { ConversationStateService } from './services/conversation-state.service';
import { MessageStateService } from './services/message-state.service';
import { ConnectionStateService } from './services/connection-state.service';
import { AudioService } from './services/audio.service';
import { Conversation, ConversationUpdate } from './models/conversation.model';
import { Message } from './models/message.model';
import { ConnectionStatus } from './models/connection.model';

@Component({
  selector: 'app-messaging',
  templateUrl: './messaging.component.html',
  styleUrls: ['./messaging.component.scss']
})
export class MessagingComponent implements OnInit, OnDestroy {
  // State
  conversations: Conversation[] = [];
  selectedConversation?: Conversation;
  messages: Message[] = [];
  currentUserId?: number;
  currentUserName?: string;
  connectionStatus: ConnectionStatus = 'offline';
  searchQuery = '';
  isLoading = false;
  isLoadingMessages = false;
  error?: string;
  isMobile = false;
  showMobileChat = false;
  
  // Mobile menu state
  showUserDropdown = false;
  showMobileMenu = false;
  
  // Typing state
  typingUsers = new Set<number>();
  typingTimeout?: any;
  
  // Subscriptions
  private subscriptions = new Subscription();
  
  constructor(
    private socketService: SocketService,
    private apiService: MessagingApiService,
    private conversationState: ConversationStateService,
    private messageState: MessageStateService,
    private connectionState: ConnectionStateService,
    private audioService: AudioService,
    private router: Router
  ) {}
  
  ngOnInit(): void {
    this.checkMobile();
    this.initializeUser();
    this.setupEventListeners();
    this.setupSocketListeners();
    this.setupStateSubscriptions();
    
    // Setup window resize listener
    window.addEventListener('resize', () => this.checkMobile());
  }
  
  ngOnDestroy(): void {
    this.subscriptions.unsubscribe();
    this.socketService.disconnect();
    window.removeEventListener('resize', () => this.checkMobile());
    if (this.typingTimeout) {
      clearTimeout(this.typingTimeout);
    }
  }
  
  private checkMobile(): void {
    this.isMobile = window.innerWidth <= 800;
    if (!this.isMobile) {
      this.showMobileMenu = false;
    }
  }
  
  private async initializeUser(): Promise<void> {
    console.log('🔐 Initializing user authentication...');
    
    try {
      const user = await this.apiService.getCurrentUser().toPromise();
      console.log('👤 User response:', user);
      
      if (user) {
        this.currentUserId = user.id;
        this.currentUserName = user.name;
        console.log('✅ User authenticated:', { id: user.id, name: user.name });
        
        // Store authentication status
        localStorage.setItem('authenticated', 'true');
        
        // Connect to Socket.io with user info
        this.socketService.connect(user.id, user.name);
        
        // Load conversations after authentication
        await this.loadConversations();
      } else {
        console.warn('⚠️ No user data received');
        this.handleAuthenticationFailure();
      }
    } catch (error: any) {
      console.error('❌ Failed to initialize user:', error);
      
      // Check if it's an authentication error
      if (error.status === 401 || error.message?.includes('401')) {
        this.handleAuthenticationFailure();
      } else {
        // Network or other error - show retry button
        this.error = 'Failed to connect. Please check your connection and try again.';
        this.isLoading = false;
      }
    }
  }
  
  private handleAuthenticationFailure(): void {
    // Clear any stored auth data
    localStorage.removeItem('authenticated');
    localStorage.removeItem('sessionToken');
    localStorage.removeItem('user');
    
    this.error = 'Please log in to continue';
    this.isLoading = false;
    
    // Immediate redirect for authentication failures
    window.location.href = '/login';
  }
  
  async loadConversations(): Promise<void> {
    this.isLoading = true;
    this.error = undefined;
    
    console.log('🔄 Loading conversations...');
    
    try {
      const conversations = await this.apiService.getConversations().toPromise();
      console.log('📦 Conversations response:', conversations);
      
      if (conversations) {
        this.conversations = conversations;
        this.conversationState.setConversations(conversations);
        
        // Auto-select first conversation if none selected
        if (conversations.length > 0 && !this.selectedConversation) {
          console.log('🎯 Auto-selecting first conversation');
          this.selectConversation(conversations[0]);
        } else {
          console.log('📭 No conversations to display');
        }
      }
    } catch (error) {
      console.error('❌ Failed to load conversations:', error);
      this.error = 'Failed to load conversations. Please try again.';
    } finally {
      this.isLoading = false;
    }
  }
  
  private setupEventListeners(): void {
    // Close dropdowns when clicking outside
    document.addEventListener('click', (event) => {
      const target = event.target as HTMLElement;
      if (!target.closest('.user-menu')) {
        this.showUserDropdown = false;
      }
      if (!target.closest('.mobile-sidebar') && !target.closest('.mobile-menu-btn')) {
        this.showMobileMenu = false;
      }
    });
  }
  
  private setupSocketListeners(): void {
    // Connection status
    this.subscriptions.add(
      this.socketService.onConnect().subscribe(() => {
        this.connectionStatus = 'online';
        this.connectionState.setStatus('online');
        
        // Join global room for cross-conversation notifications
        this.socketService.emit('join_global', {
          userId: this.currentUserId,
          userName: this.currentUserName
        });
      })
    );
    
    this.subscriptions.add(
      this.socketService.onDisconnect().subscribe(() => {
        this.connectionStatus = 'offline';
        this.connectionState.setStatus('offline');
      })
    );
    
    // Message events
    this.subscriptions.add(
      this.socketService.onMessage().subscribe((message: Message) => {
        this.handleNewMessage(message);
      })
    );
    
    // Typing events
    this.subscriptions.add(
      this.socketService.onTypingStart().subscribe((data: any) => {
        if (data.userId !== this.currentUserId && data.conversationId === this.selectedConversation?.id) {
          this.typingUsers.add(data.userId);
        }
      })
    );
    
    this.subscriptions.add(
      this.socketService.onTypingStop().subscribe((data: any) => {
        if (data.conversationId === this.selectedConversation?.id) {
          this.typingUsers.delete(data.userId);
        }
      })
    );
    
    // Cross-conversation notifications
    this.subscriptions.add(
      this.socketService.onConversationUpdate().subscribe((update: ConversationUpdate) => {
        this.handleConversationUpdate(update);
      })
    );
  }
  
  private setupStateSubscriptions(): void {
    // Subscribe to conversation state changes
    this.subscriptions.add(
      this.conversationState.conversations$.subscribe(conversations => {
        this.conversations = conversations;
      })
    );
    
    // Subscribe to message state changes
    this.subscriptions.add(
      this.messageState.messages$.subscribe(messages => {
        this.messages = messages;
      })
    );
    
    // Subscribe to connection state changes
    this.subscriptions.add(
      this.connectionState.status$.subscribe(status => {
        this.connectionStatus = status;
      })
    );
  }
  
  async selectConversation(conversation: Conversation): Promise<void> {
    if (this.selectedConversation?.id === conversation.id) return;
    
    // Leave previous conversation room
    if (this.selectedConversation) {
      this.socketService.emit('leave_conversation', {
        conversationId: this.selectedConversation.id
      });
    }
    
    this.selectedConversation = conversation;
    this.conversationState.selectConversation(conversation);
    this.isLoadingMessages = true;
    this.typingUsers.clear();
    
    // Join new conversation room
    this.socketService.emit('join_conversation', {
      conversationId: conversation.id,
      userId: this.currentUserId,
      userName: this.currentUserName
    });
    
    try {
      // Load messages
      const messages = await this.apiService.getMessages(conversation.id).toPromise();
      if (messages) {
        this.messages = messages;
        this.messageState.setMessages(messages);
        
        // Mark as read
        await this.apiService.markAsRead(conversation.id).toPromise();
        
        // Update unread count locally
        this.updateConversation({
          id: conversation.id,
          unread_count: 0
        });
        
        // Scroll to bottom after messages load
        setTimeout(() => this.scrollToBottom(), 100);
      }
    } catch (error) {
      console.error('Failed to load messages:', error);
      this.error = 'Failed to load messages. Please try again.';
    } finally {
      this.isLoadingMessages = false;
    }
    
    // Show mobile chat view if on mobile
    if (this.isMobile) {
      this.showMobileChat = true;
    }
  }
  
  async sendMessage(content: string): Promise<void> {
    if (!content.trim() || !this.selectedConversation) return;
    
    const tempMessage: Message = {
      id: Date.now(),
      sender_id: this.currentUserId!,
      sender_name: this.currentUserName!,
      message: content,
      created_at: new Date().toISOString(),
      status: 'sending',
      conversation_id: this.selectedConversation.id
    };
    
    // Add message optimistically
    this.messages.push(tempMessage);
    this.messageState.addMessage(tempMessage);
    this.scrollToBottom();
    
    try {
      // Send via Socket.io
      this.socketService.emit('send_message', {
        conversationId: this.selectedConversation.id,
        content: content,
        userId: this.currentUserId,
        userName: this.currentUserName
      });
      
      // Also send via HTTP as backup
      const sentMessage = await this.apiService.sendMessage(
        this.selectedConversation.id,
        content
      ).toPromise();
      
      if (sentMessage) {
        // Update temp message with real data
        const index = this.messages.findIndex(m => m.id === tempMessage.id);
        if (index !== -1) {
          this.messages[index] = { ...sentMessage, status: 'sent' };
          this.messageState.updateMessage(sentMessage);
        }
        
        // Update conversation preview
        this.updateConversation({
          id: this.selectedConversation.id,
          last_message_preview: content,
          last_message_at: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Failed to send message:', error);
      
      // Mark message as failed
      const index = this.messages.findIndex(m => m.id === tempMessage.id);
      if (index !== -1) {
        this.messages[index].status = 'failed';
      }
    }
  }
  
  handleTypingStart(): void {
    if (!this.selectedConversation) return;
    
    // Clear existing timeout
    if (this.typingTimeout) {
      clearTimeout(this.typingTimeout);
    }
    
    // Emit typing start
    this.socketService.emit('typing_start', {
      conversationId: this.selectedConversation.id,
      userId: this.currentUserId,
      userName: this.currentUserName
    });
    
    // Auto-stop typing after 3 seconds
    this.typingTimeout = setTimeout(() => {
      this.handleTypingStop();
    }, 3000);
  }
  
  handleTypingStop(): void {
    if (!this.selectedConversation) return;
    
    if (this.typingTimeout) {
      clearTimeout(this.typingTimeout);
      this.typingTimeout = null;
    }
    
    this.socketService.emit('typing_stop', {
      conversationId: this.selectedConversation.id,
      userId: this.currentUserId
    });
  }
  
  private handleNewMessage(message: Message): void {
    // Check if message is for current conversation
    if (message.conversation_id === this.selectedConversation?.id) {
      // Add to messages if not already there (avoid duplicates)
      if (!this.messages.find(m => m.id === message.id)) {
        this.messages.push(message);
        this.messageState.addMessage(message);
        this.scrollToBottom();
        
        // Play sound for received messages
        if (message.sender_id !== this.currentUserId) {
          this.audioService.playNotificationSound();
        }
      }
    } else {
      // Show cross-conversation notification
      this.showCrossConversationNotification(message);
    }
    
    // Update conversation in list
    const conversationId = message.conversation_id || this.getConversationIdForMessage(message);
    if (conversationId) {
      this.updateConversation({
        id: conversationId,
        last_message_preview: message.message,
        last_message_at: message.created_at,
        unread_count: conversationId !== this.selectedConversation?.id ? 1 : 0
      });
    }
  }
  
  private handleConversationUpdate(update: ConversationUpdate): void {
    this.updateConversation(update);
  }
  
  private updateConversation(update: ConversationUpdate): void {
    const index = this.conversations.findIndex(c => c.id === update.id);
    if (index !== -1) {
      this.conversations[index] = {
        ...this.conversations[index],
        ...update
      };
      
      // Move to top if there's a new message
      if (update.last_message_at) {
        const conversation = this.conversations.splice(index, 1)[0];
        this.conversations.unshift(conversation);
      }
      
      this.conversationState.updateConversation(update);
    }
  }
  
  private showCrossConversationNotification(message: Message): void {
    // Find conversation for notification
    const conversation = this.conversations.find(c => 
      c.id === message.conversation_id || 
      this.getConversationIdForMessage(message) === c.id
    );
    
    if (conversation) {
      // Emit notification event that the notification component will handle
      this.conversationState.showNotification({
        conversationId: conversation.id,
        listingTitle: conversation.listing.title,
        senderName: message.sender_name,
        message: message.message,
        timestamp: message.created_at
      });
      
      // Play notification sound
      this.audioService.playNotificationSound();
    }
  }
  
  private getConversationIdForMessage(message: Message): number | undefined {
    // Try to find conversation based on sender
    const conversation = this.conversations.find(c => 
      c.other_user.id === message.sender_id
    );
    return conversation?.id;
  }
  
  private scrollToBottom(smooth = false): void {
    // Implementation handled by messages-area component
  }
  
  onBackToConversations(): void {
    this.showMobileChat = false;
    this.selectedConversation = undefined;
  }
  
  onSearchChange(query: string): void {
    this.searchQuery = query;
    // Filter conversations based on search
    if (query) {
      const filtered = this.conversations.filter(c => 
        c.listing.title.toLowerCase().includes(query.toLowerCase()) ||
        c.other_user.name.toLowerCase().includes(query.toLowerCase()) ||
        c.last_message_preview?.toLowerCase().includes(query.toLowerCase())
      );
      this.conversationState.setConversations(filtered);
    } else {
      // Reload all conversations
      this.loadConversations();
    }
  }
  
  // Mobile menu methods
  toggleUserDropdown(): void {
    this.showUserDropdown = !this.showUserDropdown;
  }
  
  toggleMobileMenu(): void {
    this.showMobileMenu = !this.showMobileMenu;
  }
  
  closeMobileMenu(): void {
    this.showMobileMenu = false;
  }
  
  async logout(): Promise<void> {
    try {
      await this.apiService.logout().toPromise();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      window.location.href = '/login';
    }
  }
  
  async retryAuthentication(): Promise<void> {
    this.error = undefined;
    this.isLoading = true;
    await this.initializeUser();
  }
  
  async retryConnection(): Promise<void> {
    this.error = undefined;
    this.isLoading = true;
    
    // Try to reconnect socket first
    if (this.currentUserId && this.currentUserName) {
      this.socketService.connect(this.currentUserId, this.currentUserName);
    }
    
    // Then reload conversations
    await this.loadConversations();
  }
}
