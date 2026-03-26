import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable, Subject } from 'rxjs';
import { Conversation, ConversationUpdate } from '../models/conversation.model';

interface Notification {
  conversationId: number;
  listingTitle: string;
  senderName: string;
  message: string;
  timestamp: string;
}

@Injectable({
  providedIn: 'root'
})
export class ConversationStateService {
  private conversationsSubject = new BehaviorSubject<Conversation[]>([]);
  private selectedConversationSubject = new BehaviorSubject<Conversation | null>(null);
  private notificationSubject = new Subject<Notification>();
  
  // Observables
  conversations$ = this.conversationsSubject.asObservable();
  selectedConversation$ = this.selectedConversationSubject.asObservable();
  notifications$ = this.notificationSubject.asObservable();
  
  constructor() {}
  
  // Get current values
  getConversations(): Conversation[] {
    return this.conversationsSubject.value;
  }
  
  getSelectedConversation(): Conversation | null {
    return this.selectedConversationSubject.value;
  }
  
  // Set conversations
  setConversations(conversations: Conversation[]): void {
    // Sort by last message time
    const sorted = [...conversations].sort((a, b) => {
      const timeA = new Date(a.last_message_at || 0).getTime();
      const timeB = new Date(b.last_message_at || 0).getTime();
      return timeB - timeA;
    });
    this.conversationsSubject.next(sorted);
  }
  
  // Add conversation
  addConversation(conversation: Conversation): void {
    const current = this.conversationsSubject.value;
    const exists = current.find(c => c.id === conversation.id);
    
    if (!exists) {
      this.setConversations([conversation, ...current]);
    }
  }
  
  // Update conversation
  updateConversation(update: ConversationUpdate): void {
    const conversations = this.conversationsSubject.value;
    const index = conversations.findIndex(c => c.id === update.id);
    
    if (index !== -1) {
      const updated = { ...conversations[index], ...update };
      const newConversations = [...conversations];
      newConversations[index] = updated;
      
      // Re-sort if last message changed
      if (update.last_message_at) {
        newConversations.sort((a, b) => {
          const timeA = new Date(a.last_message_at || 0).getTime();
          const timeB = new Date(b.last_message_at || 0).getTime();
          return timeB - timeA;
        });
      }
      
      this.conversationsSubject.next(newConversations);
      
      // Update selected conversation if it's the one being updated
      if (this.selectedConversationSubject.value?.id === update.id) {
        this.selectedConversationSubject.next(updated);
      }
    }
  }
  
  // Remove conversation
  removeConversation(conversationId: number): void {
    const filtered = this.conversationsSubject.value.filter(c => c.id !== conversationId);
    this.conversationsSubject.next(filtered);
    
    // Clear selection if removed conversation was selected
    if (this.selectedConversationSubject.value?.id === conversationId) {
      this.selectedConversationSubject.next(null);
    }
  }
  
  // Select conversation
  selectConversation(conversation: Conversation | null): void {
    this.selectedConversationSubject.next(conversation);
    
    // Clear unread count when selecting
    if (conversation) {
      this.updateConversation({
        id: conversation.id,
        unread_count: 0
      });
    }
  }
  
  // Increment unread count
  incrementUnreadCount(conversationId: number): void {
    const conversation = this.conversationsSubject.value.find(c => c.id === conversationId);
    if (conversation && conversation.id !== this.selectedConversationSubject.value?.id) {
      this.updateConversation({
        id: conversationId,
        unread_count: (conversation.unread_count || 0) + 1
      });
    }
  }
  
  // Show notification
  showNotification(notification: Notification): void {
    this.notificationSubject.next(notification);
  }
  
  // Clear all data
  clear(): void {
    this.conversationsSubject.next([]);
    this.selectedConversationSubject.next(null);
  }
}
