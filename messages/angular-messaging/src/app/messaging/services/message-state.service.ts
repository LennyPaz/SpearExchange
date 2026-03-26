import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { Message } from '../models/message.model';

@Injectable({
  providedIn: 'root'
})
export class MessageStateService {
  private messagesSubject = new BehaviorSubject<Message[]>([]);
  private typingUsersSubject = new BehaviorSubject<Map<number, string>>(new Map());
  
  // Observables
  messages$ = this.messagesSubject.asObservable();
  typingUsers$ = this.typingUsersSubject.asObservable();
  
  constructor() {}
  
  // Get current messages
  getMessages(): Message[] {
    return this.messagesSubject.value;
  }
  
  // Set messages
  setMessages(messages: Message[]): void {
    // Sort by created_at
    const sorted = [...messages].sort((a, b) => {
      return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
    });
    this.messagesSubject.next(sorted);
  }
  
  // Add message
  addMessage(message: Message): void {
    const current = this.messagesSubject.value;
    const exists = current.find(m => m.id === message.id);
    
    if (!exists) {
      const updated = [...current, message].sort((a, b) => {
        return new Date(a.created_at).getTime() - new Date(b.created_at).getTime();
      });
      this.messagesSubject.next(updated);
    }
  }
  
  // Update message
  updateMessage(message: Message): void {
    const messages = this.messagesSubject.value;
    const index = messages.findIndex(m => m.id === message.id);
    
    if (index !== -1) {
      const updated = [...messages];
      updated[index] = message;
      this.messagesSubject.next(updated);
    }
  }
  
  // Remove message
  removeMessage(messageId: number): void {
    const filtered = this.messagesSubject.value.filter(m => m.id !== messageId);
    this.messagesSubject.next(filtered);
  }
  
  // Update message status
  updateMessageStatus(messageId: number, status: 'sending' | 'sent' | 'failed'): void {
    const messages = this.messagesSubject.value;
    const message = messages.find(m => m.id === messageId);
    
    if (message) {
      this.updateMessage({ ...message, status });
    }
  }
  
  // Add typing user
  addTypingUser(userId: number, userName: string): void {
    const typingUsers = new Map(this.typingUsersSubject.value);
    typingUsers.set(userId, userName);
    this.typingUsersSubject.next(typingUsers);
  }
  
  // Remove typing user
  removeTypingUser(userId: number): void {
    const typingUsers = new Map(this.typingUsersSubject.value);
    typingUsers.delete(userId);
    this.typingUsersSubject.next(typingUsers);
  }
  
  // Clear typing users
  clearTypingUsers(): void {
    this.typingUsersSubject.next(new Map());
  }
  
  // Clear all messages
  clear(): void {
    this.messagesSubject.next([]);
    this.typingUsersSubject.next(new Map());
  }
}
