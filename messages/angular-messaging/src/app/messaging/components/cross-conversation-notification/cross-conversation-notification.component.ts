import { Component, OnInit, OnDestroy } from '@angular/core';
import { Subscription } from 'rxjs';
import { ConversationStateService } from '../../services/conversation-state.service';
import { AudioService } from '../../services/audio.service';
import { Router } from '@angular/router';

interface Notification {
  conversationId: number;
  listingTitle: string;
  senderName: string;
  message: string;
  timestamp: string;
  id: string;
}

@Component({
  selector: 'app-cross-conversation-notification',
  templateUrl: './cross-conversation-notification.component.html',
  styleUrls: ['./cross-conversation-notification.component.scss']
})
export class CrossConversationNotificationComponent implements OnInit, OnDestroy {
  notifications: Notification[] = [];
  private subscription?: Subscription;
  private timeouts: Map<string, any> = new Map();
  
  constructor(
    private conversationState: ConversationStateService,
    private audioService: AudioService,
    private router: Router
  ) {}
  
  ngOnInit(): void {
    this.subscription = this.conversationState.notifications$.subscribe(notification => {
      this.showNotification(notification);
    });
  }
  
  ngOnDestroy(): void {
    this.subscription?.unsubscribe();
    // Clear all timeouts
    this.timeouts.forEach(timeout => clearTimeout(timeout));
    this.timeouts.clear();
  }
  
  private showNotification(data: any): void {
    const notification: Notification = {
      ...data,
      id: `notification-${Date.now()}-${Math.random()}`
    };
    
    // Add notification to array
    this.notifications.push(notification);
    
    // Play sound
    this.audioService.playNotificationSound();
    
    // Auto-remove after 8 seconds
    const timeout = setTimeout(() => {
      this.removeNotification(notification.id);
    }, 8000);
    
    this.timeouts.set(notification.id, timeout);
  }
  
  removeNotification(id: string): void {
    const index = this.notifications.findIndex(n => n.id === id);
    if (index !== -1) {
      this.notifications.splice(index, 1);
    }
    
    // Clear timeout if exists
    const timeout = this.timeouts.get(id);
    if (timeout) {
      clearTimeout(timeout);
      this.timeouts.delete(id);
    }
  }
  
  openConversation(notification: Notification): void {
    // Select the conversation
    const conversation = this.conversationState.getConversations()
      .find(c => c.id === notification.conversationId);
    
    if (conversation) {
      this.conversationState.selectConversation(conversation);
    }
    
    // Remove notification
    this.removeNotification(notification.id);
  }
  
  truncateMessage(message: string, maxLength: number = 60): string {
    if (message.length <= maxLength) return message;
    return message.substring(0, maxLength) + '...';
  }
}
