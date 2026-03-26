import { Component, Input, OnChanges, SimpleChanges, ViewChild, ElementRef, AfterViewChecked } from '@angular/core';
import { Message } from '../../models/message.model';

@Component({
  selector: 'app-messages-area',
  templateUrl: './messages-area.component.html',
  styleUrls: ['./messages-area.component.scss']
})
export class MessagesAreaComponent implements OnChanges, AfterViewChecked {
  @Input() messages: Message[] = [];
  @Input() currentUserId?: number;
  @Input() typingUsers = new Set<number>();
  
  @ViewChild('scrollContainer', { static: false }) private scrollContainer?: ElementRef;
  
  private shouldScrollToBottom = false;
  private lastMessageCount = 0;
  
  ngOnChanges(changes: SimpleChanges): void {
    if (changes['messages']) {
      const currentMessages = changes['messages'].currentValue;
      if (currentMessages && currentMessages.length > this.lastMessageCount) {
        this.shouldScrollToBottom = true;
        this.lastMessageCount = currentMessages.length;
      }
    }
  }
  
  ngAfterViewChecked(): void {
    if (this.shouldScrollToBottom) {
      this.scrollToBottom();
      this.shouldScrollToBottom = false;
    }
  }
  
  scrollToBottom(): void {
    try {
      if (this.scrollContainer?.nativeElement) {
        this.scrollContainer.nativeElement.scrollTop = this.scrollContainer.nativeElement.scrollHeight;
      }
    } catch(err) {
      console.error('Scroll to bottom error:', err);
    }
  }
  
  formatMessageTime(timestamp: string): string {
    const date = new Date(timestamp);
    return date.toLocaleTimeString('en-US', { 
      hour: 'numeric', 
      minute: '2-digit',
      hour12: true 
    });
  }
  
  formatMessageDate(timestamp: string): string {
    const date = new Date(timestamp);
    const today = new Date();
    const yesterday = new Date(today);
    yesterday.setDate(yesterday.getDate() - 1);
    
    if (date.toDateString() === today.toDateString()) {
      return 'Today';
    } else if (date.toDateString() === yesterday.toDateString()) {
      return 'Yesterday';
    } else {
      return date.toLocaleDateString('en-US', { 
        month: 'short', 
        day: 'numeric',
        year: date.getFullYear() !== today.getFullYear() ? 'numeric' : undefined
      });
    }
  }
  
  shouldShowDateSeparator(index: number): boolean {
    if (index === 0) return true;
    
    const currentMessage = this.messages[index];
    const previousMessage = this.messages[index - 1];
    
    const currentDate = new Date(currentMessage.created_at).toDateString();
    const previousDate = new Date(previousMessage.created_at).toDateString();
    
    return currentDate !== previousDate;
  }
  
  getMessageStatusIcon(status?: string): string {
    switch (status) {
      case 'sending': return 'fas fa-clock';
      case 'sent': return 'fas fa-check';
      case 'failed': return 'fas fa-exclamation-triangle';
      default: return '';
    }
  }
  
  getMessageStatusTooltip(status?: string): string {
    switch (status) {
      case 'sending': return 'Sending...';
      case 'sent': return 'Sent';
      case 'failed': return 'Failed to send';
      default: return '';
    }
  }
  
  trackByMessageId(index: number, message: Message): number {
    return message.id;
  }
}
