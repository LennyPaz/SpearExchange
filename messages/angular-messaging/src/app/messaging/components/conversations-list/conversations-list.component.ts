import { Component, Input, Output, EventEmitter, OnInit, OnChanges, SimpleChanges } from '@angular/core';
import { Conversation } from '../../models/conversation.model';

@Component({
  selector: 'app-conversations-list',
  templateUrl: './conversations-list.component.html',
  styleUrls: ['./conversations-list.component.scss']
})
export class ConversationsListComponent implements OnInit, OnChanges {
  @Input() conversations: Conversation[] = [];
  @Input() selectedConversationId?: number;
  @Input() currentUserId?: number;
  @Output() conversationSelected = new EventEmitter<Conversation>();
  
  filteredConversations: Conversation[] = [];
  searchQuery = '';
  
  ngOnInit(): void {
    this.filteredConversations = this.conversations;
  }
  
  ngOnChanges(changes: SimpleChanges): void {
    if (changes['conversations']) {
      this.filteredConversations = this.conversations;
      this.applySearchFilter();
    }
  }
  
  onSearchChange(query: string): void {
    this.searchQuery = query;
    this.applySearchFilter();
  }
  
  private applySearchFilter(): void {
    if (!this.searchQuery.trim()) {
      this.filteredConversations = this.conversations;
      return;
    }
    
    const query = this.searchQuery.toLowerCase();
    this.filteredConversations = this.conversations.filter(conversation =>
      conversation.listing.title.toLowerCase().includes(query) ||
      conversation.other_user.name.toLowerCase().includes(query) ||
      conversation.last_message_preview?.toLowerCase().includes(query)
    );
  }
  
  selectConversation(conversation: Conversation): void {
    this.conversationSelected.emit(conversation);
  }
  
  formatTime(timestamp: string): string {
    if (!timestamp) return '';
    
    const date = new Date(timestamp);
    const now = new Date();
    const diffMs = now.getTime() - date.getTime();
    const diffMins = Math.floor(diffMs / 60000);
    const diffHours = Math.floor(diffMs / 3600000);
    const diffDays = Math.floor(diffMs / 86400000);
    
    if (diffMins < 1) return 'Just now';
    if (diffMins < 60) return `${diffMins}m ago`;
    if (diffHours < 24) return `${diffHours}h ago`;
    if (diffDays < 7) return `${diffDays}d ago`;
    
    // Format as date for older messages
    return date.toLocaleDateString('en-US', { 
      month: 'short', 
      day: 'numeric',
      year: date.getFullYear() !== now.getFullYear() ? 'numeric' : undefined
    });
  }
  
  getListingImage(conversation: Conversation): string | null {
    // Parse image URL if it's a JSON string
    if (conversation.listing.image_url) {
      if (typeof conversation.listing.image_url === 'string') {
        try {
          // Check if it's already a URL
          if (conversation.listing.image_url.startsWith('http')) {
            return conversation.listing.image_url;
          }
          // Try parsing as JSON
          const parsed = JSON.parse(conversation.listing.image_url);
          if (Array.isArray(parsed) && parsed.length > 0) {
            return parsed[0];
          }
        } catch {
          return conversation.listing.image_url;
        }
      }
    }
    return null;
  }
  
  trackByConversationId(index: number, conversation: Conversation): number {
    return conversation.id;
  }
  
  onImageError(event: Event): void {
    const img = event.target as HTMLImageElement | null;
    if (img) {
      img.style.display = 'none';
    }
  }
}
