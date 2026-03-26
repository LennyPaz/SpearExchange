import { Component, Input } from '@angular/core';
import { Conversation } from '../../models/conversation.model';

@Component({
  selector: 'app-chat-header',
  templateUrl: './chat-header.component.html',
  styleUrls: ['./chat-header.component.scss']
})
export class ChatHeaderComponent {
  @Input() conversation?: Conversation;
  @Input() otherUserRole?: string;
  
  getListingImage(): string | null {
    if (!this.conversation?.listing.image_url) return null;
    
    const imageUrl = this.conversation.listing.image_url;
    
    if (typeof imageUrl === 'string') {
      try {
        if (imageUrl.startsWith('http')) {
          return imageUrl;
        }
        const parsed = JSON.parse(imageUrl);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed[0];
        }
      } catch {
        return imageUrl;
      }
    }
    
    return null;
  }
  
  formatPrice(price: number): string {
    return `${price.toFixed(2)}`;
  }
  
  onImageError(event: Event): void {
    const img = event.target as HTMLImageElement | null;
    if (img) {
      img.style.display = 'none';
    }
  }
}
