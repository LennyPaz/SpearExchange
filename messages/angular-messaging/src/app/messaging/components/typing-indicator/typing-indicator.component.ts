import { Component, Input } from '@angular/core';
import { Conversation } from '../../models/conversation.model';

@Component({
  selector: 'app-typing-indicator',
  templateUrl: './typing-indicator.component.html',
  styleUrls: ['./typing-indicator.component.scss']
})
export class TypingIndicatorComponent {
  @Input() typingUsers = new Set<number>();
  @Input() conversations: Conversation[] = [];
  
  getTypingUserNames(): string[] {
    const names: string[] = [];
    
    this.typingUsers.forEach(userId => {
      const conversation = this.conversations.find(c => 
        c.other_user.id === userId
      );
      if (conversation) {
        names.push(conversation.other_user.name);
      }
    });
    
    return names;
  }
  
  getTypingText(): string {
    const names = this.getTypingUserNames();
    
    if (names.length === 0) return '';
    if (names.length === 1) return `${names[0]} is typing`;
    if (names.length === 2) return `${names[0]} and ${names[1]} are typing`;
    return `${names[0]} and ${names.length - 1} others are typing`;
  }
}
