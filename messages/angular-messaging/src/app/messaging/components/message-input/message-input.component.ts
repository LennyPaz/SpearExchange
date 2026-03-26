import { Component, Output, EventEmitter, ViewChild, ElementRef, AfterViewInit } from '@angular/core';

@Component({
  selector: 'app-message-input',
  templateUrl: './message-input.component.html',
  styleUrls: ['./message-input.component.scss']
})
export class MessageInputComponent implements AfterViewInit {
  @Output() messageSent = new EventEmitter<string>();
  @Output() typingStart = new EventEmitter<void>();
  @Output() typingStop = new EventEmitter<void>();
  
  @ViewChild('messageInput') messageInputRef?: ElementRef<HTMLTextAreaElement>;
  
  messageText = '';
  private typingTimeout?: any;
  private isTyping = false;
  
  ngAfterViewInit(): void {
    // Auto-focus input
    this.messageInputRef?.nativeElement.focus();
  }
  
  onKeyPress(event: KeyboardEvent): void {
    // Send on Enter (without Shift)
    if (event.key === 'Enter' && !event.shiftKey) {
      event.preventDefault();
      this.sendMessage();
    }
  }
  
  onInput(): void {
    this.adjustTextareaHeight();
    this.handleTypingIndicator();
  }
  
  sendMessage(): void {
    const message = this.messageText.trim();
    if (!message) return;
    
    this.messageSent.emit(message);
    this.messageText = '';
    this.resetTextareaHeight();
    this.stopTyping();
    
    // Refocus input
    this.messageInputRef?.nativeElement.focus();
  }
  
  private handleTypingIndicator(): void {
    if (!this.isTyping && this.messageText.trim()) {
      this.isTyping = true;
      this.typingStart.emit();
    }
    
    // Clear existing timeout
    if (this.typingTimeout) {
      clearTimeout(this.typingTimeout);
    }
    
    // Set new timeout
    this.typingTimeout = setTimeout(() => {
      this.stopTyping();
    }, 2000);
  }
  
  private stopTyping(): void {
    if (this.isTyping) {
      this.isTyping = false;
      this.typingStop.emit();
    }
    
    if (this.typingTimeout) {
      clearTimeout(this.typingTimeout);
      this.typingTimeout = null;
    }
  }
  
  private adjustTextareaHeight(): void {
    const textarea = this.messageInputRef?.nativeElement;
    if (!textarea) return;
    
    // Reset height to auto to get the correct scrollHeight
    textarea.style.height = 'auto';
    
    // Set height based on scrollHeight, with max height
    const newHeight = Math.min(textarea.scrollHeight, 120);
    textarea.style.height = `${newHeight}px`;
  }
  
  private resetTextareaHeight(): void {
    const textarea = this.messageInputRef?.nativeElement;
    if (!textarea) return;
    
    textarea.style.height = '44px';
  }
  
  get isSendDisabled(): boolean {
    return !this.messageText.trim();
  }
}
