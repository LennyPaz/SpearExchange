import { NgModule } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormsModule } from '@angular/forms';

import { MessagingComponent } from './messaging.component';
import { ConversationsListComponent } from './components/conversations-list/conversations-list.component';
import { ChatHeaderComponent } from './components/chat-header/chat-header.component';
import { MessagesAreaComponent } from './components/messages-area/messages-area.component';
import { MessageInputComponent } from './components/message-input/message-input.component';
import { ConnectionStatusComponent } from './components/connection-status/connection-status.component';
import { TypingIndicatorComponent } from './components/typing-indicator/typing-indicator.component';
import { CrossConversationNotificationComponent } from './components/cross-conversation-notification/cross-conversation-notification.component';

import { SocketService } from './services/socket.service';
import { MessagingApiService } from './services/messaging-api.service';
import { AudioService } from './services/audio.service';
import { ConversationStateService } from './services/conversation-state.service';
import { MessageStateService } from './services/message-state.service';
import { ConnectionStateService } from './services/connection-state.service';

@NgModule({
  declarations: [
    MessagingComponent,
    ConversationsListComponent,
    ChatHeaderComponent,
    MessagesAreaComponent,
    MessageInputComponent,
    ConnectionStatusComponent,
    TypingIndicatorComponent,
    CrossConversationNotificationComponent
  ],
  imports: [
    CommonModule,
    FormsModule
  ],
  providers: [
    SocketService,
    MessagingApiService,
    AudioService,
    ConversationStateService,
    MessageStateService,
    ConnectionStateService
  ],
  exports: [
    MessagingComponent
  ]
})
export class MessagingModule { }
