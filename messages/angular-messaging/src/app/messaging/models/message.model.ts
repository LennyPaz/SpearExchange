// ===== MODELS/MESSAGE.MODEL.TS =====
export interface Message {
  id: number;
  sender_id: number;
  sender_name: string;
  message: string;
  created_at: string;
  conversation_id?: number;
  status?: 'sending' | 'sent' | 'failed' | 'delivered' | 'read';
}

export interface TypingIndicator {
  userId: number;
  userName: string;
  conversationId: number;
  timestamp: string;
}

export interface WebSocketMessage {
  type: 'new_message' | 'typing_start' | 'typing_stop' | 'user_joined' | 'user_left' | 'connection_established' | 'error' | 'ping' | 'pong' | 'messages_read';
  data?: any;
  messageId?: number;
  conversationId?: number;
  senderId?: number;
  senderName?: string;
  content?: string;
  timestamp?: string;
  userId?: number;
  userName?: string;
  message?: string;
  error?: string;
}
