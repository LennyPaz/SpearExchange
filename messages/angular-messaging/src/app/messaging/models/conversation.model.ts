// ===== MODELS/CONVERSATION.MODEL.TS =====
export interface Conversation {
  id: number;
  listing: {
    id: number;
    title: string;
    price: number;
    image_url?: string;
    status?: string;
  };
  other_user: {
    id: number;
    name: string;
    role: 'buyer' | 'seller';
  };
  last_message_preview: string;
  last_message_at: string;
  unread_count: number;
  created_at: string;
}

export interface ConversationUpdate {
  id: number;
  last_message_preview?: string;
  last_message_at?: string;
  unread_count?: number;
}