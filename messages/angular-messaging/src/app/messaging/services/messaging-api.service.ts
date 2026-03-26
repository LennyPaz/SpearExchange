import { Injectable } from '@angular/core';
import { HttpClient, HttpHeaders } from '@angular/common/http';
import { Observable, of } from 'rxjs';
import { catchError, map } from 'rxjs/operators';
import { Conversation } from '../models/conversation.model';
import { Message } from '../models/message.model';

interface User {
  id: number;
  name: string;
  email: string;
}

@Injectable({
  providedIn: 'root'
})
export class MessagingApiService {
  private readonly baseUrl = 'https://spear-exchange.lenny-paz123.workers.dev/api';
  private currentUser?: User;
  
  constructor(private http: HttpClient) {
    this.loadUserFromStorage();
  }
  
  private loadUserFromStorage(): void {
    const storedUser = localStorage.getItem('user');
    if (storedUser) {
      try {
        this.currentUser = JSON.parse(storedUser);
      } catch (e) {
        console.error('Failed to parse stored user:', e);
      }
    }
  }
  
  private getHeaders(): HttpHeaders {
    let headers = new HttpHeaders({
      'Content-Type': 'application/json'
    });
    
    // Add session token if on mobile
    const sessionToken = localStorage.getItem('sessionToken');
    if (this.isMobile() && sessionToken) {
      headers = headers.set('Authorization', `Bearer ${sessionToken}`);
    }
    
    return headers;
  }
  
  private isMobile(): boolean {
    return /Android|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent);
  }
  
  // Authentication
  getCurrentUser(): Observable<User | null> {
    if (this.currentUser) {
      return of(this.currentUser);
    }
    
    return this.http.get<{ user: User }>(`${this.baseUrl}/me`, {
      headers: this.getHeaders(),
      withCredentials: true
    }).pipe(
      map(response => {
        this.currentUser = response.user;
        localStorage.setItem('user', JSON.stringify(response.user));
        return response.user;
      }),
      catchError(error => {
        console.error('Failed to get current user:', error);
        return of(null);
      })
    );
  }
  
  // Conversations
  getConversations(): Observable<Conversation[]> {
    return this.http.get<{ conversations: Conversation[] }>(`${this.baseUrl}/conversations`, {
      headers: this.getHeaders(),
      withCredentials: true
    }).pipe(
      map(response => {
        // Parse image URLs if they're JSON strings
        return response.conversations.map(conv => ({
          ...conv,
          listing: {
            ...conv.listing,
            image_url: this.parseImageUrl(conv.listing.image_url)
          }
        }));
      }),
      catchError(error => {
        console.error('Failed to load conversations:', error);
        return of([]);
      })
    );
  }
  
  getConversation(id: number): Observable<Conversation | null> {
    return this.http.get<Conversation>(`${this.baseUrl}/conversations/${id}`, {
      headers: this.getHeaders(),
      withCredentials: true
    }).pipe(
      map(conversation => ({
        ...conversation,
        listing: {
          ...conversation.listing,
          image_url: this.parseImageUrl(conversation.listing.image_url)
        }
      })),
      catchError(error => {
        console.error('Failed to load conversation:', error);
        return of(null);
      })
    );
  }
  
  // Messages
  getMessages(conversationId: number): Observable<Message[]> {
    return this.http.get<{ messages: Message[] }>(`${this.baseUrl}/conversations/${conversationId}/messages`, {
      headers: this.getHeaders(),
      withCredentials: true
    }).pipe(
      map(response => response.messages || []),
      catchError(error => {
        console.error('Failed to load messages:', error);
        return of([]);
      })
    );
  }
  
  sendMessage(conversationId: number, message: string): Observable<Message | null> {
    return this.http.post<{ message: Message; messageId: number }>(
      `${this.baseUrl}/conversations/${conversationId}/messages`,
      { message },
      {
        headers: this.getHeaders(),
        withCredentials: true
      }
    ).pipe(
      map(response => ({
        id: response.messageId,
        sender_id: this.currentUser?.id || 0,
        sender_name: this.currentUser?.name || 'Unknown',
        message: message,
        created_at: new Date().toISOString(),
        conversation_id: conversationId,
        status: 'sent' as const
      })),
      catchError(error => {
        console.error('Failed to send message:', error);
        return of(null);
      })
    );
  }
  
  markAsRead(conversationId: number): Observable<boolean> {
    return this.http.put(`${this.baseUrl}/conversations/${conversationId}/read`, {}, {
      headers: this.getHeaders(),
      withCredentials: true
    }).pipe(
      map(() => true),
      catchError(error => {
        console.error('Failed to mark as read:', error);
        return of(false);
      })
    );
  }
  
  // Create new conversation
  createConversation(listingId: number, message: string): Observable<Conversation | null> {
    return this.http.post<{ conversation: Conversation; conversationId: number }>(
      `${this.baseUrl}/conversations`,
      { listingId, message },
      {
        headers: this.getHeaders(),
        withCredentials: true
      }
    ).pipe(
      map(response => response.conversation),
      catchError(error => {
        console.error('Failed to create conversation:', error);
        return of(null);
      })
    );
  }
  
  // Helper method to parse image URLs
  private parseImageUrl(imageUrl: any): string | undefined {
    if (!imageUrl) return undefined;
    
    // If it's already a string URL, return it
    if (typeof imageUrl === 'string' && imageUrl.startsWith('http')) {
      return imageUrl;
    }
    
    // If it's a JSON string, parse it
    if (typeof imageUrl === 'string') {
      try {
        const parsed = JSON.parse(imageUrl);
        if (Array.isArray(parsed) && parsed.length > 0) {
          return parsed[0];
        }
        if (typeof parsed === 'string') {
          return parsed;
        }
      } catch (e) {
        // Not JSON, return as is
        return imageUrl;
      }
    }
    
    // If it's an array, return first element
    if (Array.isArray(imageUrl) && imageUrl.length > 0) {
      return imageUrl[0];
    }
    
    return undefined;
  }
  
  // Logout
  logout(): Observable<boolean> {
    return this.http.post(`${this.baseUrl}/logout`, {}, {
      headers: this.getHeaders(),
      withCredentials: true
    }).pipe(
      map(() => {
        localStorage.removeItem('user');
        localStorage.removeItem('sessionToken');
        this.currentUser = undefined;
        return true;
      }),
      catchError(error => {
        console.error('Logout failed:', error);
        localStorage.removeItem('user');
        localStorage.removeItem('sessionToken');
        this.currentUser = undefined;
        return of(true);
      })
    );
  }
}
