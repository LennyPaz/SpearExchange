import { Injectable } from '@angular/core';
import { BehaviorSubject, Observable } from 'rxjs';
import { ConnectionStatus } from '../models/connection.model';

@Injectable({
  providedIn: 'root'
})
export class ConnectionStateService {
  private statusSubject = new BehaviorSubject<ConnectionStatus>('offline');
  private reconnectAttemptsSubject = new BehaviorSubject<number>(0);
  private lastSeenSubject = new BehaviorSubject<Date | null>(null);
  
  // Observables
  status$ = this.statusSubject.asObservable();
  reconnectAttempts$ = this.reconnectAttemptsSubject.asObservable();
  lastSeen$ = this.lastSeenSubject.asObservable();
  
  constructor() {}
  
  // Get current status
  getStatus(): ConnectionStatus {
    return this.statusSubject.value;
  }
  
  // Set status
  setStatus(status: ConnectionStatus): void {
    this.statusSubject.next(status);
    
    if (status === 'online') {
      this.reconnectAttemptsSubject.next(0);
      this.lastSeenSubject.next(new Date());
    }
  }
  
  // Increment reconnect attempts
  incrementReconnectAttempts(): void {
    const current = this.reconnectAttemptsSubject.value;
    this.reconnectAttemptsSubject.next(current + 1);
  }
  
  // Reset reconnect attempts
  resetReconnectAttempts(): void {
    this.reconnectAttemptsSubject.next(0);
  }
  
  // Update last seen
  updateLastSeen(): void {
    this.lastSeenSubject.next(new Date());
  }
  
  // Check if connected
  isConnected(): boolean {
    return this.statusSubject.value === 'online';
  }
  
  // Get connection quality based on various factors
  getConnectionQuality(): 'excellent' | 'good' | 'poor' | 'offline' {
    const status = this.statusSubject.value;
    
    if (status === 'offline') return 'offline';
    if (status === 'poor') return 'poor';
    
    const reconnectAttempts = this.reconnectAttemptsSubject.value;
    if (reconnectAttempts === 0) return 'excellent';
    if (reconnectAttempts < 3) return 'good';
    return 'poor';
  }
}
