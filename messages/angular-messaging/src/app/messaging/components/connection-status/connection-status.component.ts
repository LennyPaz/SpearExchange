import { Component, Input } from '@angular/core';
import { ConnectionStatus } from '../../models/connection.model';

@Component({
  selector: 'app-connection-status',
  templateUrl: './connection-status.component.html',
  styleUrls: ['./connection-status.component.scss']
})
export class ConnectionStatusComponent {
  @Input() status: ConnectionStatus = 'offline';
  
  getStatusText(): string {
    switch (this.status) {
      case 'online': return 'Connected';
      case 'offline': return 'Offline';
      case 'connecting': return 'Connecting...';
      case 'reconnecting': return 'Reconnecting...';
      case 'poor': return 'Poor Connection';
      default: return 'Unknown';
    }
  }
  
  getStatusIcon(): string {
    switch (this.status) {
      case 'online': return 'fas fa-circle';
      case 'offline': return 'fas fa-exclamation-circle';
      case 'connecting': 
      case 'reconnecting': return 'fas fa-spinner fa-spin';
      case 'poor': return 'fas fa-exclamation-triangle';
      default: return 'fas fa-question-circle';
    }
  }
  
  getStatusClass(): string {
    return `connection-status ${this.status}`;
  }
}
