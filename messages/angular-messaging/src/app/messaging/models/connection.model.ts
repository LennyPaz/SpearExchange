// ===== MODELS/CONNECTION.MODEL.TS =====
export type ConnectionStatus = 'online' | 'offline' | 'connecting' | 'reconnecting' | 'poor';

export interface ConnectionState {
  status: ConnectionStatus;
  lastConnected?: Date;
  reconnectAttempts: number;
  latency?: number;
}

export interface AudioSettings {
  notificationsEnabled: boolean;
  messageSound: boolean;
  typingSound: boolean;
  connectionSound: boolean;
  volume: number;
}
