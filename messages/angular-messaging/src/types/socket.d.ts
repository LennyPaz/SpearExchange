declare module 'socket.io-client' {
  export interface Socket {
    id: string;
    connected: boolean;
    disconnected: boolean;
    on(event: string, fn: Function): Socket;
    emit(event: string, ...args: any[]): Socket;
    connect(): Socket;
    disconnect(): Socket;
  }
  
  export function io(uri: string, opts?: any): Socket;
}
