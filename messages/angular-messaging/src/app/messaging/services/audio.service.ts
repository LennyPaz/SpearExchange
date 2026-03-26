import { Injectable } from '@angular/core';

@Injectable({
  providedIn: 'root'
})
export class AudioService {
  private audioContext?: AudioContext;
  private isInitialized = false;
  private notificationSound?: HTMLAudioElement;
  
  constructor() {
    this.initializeAudioContext();
    this.preloadSounds();
  }
  
  private initializeAudioContext(): void {
    // Initialize on first user interaction
    if (typeof window !== 'undefined') {
      const initAudio = () => {
        if (!this.isInitialized) {
          try {
            this.audioContext = new (window.AudioContext || (window as any).webkitAudioContext)();
            this.isInitialized = true;
            
            // Remove listeners after initialization
            document.removeEventListener('click', initAudio);
            document.removeEventListener('keydown', initAudio);
          } catch (error) {
            console.error('Failed to initialize audio context:', error);
          }
        }
      };
      
      // Wait for user interaction to initialize audio
      document.addEventListener('click', initAudio, { once: true });
      document.addEventListener('keydown', initAudio, { once: true });
    }
  }
  
  private preloadSounds(): void {
    // Create notification sound using Web Audio API
    if (typeof window !== 'undefined' && 'Audio' in window) {
      this.notificationSound = new Audio();
      this.notificationSound.volume = 0.5;
      
      // Create a data URL for a simple notification sound
      // This is a base64 encoded simple beep sound
      this.notificationSound.src = 'data:audio/wav;base64,UklGRiQAAABXQVZFZm10IBAAAAABAAEARKwAAIhYAQACABAAZGF0YQAAAAA=';
    }
  }
  
  playNotificationSound(): void {
    if (!this.isInitialized || !this.audioContext) {
      console.log('Audio not initialized, skipping notification sound');
      return;
    }
    
    try {
      // Use Web Audio API for better control
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      oscillator.frequency.value = 800; // Frequency in Hz
      oscillator.type = 'sine';
      
      // Envelope for smooth sound
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.3, this.audioContext.currentTime + 0.01);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.3);
      
      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + 0.3);
    } catch (error) {
      console.error('Failed to play notification sound:', error);
      
      // Fallback to HTML5 Audio
      if (this.notificationSound) {
        this.notificationSound.play().catch(e => {
          console.log('Failed to play fallback sound:', e);
        });
      }
    }
  }
  
  playTypingSound(): void {
    if (!this.isInitialized || !this.audioContext) return;
    
    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      oscillator.frequency.value = 600;
      oscillator.type = 'sine';
      
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.1, this.audioContext.currentTime + 0.005);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.05);
      
      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + 0.05);
    } catch (error) {
      console.error('Failed to play typing sound:', error);
    }
  }
  
  playSendSound(): void {
    if (!this.isInitialized || !this.audioContext) return;
    
    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      oscillator.frequency.value = 1000;
      oscillator.type = 'sine';
      
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.2, this.audioContext.currentTime + 0.01);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.15);
      
      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + 0.15);
    } catch (error) {
      console.error('Failed to play send sound:', error);
    }
  }
  
  playErrorSound(): void {
    if (!this.isInitialized || !this.audioContext) return;
    
    try {
      const oscillator = this.audioContext.createOscillator();
      const gainNode = this.audioContext.createGain();
      
      oscillator.connect(gainNode);
      gainNode.connect(this.audioContext.destination);
      
      oscillator.frequency.value = 300;
      oscillator.type = 'sawtooth';
      
      gainNode.gain.setValueAtTime(0, this.audioContext.currentTime);
      gainNode.gain.linearRampToValueAtTime(0.3, this.audioContext.currentTime + 0.01);
      gainNode.gain.exponentialRampToValueAtTime(0.01, this.audioContext.currentTime + 0.3);
      
      oscillator.start(this.audioContext.currentTime);
      oscillator.stop(this.audioContext.currentTime + 0.3);
    } catch (error) {
      console.error('Failed to play error sound:', error);
    }
  }
  
  setVolume(volume: number): void {
    if (this.notificationSound) {
      this.notificationSound.volume = Math.max(0, Math.min(1, volume));
    }
  }
  
  isMuted(): boolean {
    return this.notificationSound?.volume === 0;
  }
  
  mute(): void {
    this.setVolume(0);
  }
  
  unmute(): void {
    this.setVolume(0.5);
  }
}
