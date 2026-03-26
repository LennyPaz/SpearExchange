# Quick Start Guide - Angular Messaging App

## Prerequisites
- Node.js 18+ installed
- npm or yarn package manager
- Cloudflare account (for Worker deployment)
- Git

## Installation

### 1. Install Angular Dependencies
```bash
cd messages/angular-messaging
npm install
```

### 2. Install Worker Dependencies
```bash
cd ../../spear-exchange/src
npm install
```

## Configuration

### 1. Update Angular Environment Files

**Development** (`src/environments/environment.ts`):
```typescript
export const environment = {
  production: false,
  apiUrl: 'http://localhost:8787',
  socketUrl: 'ws://localhost:8787'
};
```

**Production** (`src/environments/environment.prod.ts`):
```typescript
export const environment = {
  production: true,
  apiUrl: 'https://spear-exchange.lenny-paz123.workers.dev',
  socketUrl: 'wss://spear-exchange.lenny-paz123.workers.dev'
};
```

### 2. Configure Cloudflare Worker

Create `wrangler.toml` in `spear-exchange/src`:
```toml
name = "spear-exchange"
main = "worker.js"
compatibility_date = "2024-01-01"

[[d1_databases]]
binding = "DB"
database_name = "spear-exchange"
database_id = "your-database-id"

[[r2_buckets]]
binding = "IMAGES_BUCKET"
bucket_name = "spear-exchange-images"

[[durable_objects.bindings]]
name = "CHAT_ROOM"
class_name = "ChatRoom"
script_name = "spear-exchange"

[vars]
PRODUCTION_URL = "https://spear-exchange.lenny-paz123.workers.dev"
```

## Running Locally

### 1. Start the Angular Development Server
```bash
cd messages/angular-messaging
npm start
```
The app will be available at `http://localhost:4200`

### 2. Start the Cloudflare Worker (Local)
```bash
cd ../../spear-exchange/src
wrangler dev
```
The API will be available at `http://localhost:8787`

## Building for Production

### 1. Build Angular App
```bash
cd messages/angular-messaging
npm run build -- --configuration production
```

### 2. Deploy Worker to Cloudflare
```bash
cd ../../spear-exchange/src
wrangler deploy
```

## Testing

### Run Tests
```bash
cd messages/angular-messaging
chmod +x test-app.sh
./test-app.sh
```

### Manual Testing Checklist

#### Desktop (>800px):
1. Open app in Chrome/Firefox/Safari
2. Check navigation displays all links
3. Click user dropdown - should open/close
4. Select a conversation - messages should load
5. Send a message - should appear instantly
6. Open another browser/incognito - message should appear there too

#### Mobile (≤800px):
1. Open Chrome DevTools (F12)
2. Toggle device toolbar (Ctrl+Shift+M)
3. Select iPhone or Android device
4. Click hamburger menu - sidebar should slide in
5. Click outside - sidebar should close
6. Select conversation - should switch to chat view
7. Click back button - should return to conversations

#### Authentication:
1. Clear localStorage: `localStorage.clear()` in console
2. Refresh page - should redirect to login
3. Simulate network error: Go offline in DevTools
4. Should see "Try Again" button
5. Go back online and click - should reconnect

#### Socket.io:
1. Open browser console
2. Should see: "✅ Socket.io connected"
3. Send a message
4. Should see: "📤 Emitted send_message"
5. Receive a message
6. Should see: "📨 New message received"

## Troubleshooting

### Mobile Menu Not Working
```bash
# Clear Angular cache
rm -rf .angular/cache
npm start
```

### Socket.io Connection Failed
```javascript
// Check in browser console
console.log(io.sockets);
// Should show active sockets
```

### Authentication Issues
```javascript
// Clear all auth data
localStorage.clear();
document.cookie.split(";").forEach(c => {
  document.cookie = c.replace(/^ +/, "").replace(/=.*/, "=;expires=" + new Date().toUTCString() + ";path=/");
});
```

### SCSS Compilation Errors
```bash
# Rebuild styles
npm run build:styles
```

## Deployment URLs

- **Production App**: https://lennypaz.github.io/SpearExchange/messages/
- **API**: https://spear-exchange.lenny-paz123.workers.dev
- **WebSocket**: wss://spear-exchange.lenny-paz123.workers.dev/socket.io/

## Support

For issues, check:
1. Browser console for errors
2. Network tab for failed requests
3. Application tab for localStorage/cookies
4. Cloudflare dashboard for Worker logs

## Version Info
- Angular: 17.x
- Socket.io Client: 4.x
- Node.js: 18+
- TypeScript: 5.x

---

**Last Updated**: December 2024
**Status**: Production Ready
