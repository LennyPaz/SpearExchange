# Angular Messaging Application

A real-time messaging application built with Angular 17 and Socket.io, designed for The Spear Exchange marketplace.

## Features

- ✅ **Real-time messaging** with Socket.io
- ✅ **Responsive design** - Works perfectly on desktop and mobile
- ✅ **Typing indicators** - See when others are typing
- ✅ **Read receipts** - Know when messages are read
- ✅ **Cross-conversation notifications** - Get notified of messages in other conversations
- ✅ **Connection status** - Real-time connection status indicator
- ✅ **Audio notifications** - Sound alerts for new messages
- ✅ **Message status** - Visual feedback for sending/sent/failed states
- ✅ **Search conversations** - Quickly find conversations
- ✅ **Auto-scrolling** - Automatic scroll to latest messages
- ✅ **Virtual scrolling** - Performance optimized for large message lists
- ✅ **Unread counts** - See unread message counts per conversation
- ✅ **Image support** - Display listing images in conversations

## Prerequisites

- Node.js (v18 or higher)
- npm (v9 or higher)
- Angular CLI (v17)

## Installation

1. **Install Angular CLI globally (if not already installed):**
   ```bash
   npm install -g @angular/cli@17
   ```

2. **Install project dependencies:**
   ```bash
   npm install
   ```

3. **Verify installation:**
   ```bash
   ng version
   ```

## Development Setup

1. **Start the development server:**
   ```bash
   npm start
   ```
   Or:
   ```bash
   ng serve --port 4200
   ```

2. **Open your browser and navigate to:**
   ```
   http://localhost:4200
   ```

## Building for Production

1. **Create a production build:**
   ```bash
   npm run build
   ```
   Or:
   ```bash
   ng build --configuration production
   ```

2. **The build artifacts will be stored in the `dist/` directory.**

## Testing

### Unit Tests
```bash
ng test
```

### E2E Tests
```bash
ng e2e
```

## Project Structure

```
src/
├── app/
│   ├── messaging/
│   │   ├── components/
│   │   │   ├── chat-header/
│   │   │   ├── connection-status/
│   │   │   ├── conversations-list/
│   │   │   ├── cross-conversation-notification/
│   │   │   ├── message-input/
│   │   │   ├── messages-area/
│   │   │   └── typing-indicator/
│   │   ├── models/
│   │   │   ├── connection.model.ts
│   │   │   ├── conversation.model.ts
│   │   │   └── message.model.ts
│   │   ├── services/
│   │   │   ├── audio.service.ts
│   │   │   ├── connection-state.service.ts
│   │   │   ├── conversation-state.service.ts
│   │   │   ├── message-state.service.ts
│   │   │   ├── messaging-api.service.ts
│   │   │   └── socket.service.ts
│   │   ├── messaging.component.ts
│   │   ├── messaging.component.html
│   │   ├── messaging.component.scss
│   │   └── messaging.module.ts
│   ├── app-routing.module.ts
│   ├── app.component.ts
│   ├── app.component.html
│   ├── app.component.scss
│   └── app.module.ts
├── styles/
│   └── _variables.scss
├── assets/
├── index.html
├── main.ts
└── styles.scss
```

## Key Technologies

- **Angular 17** - Frontend framework
- **Socket.io Client** - Real-time WebSocket communication
- **RxJS** - Reactive programming
- **TypeScript** - Type-safe JavaScript
- **SCSS** - Advanced CSS preprocessing
- **Font Awesome** - Icon library

## API Endpoints

The application connects to the following API endpoints:

- **Base URL:** `https://spear-exchange.lenny-paz123.workers.dev/api`
- **WebSocket URL:** `wss://spear-exchange.lenny-paz123.workers.dev`

### REST Endpoints:
- `GET /me` - Get current user
- `GET /conversations` - Get all conversations
- `GET /conversations/:id` - Get specific conversation
- `GET /conversations/:id/messages` - Get messages for conversation
- `POST /conversations/:id/messages` - Send a message
- `PUT /conversations/:id/read` - Mark messages as read

### Socket.io Events:
- `connect` - Connection established
- `disconnect` - Connection lost
- `new_message` - New message received
- `typing_start` - User started typing
- `typing_stop` - User stopped typing
- `conversation_updated` - Conversation metadata updated
- `notification` - Cross-conversation notification

## Configuration

### Environment Variables
Create a `.env` file in the root directory (optional):
```
API_URL=https://spear-exchange.lenny-paz123.workers.dev/api
SOCKET_URL=wss://spear-exchange.lenny-paz123.workers.dev
```

### Proxy Configuration (for local development)
If you need to proxy API calls during development, create `proxy.conf.json`:
```json
{
  "/api": {
    "target": "https://spear-exchange.lenny-paz123.workers.dev",
    "secure": true,
    "changeOrigin": true
  }
}
```

Then run with:
```bash
ng serve --proxy-config proxy.conf.json
```

## Performance Optimizations

1. **Virtual Scrolling** - Efficiently renders large lists
2. **OnPush Change Detection** - Optimized change detection strategy
3. **Lazy Loading** - Components loaded on demand
4. **Tree Shaking** - Unused code eliminated in production
5. **AOT Compilation** - Ahead-of-time compilation for faster rendering
6. **Service Workers** - Can be added for offline support

## Browser Support

- Chrome (latest)
- Firefox (latest)
- Safari (latest)
- Edge (latest)
- Mobile browsers (iOS Safari, Chrome Mobile)

## Troubleshooting

### Common Issues

1. **Port already in use:**
   ```bash
   ng serve --port 4201
   ```

2. **Clear cache and reinstall:**
   ```bash
   rm -rf node_modules package-lock.json
   npm cache clean --force
   npm install
   ```

3. **Socket connection issues:**
   - Check if WebSocket is blocked by firewall/proxy
   - Verify API server is running
   - Check browser console for CORS errors

4. **Build errors:**
   ```bash
   ng build --verbose
   ```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is proprietary and confidential.

## Support

For support, email support@spearexchange.com or open an issue in the repository.

## Deployment

### Deploy to Production

1. **Build the application:**
   ```bash
   ng build --configuration production
   ```

2. **Deploy the `dist/angular-messaging` folder to your hosting service.**

### Docker Deployment

```dockerfile
FROM node:18-alpine as build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist/angular-messaging /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## Additional Notes

- The application automatically handles authentication via cookies/tokens
- Messages are encrypted in transit using WSS (WebSocket Secure)
- The application includes automatic reconnection logic for network interruptions
- All timestamps are stored in UTC and converted to local time for display
