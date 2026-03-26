-- Users table
CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    phone_number TEXT,
    profile_name TEXT,
    bio TEXT,
    is_verified INTEGER DEFAULT 0,
    verification_token TEXT,
    reset_token TEXT,
    reset_token_expires TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Listings table
CREATE TABLE listings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    price REAL NOT NULL,
    category TEXT NOT NULL,
    listing_type TEXT NOT NULL DEFAULT 'goods',
    price_period TEXT NOT NULL DEFAULT 'one_time',
    condition TEXT,
    negotiable INTEGER DEFAULT 0,
    contact_method TEXT,
    phone_number TEXT,
    image_urls TEXT,
    location TEXT,
    availability_start TEXT,
    availability_end TEXT,
    housing_type TEXT,
    bedrooms INTEGER,
    bathrooms REAL,
    furnished INTEGER DEFAULT 0,
    utilities_included INTEGER DEFAULT 0,
    parking_available INTEGER DEFAULT 0,
    pet_friendly INTEGER DEFAULT 0,
    roommates_allowed INTEGER DEFAULT 1,
    lease_transfer_fee REAL,
    address_text TEXT,
    sublease_notes TEXT,
    status TEXT DEFAULT 'active',
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- User sessions table
CREATE TABLE user_sessions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    expires_at DATETIME NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Conversations table (NEW)
CREATE TABLE conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    listing_id INTEGER NOT NULL,
    buyer_id INTEGER NOT NULL,
    seller_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_message_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_message_preview TEXT DEFAULT '',
    is_archived_buyer BOOLEAN DEFAULT 0,
    is_archived_seller BOOLEAN DEFAULT 0,
    FOREIGN KEY (listing_id) REFERENCES listings(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id),
    FOREIGN KEY (seller_id) REFERENCES users(id),
    UNIQUE(listing_id, buyer_id, seller_id)
);

-- Messages table (UPDATED)
CREATE TABLE messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    message TEXT NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    is_read BOOLEAN DEFAULT 0,
    message_type TEXT DEFAULT 'text',
    FOREIGN KEY (conversation_id) REFERENCES conversations(id),
    FOREIGN KEY (sender_id) REFERENCES users(id)
);

-- Favorites table
CREATE TABLE favorites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    listing_id INTEGER NOT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(user_id, listing_id),
    FOREIGN KEY (user_id) REFERENCES users (id),
    FOREIGN KEY (listing_id) REFERENCES listings (id)
);

-- Performance indexes for messaging system
CREATE INDEX idx_conversations_listing_buyer_seller ON conversations(listing_id, buyer_id, seller_id);
CREATE INDEX idx_conversations_buyer ON conversations(buyer_id);
CREATE INDEX idx_conversations_seller ON conversations(seller_id);
CREATE INDEX idx_messages_conversation ON messages(conversation_id);
CREATE INDEX idx_messages_created_at ON messages(created_at);
