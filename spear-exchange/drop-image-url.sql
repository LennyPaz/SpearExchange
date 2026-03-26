-- Step 1: Rename the original table
ALTER TABLE listings RENAME TO listings_old;

-- Step 2: Create new table without image_url column
CREATE TABLE listings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER,
  title TEXT NOT NULL,
  description TEXT,
  price DECIMAL(10,2),
  category TEXT,
  image_urls TEXT,
  status TEXT DEFAULT 'active',
  location TEXT,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users (id)
);

-- Step 3: Copy data over (excluding the dropped column)
INSERT INTO listings (
  id, user_id, title, description, price, category, image_urls, status, location, created_at, updated_at
)
SELECT 
  id, user_id, title, description, price, category, image_urls, status, location, created_at, updated_at
FROM listings_old;

-- Step 4: Remove the old table
DROP TABLE listings_old;
