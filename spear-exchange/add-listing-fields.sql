-- Add new fields to listings table
ALTER TABLE listings ADD COLUMN condition TEXT;
ALTER TABLE listings ADD COLUMN negotiable INTEGER DEFAULT 0;
ALTER TABLE listings ADD COLUMN contact_method TEXT;
ALTER TABLE listings ADD COLUMN phone_number TEXT;

-- Update existing listings with default values if needed
UPDATE listings SET condition = 'Good' WHERE condition IS NULL;
UPDATE listings SET negotiable = 0 WHERE negotiable IS NULL;
UPDATE listings SET contact_method = 'email' WHERE contact_method IS NULL;
UPDATE listings SET phone_number = '' WHERE phone_number IS NULL;
