ALTER TABLE listings ADD COLUMN listing_type TEXT NOT NULL DEFAULT 'goods';
ALTER TABLE listings ADD COLUMN price_period TEXT NOT NULL DEFAULT 'one_time';
ALTER TABLE listings ADD COLUMN availability_start TEXT;
ALTER TABLE listings ADD COLUMN availability_end TEXT;
ALTER TABLE listings ADD COLUMN housing_type TEXT;
ALTER TABLE listings ADD COLUMN bedrooms INTEGER;
ALTER TABLE listings ADD COLUMN bathrooms REAL;
ALTER TABLE listings ADD COLUMN furnished INTEGER DEFAULT 0;
ALTER TABLE listings ADD COLUMN utilities_included INTEGER DEFAULT 0;
ALTER TABLE listings ADD COLUMN parking_available INTEGER DEFAULT 0;
ALTER TABLE listings ADD COLUMN pet_friendly INTEGER DEFAULT 0;
ALTER TABLE listings ADD COLUMN roommates_allowed INTEGER DEFAULT 1;
ALTER TABLE listings ADD COLUMN lease_transfer_fee REAL;
ALTER TABLE listings ADD COLUMN address_text TEXT;
ALTER TABLE listings ADD COLUMN sublease_notes TEXT;

UPDATE listings
SET
  listing_type = COALESCE(listing_type, 'goods'),
  price_period = COALESCE(price_period, 'one_time'),
  roommates_allowed = COALESCE(roommates_allowed, 1),
  furnished = COALESCE(furnished, 0),
  utilities_included = COALESCE(utilities_included, 0),
  parking_available = COALESCE(parking_available, 0),
  pet_friendly = COALESCE(pet_friendly, 0);
