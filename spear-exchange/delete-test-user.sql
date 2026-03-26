-- Replace 3 with the actual user ID
DELETE FROM messages WHERE sender_id = 7 OR receiver_id = 7;
DELETE FROM favorites WHERE user_id = 7;
DELETE FROM listings WHERE user_id = 7;
DELETE FROM user_sessions WHERE user_id = 7;
DELETE FROM users WHERE id = 7;