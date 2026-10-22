SET lock_timeout = '5s';
ALTER TABLE user_sessions DROP COLUMN callback_id;
RESET lock_timeout;
