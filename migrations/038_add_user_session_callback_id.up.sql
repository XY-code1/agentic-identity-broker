SET lock_timeout = '5s';
ALTER TABLE user_sessions ADD COLUMN callback_id TEXT NOT NULL DEFAULT '';
RESET lock_timeout;
