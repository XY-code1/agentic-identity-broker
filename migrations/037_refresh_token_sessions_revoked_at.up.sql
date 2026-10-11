-- Distinguish a rotated refresh token from a revoked one. A rotated token may be presented again
-- within the rotation grace period (lost-response retry); a revoked token never may.
ALTER TABLE refresh_token_sessions ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;
