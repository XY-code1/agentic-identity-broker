-- user_grants was created with TIMESTAMP columns while every other lifecycle table uses
-- TIMESTAMPTZ. A TIMESTAMP parameter drops the zone of a non-UTC value, so a grant expiry
-- chosen as 18:00+02:00 was stored as 18:00 and expired two hours late. Existing values were
-- written in UTC by the application and are reinterpreted as UTC.
ALTER TABLE user_grants
    ALTER COLUMN valid_until TYPE TIMESTAMPTZ USING valid_until AT TIME ZONE 'UTC',
    ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC',
    ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
