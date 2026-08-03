-- Drops the invariant and restores the original non-unique lower() indexes.
-- The original mixed-case spellings are NOT recoverable: the up migration
-- rewrote them in place and kept no record of what they were.

ALTER TABLE users
    DROP CONSTRAINT IF EXISTS users_username_lowercase,
    DROP CONSTRAINT IF EXISTS users_email_lowercase;

DROP INDEX IF EXISTS users_username_lower_idx;
DROP INDEX IF EXISTS users_email_lower_idx;

CREATE INDEX users_email_lower_idx    ON users (lower(email));
CREATE INDEX users_username_lower_idx ON users (lower(username));
