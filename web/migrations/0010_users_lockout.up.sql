ALTER TABLE users
    ADD COLUMN failed_login_count INT         NOT NULL DEFAULT 0,
    ADD COLUMN locked_until       TIMESTAMPTZ NULL;
