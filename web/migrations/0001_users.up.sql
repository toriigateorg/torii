CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id            UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    username      VARCHAR(64)  NOT NULL UNIQUE,
    email         VARCHAR(254) NOT NULL UNIQUE,
    first_name    VARCHAR(128) NOT NULL DEFAULT '',
    last_name     VARCHAR(128) NOT NULL DEFAULT '',
    password_hash TEXT         NOT NULL,
    user_type     VARCHAR(16)  NOT NULL DEFAULT 'user'
        CHECK (user_type IN ('admin', 'user')),
    created_at    TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at    TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX users_email_lower_idx    ON users (lower(email));
CREATE INDEX users_username_lower_idx ON users (lower(username));
