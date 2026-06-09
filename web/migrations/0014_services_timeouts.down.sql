ALTER TABLE services
    DROP COLUMN read_timeout_secs,
    DROP COLUMN write_timeout_secs,
    DROP COLUMN dial_timeout_secs;
