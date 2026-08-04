-- Durable single-use ledger for cross-host handoff tokens.
--
-- The burn was a process-local map, which meant a token could be redeemed once
-- per replica inside its 30s window: torii answers both TORII_URL and every
-- service host, so one instance saw both the mint and the redemption, but nothing
-- shared that fact between instances. Redemption also has a browser correlator now
-- (HandoffClaims.Confirmation), so this is the second of two independent bounds
-- rather than the only one — but "single use" should mean single use.
--
-- jti is the primary key, so the burn is an INSERT ... ON CONFLICT DO NOTHING and
-- the winner is decided by Postgres rather than by read-then-write.
CREATE TABLE handoff_jtis (
    jti        TEXT        PRIMARY KEY,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Rows are only useful until the token they record expires (30s), so the sweeper
-- deletes on this column. Without it the table grows by one row per cross-host
-- login forever.
CREATE INDEX handoff_jtis_expires_at_idx ON handoff_jtis (expires_at);
