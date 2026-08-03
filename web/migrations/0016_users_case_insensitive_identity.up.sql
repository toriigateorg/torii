-- Signin folds case (lower(username) = lower($1) OR lower(email) = lower($1))
-- but uniqueness was enforced on the raw columns, and the lower() indexes were
-- not unique. So 'Admin' and 'admin' could both exist and both satisfy the
-- signin predicate, with no ORDER BY to say which one won. That meant denial of
-- password signin by username, failed-login counters and 15-minute lockouts
-- landing on the wrong account, audit events attributed to the wrong principal,
-- and — because torii asserts X-Torii-Username to upstreams as authoritative
-- identity, and most apps resolve usernames case-insensitively — an
-- attacker-registered 'Admin' mapping onto an upstream's real 'admin'.
--
-- Canonicalize to lowercase and enforce the invariant in the schema, so it does
-- not depend on every Go write path remembering to normalize.

-- Pre-flight. Folding case is destructive if two accounts collide, and only a
-- human can say which of them is legitimate, so refuse rather than guess. The
-- UPDATE below would trip the existing plain UNIQUE constraint anyway; this runs
-- first purely so the operator gets the offending rows instead of a bare
-- "duplicate key value violates unique constraint users_username_key".
--
-- golang-migrate sends this file as a single statement, so raising here rolls
-- back the whole migration and touches no data. It does leave schema_migrations
-- dirty at version 16 — clear that with `torii migrate force 15` once the
-- collisions are resolved, then re-run `torii migrate up`.
DO $$
DECLARE
    report text;
BEGIN
    SELECT string_agg(line, E'\n' ORDER BY line) INTO report
    FROM (
        SELECT format('  username %L is held by %s accounts: %s',
                      lower(username),
                      count(*),
                      string_agg(format('%L (id=%s, created=%s)',
                                        username, id, created_at),
                                 ', ' ORDER BY created_at)) AS line
        FROM users
        GROUP BY lower(username)
        HAVING count(*) > 1

        UNION ALL

        SELECT format('  email %L is held by %s accounts: %s',
                      lower(email),
                      count(*),
                      string_agg(format('%L (id=%s, created=%s)',
                                        email, id, created_at),
                                 ', ' ORDER BY created_at))
        FROM users
        GROUP BY lower(email)
        HAVING count(*) > 1
    ) collisions;

    IF report IS NOT NULL THEN
        RAISE EXCEPTION E'accounts collide when letter case is folded:\n%', report
            USING HINT = 'Rename or delete the impostor account, run `torii migrate force 15`, then re-run `torii migrate up`. The oldest row is usually the legitimate one; a newer duplicate of a privileged name is the signature of the attack this migration closes.';
    END IF;
END $$;

UPDATE users SET username = lower(username) WHERE username <> lower(username);
UPDATE users SET email    = lower(email)    WHERE email    <> lower(email);

DROP INDEX users_username_lower_idx;
DROP INDEX users_email_lower_idx;

CREATE UNIQUE INDEX users_username_lower_idx ON users (lower(username));
CREATE UNIQUE INDEX users_email_lower_idx    ON users (lower(email));

ALTER TABLE users
    ADD CONSTRAINT users_username_lowercase CHECK (username = lower(username)),
    ADD CONSTRAINT users_email_lowercase    CHECK (email    = lower(email));
