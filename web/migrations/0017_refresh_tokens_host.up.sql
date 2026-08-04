-- Bind each refresh token to the host it was issued for.
--
-- torii's session cookies are host-only (no Domain attribute) and carry no cookie
-- name prefix, so per RFC 6265bis a script on a sibling host under the same
-- registrable domain can write a same-named cookie carrying Domain=example.com:
-- that is a different storage key, HttpOnly does not protect it, and the write is
-- accepted. Because refresh_tokens keyed on the hash alone, a token the attacker
-- minted for themselves on host B — readable straight out of Set-Cookie by a
-- non-browser client — could then be planted in a victim's jar and redeemed on B,
-- issuing the victim a session as the attacker.
--
-- The __Host- cookie prefix (see internal/auth/cookies.go) stops the forgery in
-- the browser. This column stops the *replay* server-side, which is the half that
-- holds regardless of browser behaviour, and is why the refresh cookie can keep
-- its narrow Path=/_torii/api/v1/ scope (that path is incompatible with __Host-,
-- which mandates Path=/).
--
-- Existing rows get '' and can never match a real canonical host, so every live
-- session is invalidated by this migration and users sign in once more. That is
-- deliberate: an "unbound, therefore accept anywhere" state is exactly the
-- weakness being removed. No rows are deleted — they age out on their own
-- expires_at, and `torii tokens cleanup` will collect them sooner.
ALTER TABLE refresh_tokens ADD COLUMN host TEXT NOT NULL DEFAULT '';

-- Dropped so a future INSERT cannot silently omit the binding and land back in
-- the unbound state.
ALTER TABLE refresh_tokens ALTER COLUMN host DROP DEFAULT;
