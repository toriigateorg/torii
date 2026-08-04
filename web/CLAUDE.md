# torii

Identity-aware reverse proxy with built-in auth and RBAC. Single Go binary in production: the Echo API server, golang-migrate, and the embedded Nuxt SPA all ship as one executable.

## House rules (read first, every session)

1. **Never run `go`, `bun`, `sqlc`, `docker`, or `docker compose` commands yourself.** Print the exact command and ask the user to run it. This includes `go get`, `go mod tidy`, `bun add`, `bun install`, `sqlc generate`, `docker compose up`, builds, etc. Same goes for migrations (`torii migrate ...`).
2. **No SSR.** Nuxt is configured with `ssr: false` and is treated as a static SPA. Every piece of dynamic data on every page is hydrated client-side by calling the Go API. Don't reach for `useFetch` server-side patterns, `serverMiddleware`, Nitro routes, or any Nuxt feature that runs on a Node server.
3. **API routes live under `/api/v1/`.** No exceptions.
4. **Admin routes are namespaced.** Backend: `/api/v1/admin/...`. Frontend: `/admin/...`. Both gates are enforced (server: `auth.RequireAdmin`; client: `middleware/admin.ts` throwing a 401 `createError`).
5. **UI is shadcn-vue + Tailwind v4, written in TypeScript.** Always reuse the components already vendored under `client/app/components/ui/` (Button, Card, Dialog, Table, DropdownMenu, Sheet, Input, Label, Alert, Badge, NativeSelect, Tabs, etc.). If a primitive isn't there yet, ask the user to add it via the shadcn-vue CLI rather than hand-rolling. All `<script>` blocks use `lang="ts"`.

---

## Stack

- **Backend**: Go 1.26 · Echo v5 (`github.com/labstack/echo/v5`) · pgx v5 + sqlc · golang-migrate · `urfave/cli/v3` for the CLI surface · `golang-jwt/v5` for access tokens · argon2id for password hashing.
- **Frontend**: Nuxt 4 (`ssr: false`) · Vue 3 · TypeScript · Tailwind v4 (`@tailwindcss/vite`) · shadcn-nuxt (component prefix is empty — use `Button`, not `UiButton`) · `@nuxtjs/color-mode` · `lucide-vue-next` for icons.
- **DB**: PostgreSQL 18.
- **Build/runtime**: dev runs the Go binary under `air` and spawns Nuxt as a child (`bun run dev` on `:3000`); echo reverse-proxies non-API traffic to it. Production embeds the generated SPA via `//go:embed` and serves it directly — no Node, no Nuxt, no `air`.

## Layout

```
server.go                    package main; godotenv + cli root
cmd/
  serve.go                   `torii serve` (with --migrate flag)
  migrate.go                 `torii migrate up|down`
internal/
  api/
    router.go                mounts /api/v1 group, auth + admin routes
    auth.go                  signup/signin/refresh/logout/me handlers
    admin_users.go           /api/v1/admin/users (list/create/delete)
    admin_tokens.go          /api/v1/admin/tokens (list/revoke/cleanup)
    pagination.go            shared ?page=&page_size= helper
  auth/
    jwt.go                   HS256 access tokens, Claims struct
    refresh.go               opaque random refresh tokens (sha256 hash stored)
    password.go              argon2id hash + strength validator
    cookies.go               access/refresh cookie helpers
    middleware.go            RequireUser + RequireAdmin
  config/config.go           env loader: APP_ENV, JWT_SECRET, *_EXPIRY_*
  db/
    pool.go                  pgxpool.Open (hand-written, NOT regenerated)
    db.go, models.go,        sqlc-generated — DO NOT edit by hand
    *.sql.go
    queries/                 sqlc input (.sql files)
  proxy/proxy.go             Nuxt reverse proxy (dev only)
  web/
    web.go                   //go:embed all:dist + SPA fallback handler
    dist/                    populated at build time; .gitkeep is the only
                             thing in version control
migrations/                  golang-migrate files: NNNN_name.{up,down}.sql
sqlc.yaml                    pgx/v5 + uuid override (timestamptz stays pgtype)
client/                      Nuxt 4 SPA
  nuxt.config.ts             ssr: false, shadcn-nuxt, color-mode
  app/
    app.vue
    layouts/default.vue      navbar (auth-aware) + footer
    pages/                   index, signin, signup, dashboard,
                             admin/model/{users,tokens}, health
    composables/
      useAuth.ts             accessToken (Vue ref), user, signin/up/out, refresh
      useAdminApi.ts         typed wrappers for /admin/* endpoints
    middleware/
      auth.ts                redirect to /signin if no session
      guest.ts               redirect to /dashboard if signed in
      admin.ts               throw 401 createError if not user_type=admin
    plugins/auth.client.ts   await useAuth().bootstrap() at app start
    components/
      ThemeToggle.vue
      admin/{AdminShell,PaginationBar}.vue
      ui/                    shadcn-vue primitives — reuse, don't duplicate
  error.vue                  styled error page (used for the admin 401)
Dockerfile                   prod: bun build SPA → embed → static Go binary
Dockerfile.dev               dev: golang + bun + air + sqlc, hot reload
docker-compose.yml           dev (bind-mounts source, runs air)
docker-compose.prod.yml      prod (bind-mounted ./audit-logs, healthcheck, APP_ENV=production)
```

## Auth model

- **Token types**: every JWT signed with `JWT_SECRET` carries a `typ` claim (`auth.TokenTypeAccess` / `auth.TokenTypeHandoff`) and each parser accepts only its own. The secret is shared across kinds, so without it a handoff token verified as an access token. Any new secret-signed token type must declare a `typ` and check it.
- **Access token**: HS256 JWT, 1 min default (`ACCESS_TOKEN_EXPIRY_MINS`). Permissions and roles are a snapshot taken at issuance, so a revoked role keeps working until the token expires — that lag is exactly this TTL, which is why it's short. Returned in JSON response body **and** as an httpOnly cookie. Client keeps it in a Vue `ref` (`useAuth().accessToken`) and sends it in the `X-Torii-Authorization` header (torii never reads the standard `Authorization` header — that is reserved for upstream services behind the proxy).
- **Host binding**: every access token carries an `aud` claim set to the canonical host it was issued for, and `ParseAccessToken` rejects a token whose `aud` isn't the host now serving the request. Sessions are established per host (`/signin`, `/signup`, `/sso_handoff`, `/token_refresh` all answer on proxied service hosts), so without the binding a token minted on an upstream's origin is a portable control-plane credential. For the same reason the token is echoed into the response body **only** on `TORII_URL` — on a service host the SPA has the cookie and `useAuth().accessToken` stays null (`isAuthed` keys off the user, not the token). Tokens minted before this claim existed fail closed and age out within one access TTL.
- **Refresh token**: 32 random bytes, base64url-encoded. Server stores only the sha256 hash in `refresh_tokens`. Delivered as an httpOnly + SameSite=Lax cookie, `Secure` only when `APP_ENV != "dev"`, at `Path=/` in prod (`__Host-` mandates it) and at `/_torii/api/v1/` in dev. **Host-bound**: `refresh_tokens.host` records the `config.CanonicalHost` the session was established on, and both refresh paths reject a mismatch. One token used to mint sessions on any host, which is what made a planted cookie redeemable.
- **Cookie names carry the `__Host-` prefix in production** (`auth.UseHostPrefixedCookies`, called once from `cmd/serve.go` when `IsProd`). The names are therefore **vars, not consts** — read them at call time, never snapshot them into a package-level map, or you will capture the dev spellings and forward real cookies to upstreams (`proxy.toriiReservedCookies` is a function for exactly this reason). The prefix makes a cookie unstorable unless it is `Secure`, `Path=/` and carries no `Domain`, which is what stops a sibling host under the same registrable domain forging one: torii's cookies are host-only, and per RFC 6265bis `HttpOnly` only protects a write whose full (name, domain, host-only, path) tuple matches — so a `document.cookie` write carrying `Domain=example.com` was a *different* key and was accepted. **Every** torii cookie carries the prefix, including the refresh cookie and the four SSO temp cookies (`sso_state` / `sso_nonce` / `sso_return_host` / `sso_handoff_cnf`), whose names now live in `internal/auth/cookies.go` alongside the rest. The refresh cookie used to be exempt on the theory that its narrow `/_torii/api/v1/` scope kept it away from upstreams and that `refresh_tokens.host` defended it: neither held. The proxy strips every name in `ToriiCookieNames()` anyway, so the scope bought nothing, and the host column records which host *minted* a token, not whose browser holds it. Meanwhile the exemption cost the prefix — and per RFC 6265 §5.4 a longer path sorts first, so a sibling host could plant a cookie at a deeper path that won `(*http.Request).Cookie`'s first match and that no clearing path could remove. `__Host-` mandates `Path=/`, so `refreshCookiePath` and `ssoCookiePath` are **vars** that `UseHostPrefixedCookies` flips to `/`. Gated on `IsProd` because a `__Host-` cookie without `Secure` is dropped by the browser — **running `APP_ENV=production` without a TLS terminator in front will lock every user out**, as `Secure` cookies alone already would.
- **Rotation**: every successful `/api/v1/token_refresh` consumes the old row and creates a new one, in one statement (`ConsumeRefreshTokenByHash`). The Nuxt composable schedules a silent refresh `expires_in - 30s` after each issuance. `AttemptCookieRefresh` (the `refresh_and_redirect` path) must stay in lockstep with `tokenRefresh` — atomic consume, `locked_until`, host binding, audit event. It previously diverged on all four, and the weaker path is the one an attacker picks.
- **`ClearAuthCookies` emits three sets**: current names, legacy unprefixed names (so an upgrade doesn't orphan cookies nothing will ever expire), and domain-scoped copies on each parent domain (the only way to clear a cookie planted before the rename). The legacy refresh name is cleared at **both** `/` and `/_torii/api/v1/`; clearing one left the other to shadow the real cookie on every request, which is a logout no in-product action can undo. `parentDomains` caps host length and label count — it is reached from the unauthenticated `/token_refresh` before any host validation, and building every suffix of an L-byte `Host` is O(L²) live bytes, which `net/http`'s 1 MiB header allowance turns into a one-request OOM of the whole gateway. `cmd/serve.go` also rejects any `Host` over `maxHostHeaderLen` before the chain runs, and registers `middleware.Recover()`. `POST /logout` requires `IsSameOrigin` — it is unauthenticated, answered on every proxied host, and exempt from the cookie CSRF gate, so a cross-site form POST could otherwise delete a visitor's real cookies and leave a planted one to win.
- **First user is admin, and needs a bootstrap token**: while `users` is empty `Signup` grants the `admin` role and its full permission set. That grant requires (a) the request to arrive on `TORII_URL`, and (b) a `bootstrap_token` in the body matching `Config.BootstrapToken`, which `cmd/serve.go` generates and prints to stderr at startup when `CountUsers() == 0` (or takes from `TORII_BOOTSTRAP_TOKEN`). `signup_enabled` does **not** gate this path — the check short-circuits at count zero — so the token is the only thing standing between a freshly migrated deployment and an anonymous administrator. Once any account exists the token is cleared in memory. `GET /auth/config` reports `bootstrap_required` so the signup page can ask for it.
- **Self-protection on admin endpoints**: admins cannot delete themselves or revoke their own current refresh token (server compares sha256 of caller's refresh cookie to row hash).
- **Privilege ceiling on every destructive user operation**: `guardOutranksTarget` gates password reset, unlock, role revoke, **user delete**, **session revoke**, and **refresh-token revoke**. A delegated operator holding one write permission must not be able to act on an account more privileged than their own — deletion in particular is irreversible for the target's PATs. `role_services` assign/revoke are gated too, by `guardReachesService` **and** `callerCanGrantRole`: binding a target's services to a role you hold is how you manufacture the very reach `callerReachesUserServices` tests, which then clears the password-reset ceiling. `callerReachesRoleServices` therefore has **no** `role_services.create` short-circuit — it exempts full administrators only.
- **Last-admin guards are transactional**: `adminDeleteUser` and `adminRevokeUserRole` take `pg_advisory_xact_lock(adminGuardLock)` in the same transaction as the write. Read-then-act let two concurrent removals each observe two admins and between them leave the deployment with none.
- **Failed-login lockout**: 10 failures locks password signin for 15 min (`users.failed_login_count` / `locked_until`). A failure arriving after the window lapsed starts a fresh count instead of extending the lock — extending let one wrong password every 15 min deny an account (or every admin) forever. Clear a lock via `POST /api/v1/admin/users/:id/unlock` (`users:update`) or, if every admin is locked out, `torii users unlock <username|email>`. SSO signin doesn't consult the lock.

## Reverse proxy

- **Top-level dispatch** (`cmd/serve.go:dispatch`): every non-`/api/v1/*` request is routed by `Host`. `Host == TORII_URL` -> SPA. Match in the `services` table + valid torii access token -> `httputil.ReverseProxy` to `service_url` (path/query forwarded as-is, `Host` rewritten to upstream, per-service `headers` overlaid on top of the client's headers). Unmatched / unauthenticated -> SPA (which renders signin or a 4xx via `error.vue` once authed).
- **Service cache** (`internal/proxy/cache.go`): in-memory `map[domain]*CachedService`, refreshed on TTL (30 s) or explicit `Invalidate()` from the admin services CRUD handlers.
- **Service config**: `domain` is hostname[:port] (no scheme/path); `service_url` is `http(s)://host[:port]` with no path/query/fragment. Both are validated server- and client-side.
- **Auth on proxied requests**: signed-in torii user **plus** per-service RBAC — dispatch checks `svc.AllowsAnyRole(claims.RoleIDs)`. Unauthenticated document requests redirect to the **absolute** sign-in URL on `TORII_URL` (see Cross-domain login below); authenticated-but-no-matching-role document requests redirect to `/_torii/forbidden?service=<title>` (styled SPA page served on the service host), while XHR/asset callers get a JSON `403 {"error":"forbidden: no role grants access to this service"}`. Both denials emit an `EventProxyDenied` audit event (`reason: "unauthenticated"` / `"no_role"`).
- **Credential headers / `Authorization` passthrough**: torii **never reads the standard `Authorization` header** on any path — on service hosts it belongs to the upstream (which may run its own auth) and is forwarded untouched. torii credentials ride in dedicated headers, one per audience, and each token type has exactly one valid home (enforced in `auth.authenticateWith` via `controlPlanePolicy` / `proxyPolicy`):
  - **`X-Torii-Authorization`** → control-plane API + web UI. Accepts a session JWT or a `torii_pat_` personal token; a `torii_sat_` is rejected.
  - **`X-Torii-Service-Token`** → proxy access to an upstream. Accepts a `torii_sat_` service token only; a `torii_pat_` / JWT is rejected.
  - **`access_token` cookie** (always a session JWT) → both paths, browsers; subject to the same-origin CSRF gate on state-changing methods.
  Both torii headers and the session cookies are stripped before proxying so they never reach an upstream. See `auth.ClaimsFromProxyRequest` and `proxy.ProxyTo`.
- **Inbound header hygiene** (`proxy.stripClientHeaders`): every torii-owned header — the `X-Torii-*` identity assertions and both credential headers — is dropped from the client's request by *normalized* name (lowercase, `_` folded to `-`), so `X_Torii_Roles` can't survive to an upstream that folds underscores (nginx `underscores_in_headers`, CGI/PHP). Underscore spellings of `X-Forwarded-{For,Host,Proto}` are dropped too; the dash forms are torii's own output.
- **Trusted proxies** (`internal/proxy/trust.go`): `TRUSTED_PROXY_CIDRS` gates every `X-Forwarded-*` fact torii consumes. `RealIP()` honors XFF only from a trusted peer, and the client-facing scheme forwarded upstream as `X-Forwarded-Proto` comes from `inbound.TLS`, consulting the inbound header only from a trusted peer. There is **no default** and no CIDRs means nothing is trusted, which is announced loudly at startup — the old `{127.0.0.1/32, ::1/128}` default read as configured but could never match under the documented compose deployment (a container does not see `127.0.0.1` as the peer of a host-originated connection; Docker re-originates it from the bridge gateway), so `RealIP()` returned one constant address for every client and every per-IP rate limiter collapsed into a single shared bucket. `proxy.WarnOnMisconfiguredTrust` prints a one-shot warning the first time a request arrives carrying `X-Forwarded-For` from an untrusted peer, which is the live signature of that misconfiguration. `docker-compose.prod.yml` sets `TRUSTED_PROXY_CIDRS` explicitly. `signin` additionally carries a per-identifier limiter (`allowIdentifierAttempt`) as a fail-safe that does not depend on torii's view of the client address at all. The same gate decides what is *forwarded*: `proxy.stripForwardedHeaders` drops an inbound `X-Forwarded-For` unless the peer is trusted (`ReverseProxy` then rebuilds it from `RemoteAddr`), and always drops `X-Real-Ip` / `X-Client-Ip` / `True-Client-Ip` / `CF-Connecting-IP` / `Fastly-Client-Ip` / `Forwarded`, which torii never sets — an upstream reading one of those was reading a client-authored address.
- **Credential collection is control-plane only.** `/signin` and `/signup` are **not** in `crossHostEndpoints`, and `dispatch` serves only `/_torii/handoff`, `/_torii/forbidden` and bundle assets under `/_torii` on a service host (`toriiPathAllowedOffHost`). The client half is `middleware/domain-gate.global.ts`'s `crossHostPages`. Do not add a credential page or endpoint to either list: a password form on an upstream's origin is same-origin with whatever script that upstream runs, and a captured password has no host binding — it replays on the control plane and on every other service, defeating the per-host JWT `aud` and the off-host token suppression.
- **Cross-domain login**: cookies are scoped per host, so a session has to be materialised per service domain — but credentials are only ever entered on `TORII_URL`.
  1. `dispatch` on the service host sets a host-scoped correlator cookie (`auth.HandoffCorrelatorCookie`, `Path=/_torii/`) and 302s **absolute** to `https://TORII_URL/_torii/api/v1/handoff_start?return_to_host=…&handoff_cnf=<sha256(correlator)>&to=…`.
  2. `handoff_start` (control plane only, optional auth) resolves the caller's control-plane session — access cookie, else `AttemptCookieRefresh`, since the 1-minute access TTL means an expired token is the norm. **Already signed in is the common case** and needs no password prompt.
  3. No session → 302 to `/_torii/signin` carrying the same params; the page passes them back in the POST body (or forwards them into `/oauth/:slug/start`) and the response carries `handoff_url`.
  4. Either way the server mints a 30s single-use `typ=handoff` token with the digest as `cnf`, and the browser lands on `https://<service>/_torii/handoff#token=…`, which POSTs to `/sso_handoff`.

  Redemption requires same-origin, a correlator cookie hashing to `cnf`, and a successful `BurnHandoffJTI` insert into `handoff_jtis` (`ON CONFLICT DO NOTHING`, so Postgres picks the winner and the burn holds across replicas — it used to be a process-local map). `return_to_host` without `handoff_cnf` is ignored — that is what stops the service-host leg, and therefore the correlator, being skipped. The correlator cookie is `__Host-` prefixed in prod for the same reason as the others: forging it from a sibling host would defeat the binding.

  Do **not** point step 1 at `/_torii/signin` directly: that page carries the `guest` middleware, which bounces an authenticated visitor to `/dashboard`, so the handoff never runs and the service becomes unreachable for anyone already signed in.
- **WebSockets / streaming**: handled natively by `httputil.ReverseProxy` (Connection/Upgrade headers preserved by the default director). Deadlines are only cleared once the upstream answers `101` — a request that merely *claims* `Connection: Upgrade` gets a bounded handshake window (`upgradeHandshakeWindow`, 30s) so client headers alone can't opt out of every timeout. Concurrent hijacked connections are capped per account (`maxUpgradesPerUser`, 32); over the cap torii answers 429.

## Configuration (env)

| Var | Default | Notes |
| --- | --- | --- |
| `APP_ENV` | `dev` | anything else (`production`, `prod`, `staging`) flips: strong-password validation on signup, Secure cookies, no Nuxt subprocess, embed-served SPA |
| `JWT_SECRET` | *(required)* | HS256 secret, 32+ chars |
| `ACCESS_TOKEN_EXPIRY_MINS` | `1` | Also bounds how long a revoked role or permission keeps working (claims are snapshotted into the JWT). |
| `REFRESH_TOKEN_EXPIRY_DAYS` | `7` | |
| `DATABASE_URL` | *(required)* | pgx connection string |
| `API_HOST` | `0.0.0.0` | |
| `API_PORT` | `1356` | |
| `TORII_URL` | *(required)* | host[:port] torii itself answers on. Requests with this `Host` header serve the SPA; other hosts go through the reverse-proxy. Dev value: `localhost:1356`. Also exposed to the SPA via `runtimeConfig.public.toriiUrl`. |
| `AUDIT_LOG_DIR` | `./logs` | directory for the JSON-lines audit trail (`audit.jsonl`); auto-created. In prod, compose bind-mounts `./audit-logs` → `/app/logs`; the host dir must be owned by UID/GID 10001 (the container's `torii` user) — `mkdir -p ./audit-logs && sudo chown -R 10001:10001 ./audit-logs`. |
| `TORII_BOOTSTRAP_TOKEN` | *(generated)* | Gates the first-user administrator grant while `users` is empty. Leave unset and torii generates one per boot and prints it to stderr; set it to script an unattended first-run. Ignored once any account exists. |
| `DATABASE_URL` pool sizing | — | `internal/db/pool.go` raises `MaxConns` to 16 when the URL doesn't set `pool_max_conns`. pgx's own default is `max(4, NumCPU)`, which made "a handful of concurrent requests" and "the entire pool" the same number. |
| `TRUSTED_PROXY_CIDRS` | *(none — warns)* | Comma-separated CIDRs of the reverse proxies whose `X-Forwarded-*` torii may believe. Unset means nothing is trusted and the TCP peer is the client IP, which behind any proxy (including Docker port publishing) makes every client share one rate-limit bucket and one audit source IP. See Trusted proxies above. |
| `SITE_URL` | `https://toriigate.org` | Public canonical URL baked into the SPA at build time (canonical link, `og:url`, sitemap). Read by `client/nuxt.config.ts` during `bun run generate`. Override at Docker build via `--build-arg SITE_URL=...`. Only affects prerendered HTML — runtime requests don't read it. |

Loaded by `godotenv.Load()` in `server.go` from `.env`/`.app.env`.

## Common workflows (commands the user runs)

Dev:
```
docker compose up
```

Add a Go dep:
```
go get <module>
go mod tidy
```

Add a sqlc query: edit a file in `internal/db/queries/`, then:
```
sqlc generate
```
Note: sqlc overwrites `internal/db/db.go`, `models.go`, and `*.sql.go`. The hand-written `Open` lives in `internal/db/pool.go` precisely so it survives regeneration. Don't put hand-written code in `db.go`.

Add a migration:
```
# create files manually as migrations/NNNN_name.{up,down}.sql
torii migrate up        # via docker: docker compose run --rm app torii migrate up
```

A failed migration leaves `schema_migrations` dirty and blocks every later `up`.
Some migrations abort on purpose (0016 refuses when two accounts differ only by
letter case). Fix the data, then:
```
torii migrate force <last version that actually applied>
torii migrate up
```

Prune audit logs:
```
torii audit prune --days 90
```

Clear a failed-login lockout (escape hatch when no admin can sign in):
```
torii users unlock <username|email>
```

Add a shadcn-vue component (in `client/`):
```
bunx shadcn-vue@latest add <component>
```

Production build/run:
```
docker compose -f docker-compose.prod.yml up -d --build
```
or locally:
```
cd client && bun run generate && cd ..
rm -rf internal/web/dist && mkdir -p internal/web/dist
cp -r client/.output/public/. internal/web/dist/
go build -o torii .
APP_ENV=production JWT_SECRET=... DATABASE_URL=... ./torii serve --migrate
```

## Conventions & gotchas

- **Echo v5 quirks**: handlers take `*echo.Context`; path params are `c.Param("id")` (not `c.PathParam`); `c.Response()` is itself an `http.ResponseWriter`. Middleware signature is `func(next echo.HandlerFunc) echo.HandlerFunc`.
- **sqlc + pgx/v5**: `uuid` columns map to `github.com/google/uuid.UUID` via the override in `sqlc.yaml`. `timestamptz` columns map to `pgtype.Timestamptz` (no override worked); access via `.Time` and `.Valid`. To insert one, wrap as `pgtype.Timestamptz{Time: t, Valid: true}`.
- **Pagination**: every list endpoint uses `?page=&page_size=` (defaults 1/20, max 100). Reuse `parsePagination(c)` from `internal/api/pagination.go` and the `pageMeta` struct embedded in response shapes (`{ items, page, page_size, total }`). SQL queries use `LIMIT sqlc.arg('lim')::int OFFSET sqlc.arg('off')::int` so generated structs are `{Lim, Off}`.
- **Nuxt fetch**: always pass `credentials: 'include'` so the refresh cookie rides along. Auth header comes from `useAuth().authHeaders()` (or `useAdminApi()` which already attaches it).
- **Auto-imports**: Nuxt auto-imports composables (`useAuth`, `useAdminApi`), components under `app/components/`, and Vue refs/computed/watch — don't add explicit `import { ref } from 'vue'`.
- **Path aliases**: `~/composables/*` and `@/components/*` both resolve into `client/app/`.
- **No emojis** in committed code, comments, or copy unless the user asks for them.
- **Comments**: write none by default. Only when WHY isn't obvious from the code. Don't restate WHAT.
