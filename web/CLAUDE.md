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
docker-compose.prod.yml      prod (named volume, healthcheck, APP_ENV=production)
```

## Auth model

- **Access token**: HS256 JWT, 5 min default (`ACCESS_TOKEN_EXPIRY_MINS`). Returned in JSON response body **and** as an httpOnly cookie. Client keeps it in a Vue `ref` (`useAuth().accessToken`) and sends `Authorization: Bearer <token>`.
- **Refresh token**: 32 random bytes, base64url-encoded. Server stores only the sha256 hash in `refresh_tokens`. Delivered as an httpOnly + SameSite=Lax cookie at path `/api/v1/`, `Secure` only when `APP_ENV != "dev"`.
- **Rotation**: every successful `/api/v1/token_refresh` deletes the old row and creates a new one. The Nuxt composable schedules a silent refresh `expires_in - 30s` after each issuance.
- **First user is admin**: `Signup` runs `CountUsers`; if zero, the new account is created with `user_type='admin'` regardless of payload. Subsequent signups default to `user`.
- **Self-protection on admin endpoints**: admins cannot delete themselves or revoke their own current refresh token (server compares sha256 of caller's refresh cookie to row hash).

## Reverse proxy

- **Top-level dispatch** (`cmd/serve.go:dispatch`): every non-`/api/v1/*` request is routed by `Host`. `Host == TORII_URL` -> SPA. Match in the `services` table + valid torii access token -> `httputil.ReverseProxy` to `service_url` (path/query forwarded as-is, `Host` rewritten to upstream, per-service `headers` overlaid on top of the client's headers). Unmatched / unauthenticated -> SPA (which renders signin or a 4xx via `error.vue` once authed).
- **Service cache** (`internal/proxy/cache.go`): in-memory `map[domain]*CachedService`, refreshed on TTL (30 s) or explicit `Invalidate()` from the admin services CRUD handlers.
- **Service config**: `domain` is hostname[:port] (no scheme/path); `service_url` is `http(s)://host[:port]` with no path/query/fragment. Both are validated server- and client-side.
- **Auth on proxied requests**: any signed-in torii user. RBAC per service is intentionally not implemented yet.
- **Cross-domain login**: cookies are scoped per host, so a user must sign in once per service domain. The signin page detects non-TORII_URL hosts and does a hard `window.location.assign("/")` after success so the Go dispatch can re-evaluate and proxy.
- **WebSockets / streaming**: handled natively by `httputil.ReverseProxy` (Connection/Upgrade headers preserved by the default director).

## Configuration (env)

| Var | Default | Notes |
| --- | --- | --- |
| `APP_ENV` | `dev` | anything else (`production`, `prod`, `staging`) flips: strong-password validation on signup, Secure cookies, no Nuxt subprocess, embed-served SPA |
| `JWT_SECRET` | *(required)* | HS256 secret, 32+ chars |
| `ACCESS_TOKEN_EXPIRY_MINS` | `5` | |
| `REFRESH_TOKEN_EXPIRY_DAYS` | `7` | |
| `DATABASE_URL` | *(required)* | pgx connection string |
| `API_HOST` | `0.0.0.0` | |
| `API_PORT` | `1356` | |
| `TORII_URL` | *(required)* | host[:port] torii itself answers on. Requests with this `Host` header serve the SPA; other hosts go through the reverse-proxy. Dev value: `localhost:1356`. Also exposed to the SPA via `runtimeConfig.public.toriiUrl`. |
| `AUDIT_LOG_DIR` | `./logs` | directory for the JSON-lines audit trail (`audit.jsonl`); auto-created. Mount a volume here in prod (compose mounts `audit-logs` → `/app/logs`). |
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

Prune audit logs:
```
torii audit prune --days 90
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
