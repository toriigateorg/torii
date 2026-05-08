<p align="center">
  <img src="web/torii-logo.svg" alt="torii" width="120" />
</p>

<h1 align="center">torii</h1>

<p align="center">
  Identity-aware reverse proxy with built-in auth and RBAC.
</p>

---

torii is a single Go binary that fronts your internal services with authentication, session management, and an admin UI. The Echo API server, database migrations, and the embedded Nuxt SPA all ship as one executable — no Node runtime in production.

## Features

- Identity-aware reverse proxy: route by `Host`, gate every upstream behind a torii session.
- Built-in auth: signup/signin, JWT access tokens, rotating refresh tokens, argon2id passwords.
- First-user-is-admin bootstrap, plus an admin UI for users, services, and tokens.
- JSON-lines audit log with a prune command.
- Single static binary in production; embedded SPA via `go:embed`.

## Stack

- **Backend**: Go 1.26, Echo v5, pgx v5 + sqlc, golang-migrate, PostgreSQL 18.
- **Frontend**: Nuxt 4 (SPA), Vue 3, TypeScript, Tailwind v4, shadcn-vue.

## Quick start

Dev (Docker):

```sh
docker compose up
```

Production:

```sh
docker compose -f docker-compose.prod.yml up -d --build
```

## Configuration

Set via environment (`.env` or `.app.env`):

| Var | Default | Notes |
| --- | --- | --- |
| `APP_ENV` | `dev` | `production` enables Secure cookies, strong-password validation, embedded SPA |
| `JWT_SECRET` | *(required)* | HS256 secret, 32+ chars |
| `DATABASE_URL` | *(required)* | pgx connection string |
| `TORII_URL` | *(required)* | host[:port] torii answers on; other hosts are reverse-proxied |
| `API_HOST` / `API_PORT` | `0.0.0.0` / `1356` | |
| `ACCESS_TOKEN_EXPIRY_MINS` | `5` | |
| `REFRESH_TOKEN_EXPIRY_DAYS` | `7` | |
| `AUDIT_LOG_DIR` | `./logs` | mount a volume here in prod |

## CLI

```sh
torii serve --migrate         # run server, applying migrations on boot
torii migrate up | down       # manage schema
torii audit prune --days 90   # trim audit log
```

## License

See [LICENSE](web/LICENSE).
