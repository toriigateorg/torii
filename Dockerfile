# syntax=docker/dockerfile:1.7

# ---------- Stage 1: build the Nuxt SPA ----------
FROM oven/bun:1.3.13-alpine AS client
WORKDIR /app/client

# Install dependencies first for better layer caching.
COPY client/package.json client/bun.lock ./
RUN bun install --frozen-lockfile

# Then bring in sources and build the static SPA.
COPY client/ ./
RUN bun run generate

# ---------- Stage 2: build the Go binary with the SPA embedded ----------
FROM golang:1.26.2-alpine AS server
WORKDIR /app

# Cache module downloads.
COPY go.mod go.sum ./
RUN go mod download

# Bring in the rest of the Go sources.
COPY . .

# Stage the SPA into the embed root so //go:embed picks it up.
RUN rm -rf internal/web/dist && mkdir -p internal/web/dist
COPY --from=client /app/client/.output/public/ ./internal/web/dist/

# Static, stripped binary.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags='-s -w' -o /out/sanmon .

# ---------- Stage 3: minimal runtime ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -S sanmon && adduser -S sanmon -G sanmon

WORKDIR /app

# Migrations are read from disk (file://migrations) by `migrate up`, so they
# need to ship inside the runtime image even though the SPA is embedded.
COPY --from=server /out/sanmon /usr/local/bin/sanmon
COPY migrations /app/migrations

USER sanmon
EXPOSE 1356

ENV APP_ENV=production

ENTRYPOINT ["sanmon"]
CMD ["serve", "--migrate"]
