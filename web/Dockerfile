# syntax=docker/dockerfile:1.7

# ---------- Stage 1: build the Nuxt SPA ----------
FROM oven/bun:1.3.13-alpine AS client
WORKDIR /app/client

# Install dependencies first for better layer caching.
COPY client/package.json client/bun.lock ./
RUN bun install --frozen-lockfile

# Then bring in sources and build the static SPA.
COPY client/ ./

# Public site URL baked into prerendered HTML (canonical, og:url, sitemap).
ARG SITE_URL=https://toriigate.org
ENV SITE_URL=${SITE_URL}
# Release version surfaced in the navbar (runtimeConfig.public.toriiVersion).
ARG TORII_VERSION=dev
ENV TORII_VERSION=${TORII_VERSION}
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

# Release version baked into the binary; surfaced via `torii --version` and
# the /_torii/api/v1/health JSON.
ARG TORII_VERSION=dev

# Static, stripped binary.
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath \
    -ldflags="-s -w -X torii/internal/version.Version=${TORII_VERSION}" \
    -o /out/torii .

# ---------- Stage 3: minimal runtime ----------
FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata \
    && addgroup -g 10001 -S torii \
    && adduser  -u 10001 -S torii -G torii

WORKDIR /app

COPY --from=server /out/torii /usr/local/bin/torii

RUN mkdir -p /app/logs && chown torii:torii /app/logs

USER torii
EXPOSE 1356

ENV APP_ENV=production

ENTRYPOINT ["torii"]
CMD ["serve", "--migrate"]
