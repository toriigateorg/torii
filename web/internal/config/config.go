package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	AppEnv                 string
	JWTSecret              []byte
	AccessTokenTTL         time.Duration
	RefreshTokenTTL        time.Duration
	ToriiURL               string
	AuditLogDir            string
	BlockLoopbackUpstreams bool
}

func Load() (*Config, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET is required")
	}
	if len(secret) < 32 {
		return nil, errors.New("JWT_SECRET must be at least 32 bytes")
	}
	if isLowEntropy(secret) {
		return nil, errors.New("JWT_SECRET appears to be low-entropy (all bytes equal); use a random value")
	}
	if len(secret) < 64 {
		fmt.Fprintln(os.Stderr, "[config] WARNING: JWT_SECRET is shorter than 64 bytes; consider rotating to a 64+ byte random value")
	}

	env := os.Getenv("APP_ENV")
	if env == "" {
		env = "dev"
	}

	toriiURL := os.Getenv("TORII_URL")
	if toriiURL == "" {
		return nil, errors.New("TORII_URL is required")
	}

	auditDir := os.Getenv("AUDIT_LOG_DIR")
	if auditDir == "" {
		auditDir = "./logs"
	}

	// Torii is an identity-aware proxy in front of internal services, so
	// RFC1918 / ULA / loopback are the *expected* upstream networks. The
	// SSRF guard only ever rejects link-local (cloud metadata),
	// multicast, and unspecified addresses. Loopback is also a normal
	// pattern (sidecars, co-hosted services); turn this flag on when
	// torii binds anything sensitive on 127.0.0.1.
	blockLoopback := false
	if v := os.Getenv("BLOCK_LOOPBACK_UPSTREAMS"); v != "" {
		blockLoopback = v == "1" || strings.EqualFold(v, "true")
	}

	return &Config{
		AppEnv:                 env,
		JWTSecret:              []byte(secret),
		AccessTokenTTL:         time.Duration(intEnv("ACCESS_TOKEN_EXPIRY_MINS", 5)) * time.Minute,
		RefreshTokenTTL:        time.Duration(intEnv("REFRESH_TOKEN_EXPIRY_DAYS", 7)) * 24 * time.Hour,
		ToriiURL:               toriiURL,
		AuditLogDir:            auditDir,
		BlockLoopbackUpstreams: blockLoopback,
	}, nil
}

func (c *Config) IsProd() bool { return c.AppEnv != "dev" }

// IsToriiHost reports whether the given request Host header refers to the
// torii control plane. Comparison is case-insensitive and tolerates the
// default :80/:443 ports being implicit on either side.
func (c *Config) IsToriiHost(host string) bool {
	return canonicalHost(host) == canonicalHost(c.ToriiURL)
}

func isLowEntropy(s string) bool {
	if len(s) == 0 {
		return true
	}
	first := s[0]
	for i := 1; i < len(s); i++ {
		if s[i] != first {
			return false
		}
	}
	return true
}

func canonicalHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.TrimSuffix(h, ":443")
	h = strings.TrimSuffix(h, ":80")
	return h
}

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
