package config

import (
	"errors"
	"os"
	"strconv"
	"time"
)

type Config struct {
	AppEnv          string
	JWTSecret       []byte
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	ToriiURL       string
	AuditLogDir     string
}

func Load() (*Config, error) {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return nil, errors.New("JWT_SECRET is required")
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

	return &Config{
		AppEnv:          env,
		JWTSecret:       []byte(secret),
		AccessTokenTTL:  time.Duration(intEnv("ACCESS_TOKEN_EXPIRY_MINS", 5)) * time.Minute,
		RefreshTokenTTL: time.Duration(intEnv("REFRESH_TOKEN_EXPIRY_DAYS", 7)) * 24 * time.Hour,
		ToriiURL:       toriiURL,
		AuditLogDir:     auditDir,
	}, nil
}

func (c *Config) IsProd() bool { return c.AppEnv != "dev" }

func intEnv(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
