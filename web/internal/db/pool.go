package db

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/jackc/pgx/v5/pgxpool"
)

// minPoolConns is the floor applied when DATABASE_URL does not set
// pool_max_conns. pgx's own default is max(4, NumCPU), which on a small host is
// four — few enough that a handful of concurrent requests can hold every
// connection, so any handler that waits on the pool while holding a connection
// turns into a gateway-wide stall. Raising the floor does not fix such a handler
// (see signup) but it removes the "four requests is the whole pool" cliff.
const minPoolConns = 16

func Open(ctx context.Context) (*pgxpool.Pool, error) {
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	// Checked on the raw URL rather than by comparing against pgx's default, so an
	// operator who deliberately configures a small pool keeps it.
	if !strings.Contains(url, "pool_max_conns") && cfg.MaxConns < minPoolConns {
		cfg.MaxConns = minPoolConns
	}
	return pgxpool.NewWithConfig(ctx, cfg)
}
