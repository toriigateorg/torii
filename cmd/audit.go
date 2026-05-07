package cmd

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/urfave/cli/v3"

	"sanmon/internal/db"
)

func Audit() *cli.Command {
	return &cli.Command{
		Name:  "audit",
		Usage: "audit log maintenance",
		Commands: []*cli.Command{
			{
				Name:  "prune",
				Usage: "delete audit_logs rows older than --days",
				Flags: []cli.Flag{
					&cli.IntFlag{
						Name:     "days",
						Usage:    "delete rows older than this many days",
						Required: true,
					},
				},
				Action: func(ctx context.Context, c *cli.Command) error {
					days := c.Int("days")
					if days <= 0 {
						return fmt.Errorf("--days must be positive")
					}
					pool, err := db.Open(ctx)
					if err != nil {
						return fmt.Errorf("opening db: %w", err)
					}
					defer pool.Close()

					q := db.New(pool)
					cutoff := time.Now().Add(-time.Duration(days) * 24 * time.Hour)
					n, err := q.DeleteAuditLogsBefore(ctx, pgtype.Timestamptz{Time: cutoff, Valid: true})
					if err != nil {
						return fmt.Errorf("delete audit logs: %w", err)
					}
					fmt.Printf("Pruned %d audit log row(s) older than %s\n", n, cutoff.UTC().Format(time.RFC3339))
					return nil
				},
			},
		},
	}
}
