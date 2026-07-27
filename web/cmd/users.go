package cmd

import (
	"context"
	"fmt"

	"github.com/urfave/cli/v3"

	"torii/internal/audit"
	"torii/internal/config"
	"torii/internal/db"
)

// Users groups offline account maintenance. `unlock` exists because the API
// unlock endpoint needs an admin who can sign in — if every admin is locked out
// at the same time, that path is unavailable and the alternative would be hand
// -written UPDATEs against the users table.
func Users() *cli.Command {
	return &cli.Command{
		Name:  "users",
		Usage: "user account maintenance",
		Commands: []*cli.Command{
			{
				Name:      "unlock",
				Usage:     "clear a failed-login lockout for a username or email",
				ArgsUsage: "<username|email>",
				Action: func(ctx context.Context, c *cli.Command) error {
					identifier := c.Args().First()
					if identifier == "" {
						return fmt.Errorf("a username or email is required")
					}
					pool, err := db.Open(ctx)
					if err != nil {
						return fmt.Errorf("opening db: %w", err)
					}
					defer pool.Close()

					q := db.New(pool)
					user, err := q.GetUserByUsernameOrEmail(ctx, identifier)
					if err != nil {
						return fmt.Errorf("no user matching %q", identifier)
					}
					if err := q.ResetFailedLogin(ctx, user.ID); err != nil {
						return fmt.Errorf("clearing lockout: %w", err)
					}
					if cfg, cerr := config.Load(); cerr == nil {
						if a, aerr := audit.New(q, cfg.AuditLogDir); aerr == nil {
							a.Log(ctx, audit.Event{
								EventType:  audit.EventLockoutCleared,
								TargetType: audit.TargetUser,
								TargetID:   &user.ID,
								TargetName: user.Username,
								Metadata: map[string]any{
									"via":                "cli",
									"failed_login_count": user.FailedLoginCount,
								},
							})
							a.Close()
						}
					}
					fmt.Printf("Cleared lockout for %s (%d failed attempt(s) reset)\n", user.Username, user.FailedLoginCount)
					return nil
				},
			},
		},
	}
}
