package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/urfave/cli/v3"
)

const (
	migrationsDir = "migrations"
	sourceURL     = "file://migrations"
)

func Migrate() *cli.Command {
	return &cli.Command{
		Name:  "migrate",
		Usage: "run or revert database migrations",
		Commands: []*cli.Command{
			{
				Name:      "up",
				Usage:     "apply migrations (optionally up to NNNN)",
				ArgsUsage: "[NNNN]",
				Action: func(ctx context.Context, c *cli.Command) error {
					return migrateUp(c.Args().First())
				},
			},
			{
				Name:      "down",
				Usage:     "revert migrations (optionally down to NNNN)",
				ArgsUsage: "[NNNN]",
				Action: func(ctx context.Context, c *cli.Command) error {
					return migrateDown(c.Args().First())
				},
			},
		},
	}
}

func openMigrate() (*migrate.Migrate, error) {
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		return nil, errors.New("DATABASE_URL is not set")
	}
	m, err := migrate.New(sourceURL, dbURL)
	if err != nil {
		return nil, fmt.Errorf("opening migrate: %w", err)
	}
	return m, nil
}

// migrationVersions returns all .up.sql migration versions sorted ascending,
// parsed from the migrations/ directory (e.g. "0001_init.up.sql" -> 1).
func migrationVersions() ([]uint, error) {
	entries, err := os.ReadDir(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", migrationsDir, err)
	}
	var versions []uint
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		under := strings.IndexByte(name, '_')
		if under < 1 {
			continue
		}
		v, err := strconv.ParseUint(name[:under], 10, 64)
		if err != nil {
			continue
		}
		versions = append(versions, uint(v))
	}
	sort.Slice(versions, func(i, j int) bool { return versions[i] < versions[j] })
	return versions, nil
}

func currentVersion(m *migrate.Migrate) (uint, error) {
	v, _, err := m.Version()
	if errors.Is(err, migrate.ErrNilVersion) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	return v, nil
}

// parseTarget parses a "NNNN" positional arg as an unsigned version. Empty
// string means "no target".
func parseTarget(arg string) (uint, bool, error) {
	if arg == "" {
		return 0, false, nil
	}
	v, err := strconv.ParseUint(strings.TrimLeft(arg, "0"), 10, 64)
	if err != nil {
		// Pure-zeros like "0000" trim to "" — treat as 0.
		if strings.TrimLeft(arg, "0") == "" {
			return 0, true, nil
		}
		return 0, false, fmt.Errorf("invalid migration number %q: %w", arg, err)
	}
	return uint(v), true, nil
}

func migrateUp(targetArg string) error {
	target, hasTarget, err := parseTarget(targetArg)
	if err != nil {
		return err
	}

	m, err := openMigrate()
	if err != nil {
		return err
	}
	defer closeMigrate(m)

	all, err := migrationVersions()
	if err != nil {
		return err
	}

	cur, err := currentVersion(m)
	if err != nil {
		return err
	}

	for _, v := range all {
		if v <= cur {
			continue
		}
		if hasTarget && v > target {
			break
		}
		fmt.Printf("Running migration %04d\n", v)
		if err := m.Steps(1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				break
			}
			return fmt.Errorf("applying migration %04d: %w", v, err)
		}
	}
	fmt.Println("Migrations up to date")
	return nil
}

func migrateDown(targetArg string) error {
	target, hasTarget, err := parseTarget(targetArg)
	if err != nil {
		return err
	}

	m, err := openMigrate()
	if err != nil {
		return err
	}
	defer closeMigrate(m)

	for {
		cur, err := currentVersion(m)
		if err != nil {
			return err
		}
		if cur == 0 {
			break
		}
		if hasTarget && cur <= target {
			break
		}
		fmt.Printf("Reverting migration %04d\n", cur)
		if err := m.Steps(-1); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				break
			}
			return fmt.Errorf("reverting migration %04d: %w", cur, err)
		}
	}
	fmt.Println("Migrations reverted")
	return nil
}

func closeMigrate(m *migrate.Migrate) {
	srcErr, dbErr := m.Close()
	if srcErr != nil {
		fmt.Fprintln(os.Stderr, "migrate source close:", srcErr)
	}
	if dbErr != nil {
		fmt.Fprintln(os.Stderr, "migrate db close:", dbErr)
	}
}

