package main

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/urfave/cli/v3"

	"torii/cmd"
	"torii/internal/version"
)

func main() {
	_ = godotenv.Load()

	app := &cli.Command{
		Name:    "torii",
		Usage:   "torii server and tooling",
		Version: version.Version,
		Commands: []*cli.Command{
			cmd.Serve(),
			cmd.Migrate(),
			cmd.Audit(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
