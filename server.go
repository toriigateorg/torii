package main

import (
	"context"
	"log"
	"os"

	"github.com/joho/godotenv"
	"github.com/urfave/cli/v3"

	"sanmon/cmd"
)

func main() {
	_ = godotenv.Load()

	app := &cli.Command{
		Name:  "sanmon",
		Usage: "sanmon server and tooling",
		Commands: []*cli.Command{
			cmd.Serve(),
			cmd.Migrate(),
		},
	}

	if err := app.Run(context.Background(), os.Args); err != nil {
		log.Fatal(err)
	}
}
