// Package migrations embeds the SQL migration files so the production binary
// is fully self-contained. Both `torii migrate up|down` and `serve --migrate`
// read from this FS — there is no on-disk fallback.
package migrations

import (
	"embed"
	"io/fs"
)

//go:embed *.sql
var files embed.FS

// FS returns an io/fs.FS containing entries like "0001_users.up.sql" — the
// shape golang-migrate's iofs source driver expects.
func FS() fs.FS { return files }
