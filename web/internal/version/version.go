// Package version exposes the build-time version string of torii. The default
// "dev" value is overridden via -ldflags '-X torii/internal/version.Version=...'
// during release builds; see /justfile and the server stage of /web/Dockerfile.
package version

var Version = "dev"
