// Package web embeds the built Nuxt SPA and serves it as static assets in
// production. In dev mode the binary proxies to the Nuxt dev server instead
// (see internal/proxy), and the embedded FS is effectively empty.
package web

import (
	"embed"
	"errors"
	"io/fs"
	"net/http"
	"strings"

	"github.com/labstack/echo/v5"
)

//go:embed all:dist
var distRoot embed.FS

// HasAssets reports whether the embedded FS contains a built Nuxt bundle
// (i.e. an index.html). When false, we likely have only the .gitkeep.
func HasAssets() bool {
	sub, err := fs.Sub(distRoot, "dist")
	if err != nil {
		return false
	}
	_, err = fs.Stat(sub, "index.html")
	return err == nil
}

// Handler returns an echo handler that serves the embedded Nuxt SPA, falling
// back to index.html for any unknown path so Vue Router / Nuxt route handling
// still works on hard reload.
func Handler() echo.HandlerFunc {
	sub, err := fs.Sub(distRoot, "dist")
	if err != nil {
		return func(c *echo.Context) error {
			return c.String(http.StatusInternalServerError, "embedded assets unavailable")
		}
	}
	fileServer := http.FileServer(http.FS(spaFS{sub}))
	return func(c *echo.Context) error {
		fileServer.ServeHTTP(c.Response(), c.Request())
		return nil
	}
}

// spaFS wraps an fs.FS so that requests for missing paths fall back to
// index.html (the SPA shell). Existing files (including hashed JS/CSS bundles)
// are served untouched.
type spaFS struct{ root fs.FS }

func (s spaFS) Open(name string) (fs.File, error) {
	f, err := s.root.Open(name)
	if err == nil {
		return f, nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	// Don't masquerade missing assets (anything with a file extension besides
	// .html) as the shell — let them 404 properly so the browser shows real
	// errors for bad asset requests.
	if dot := strings.LastIndexByte(name, '.'); dot != -1 {
		ext := name[dot:]
		if ext != ".html" {
			return nil, err
		}
	}
	return s.root.Open("index.html")
}
