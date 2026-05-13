// Package web embeds the built Nuxt SPA and serves it as static assets in
// production. In dev mode the binary proxies to the Nuxt dev server instead
// (see internal/proxy), and the embedded FS is effectively empty.
package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"io"
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
//
// toriiURL is injected into every served HTML document as
// `window.__TORII_URL__`, so the SPA can resolve the operator-configured torii
// host at runtime instead of having it baked in at `nuxt generate` time. This
// is what lets the domain-gate middleware know which Host to treat as "the
// torii UI" vs. an unknown / service domain that should bounce to /signin.
func Handler(toriiURL string) echo.HandlerFunc {
	sub, err := fs.Sub(distRoot, "dist")
	if err != nil {
		return func(c *echo.Context) error {
			return c.String(http.StatusInternalServerError, "embedded assets unavailable")
		}
	}
	injection := buildInjection(toriiURL)
	// Strip the /_torii namespace before the FileServer resolves the request:
	// the embedded FS is rooted at the SPA's content, but every request that
	// reaches us has been routed through dispatch under /_torii/*. Nuxt's
	// app.baseURL = "/_torii/" emits asset URLs with the same prefix, so the
	// FileServer needs the raw path (e.g. /_nuxt/foo.js) to find them.
	fileServer := http.StripPrefix("/_torii", http.FileServer(http.FS(spaFS{sub})))
	return func(c *echo.Context) error {
		rw := &htmlInjector{ResponseWriter: c.Response(), inject: injection}
		fileServer.ServeHTTP(rw, c.Request())
		return rw.flush()
	}
}

func buildInjection(toriiURL string) []byte {
	encoded, _ := json.Marshal(toriiURL)
	return []byte("<script>window.__TORII_URL__=" + string(encoded) + "</script>")
}

// htmlInjector buffers the upstream FileServer response so we can splice a
// runtime-config <script> into the <head> of HTML documents without touching
// other assets. We commit the response untouched (passthrough) as soon as we
// determine the Content-Type is not HTML, so JS/CSS/font streams aren't held
// in memory.
type htmlInjector struct {
	http.ResponseWriter
	inject      []byte
	status      int
	wroteHeader bool
	passthrough bool
	buf         bytes.Buffer
	flushErr    error
}

func (h *htmlInjector) WriteHeader(code int) {
	if h.wroteHeader {
		return
	}
	h.status = code
	h.wroteHeader = true
	ct := h.ResponseWriter.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/html") {
		h.passthrough = true
		h.ResponseWriter.WriteHeader(code)
		return
	}
	// We're going to mutate the body length; drop any precomputed
	// Content-Length so the runtime sets the right one (or chunks).
	h.ResponseWriter.Header().Del("Content-Length")
}

func (h *htmlInjector) Write(p []byte) (int, error) {
	if !h.wroteHeader {
		h.WriteHeader(http.StatusOK)
	}
	if h.passthrough {
		return h.ResponseWriter.Write(p)
	}
	return h.buf.Write(p)
}

func (h *htmlInjector) flush() error {
	if h.flushErr != nil {
		return h.flushErr
	}
	if h.passthrough {
		return nil
	}
	if !h.wroteHeader {
		// FileServer never wrote anything (e.g. it called ServeContent which
		// short-circuited via 304). Nothing to inject.
		return nil
	}
	body := h.buf.Bytes()
	if idx := bytes.Index(body, []byte("</head>")); idx >= 0 {
		out := make([]byte, 0, len(body)+len(h.inject))
		out = append(out, body[:idx]...)
		out = append(out, h.inject...)
		out = append(out, body[idx:]...)
		body = out
	}
	h.ResponseWriter.WriteHeader(h.status)
	_, err := io.Copy(h.ResponseWriter, bytes.NewReader(body))
	h.flushErr = err
	return err
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
