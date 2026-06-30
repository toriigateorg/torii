package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"time"

	"github.com/labstack/echo/v5"

	"torii/internal/auth"
)

// Identity is the authenticated caller's session, forwarded to upstream
// services via signed X-Torii-* headers. The torii access cookie itself is
// stripped from the proxied request so a compromised upstream cannot replay
// the JWT against the torii API.
type Identity struct {
	UserID   string
	Username string
	Email    string
	Roles    []string
}

// torii-owned headers that must never be passed through from the client to
// the upstream. We re-set them ourselves below.
var stripIdentityHeaders = []string{
	"X-Torii-User",
	"X-Torii-Username",
	"X-Torii-Email",
	"X-Torii-Roles",
	"X-Torii-Issued-At",
	"X-Torii-Signature",
}

// ProxyTo reverse-proxies the request to the cached service's target. It
// strips torii-owned authentication material from the request, injects signed
// identity headers describing the caller, and applies the per-service header
// overlay last.
func ProxyTo(svc *CachedService, ident Identity, c *echo.Context) error {
	inbound := c.Request()
	origHost := inbound.Host
	origProto := "http"
	if inbound.TLS != nil || strings.EqualFold(inbound.Header.Get("X-Forwarded-Proto"), "https") {
		origProto = "https"
	}

	// Cap the request body torii forwards upstream. The control-plane API
	// keeps its own 1 MiB limit (see router.go); proxied traffic is governed
	// per-service so large uploads only flow to services that opt in. 0 means
	// no torii-imposed limit.
	if svc.MaxBodySize > 0 && inbound.Body != nil {
		inbound.Body = http.MaxBytesReader(c.Response(), inbound.Body, svc.MaxBodySize)
	}

	// Per-service read/write deadlines on the client<->torii connection. The
	// server-level ReadTimeout/WriteTimeout are disabled (see cmd/serve.go) so
	// these are the effective limits; a default is applied globally and
	// overridden here per service.
	//
	// WebSocket/upgrade requests hijack the connection for long-lived
	// bidirectional streaming, so any deadline (including the global default
	// set upstream of dispatch) would kill them. Clear deadlines for those.
	if isUpgradeRequest(inbound) {
		SetDeadlines(c.Response(), 0, 0)
	} else {
		SetDeadlines(c.Response(), svc.ReadTimeout, svc.WriteTimeout)
	}

	rp := httputil.NewSingleHostReverseProxy(svc.Target)
	if svc.Transport != nil {
		rp.Transport = svc.Transport
	}
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		// By default rewrite Host to the upstream so vhost-based servers and
		// SNI work. Per-service opt-in (preserve_host) keeps the client's
		// Host so apps like Streamlit build correct same-origin redirects
		// instead of pointing back at their internal address.
		if !svc.PreserveHost {
			req.Host = svc.Target.Host
		}

		// Surface the original client-facing host/proto to the upstream so it
		// can build correct absolute URLs and redirects. X-Forwarded-For is
		// already appended by httputil.ReverseProxy.
		if origHost != "" {
			req.Header.Set("X-Forwarded-Host", origHost)
		}
		req.Header.Set("X-Forwarded-Proto", origProto)

		// Disable upstream compression so we can splice the torii overlay
		// into HTML responses without having to decode gzip/br.
		req.Header.Del("Accept-Encoding")

		// Prevent the upstream from impersonating the torii user against
		// the torii API on its own hostname (or any other host that trusts
		// the torii access cookie / Bearer).
		req.Header.Del("Authorization")
		req.Header.Del(auth.ServiceTokenHeader)
		stripCookies(req, auth.AccessCookie, auth.RefreshCookie, auth.SessionCookie)

		// Reject any inbound X-Torii-* a client might have set so we control
		// the identity assertion end-to-end.
		for _, h := range stripIdentityHeaders {
			req.Header.Del(h)
		}

		issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
		roles := strings.Join(ident.Roles, ",")
		req.Header.Set("X-Torii-User", ident.UserID)
		req.Header.Set("X-Torii-Username", ident.Username)
		if ident.Email != "" {
			req.Header.Set("X-Torii-Email", ident.Email)
		}
		req.Header.Set("X-Torii-Roles", roles)
		req.Header.Set("X-Torii-Issued-At", issuedAt)

		if len(svc.SigningSecret) > 0 {
			payload := strings.Join([]string{
				ident.UserID,
				ident.Username,
				ident.Email,
				roles,
				issuedAt,
			}, "|")
			mac := hmac.New(sha256.New, svc.SigningSecret)
			mac.Write([]byte(payload))
			req.Header.Set("X-Torii-Signature", hex.EncodeToString(mac.Sum(nil)))
		}

		for k, v := range svc.Headers {
			req.Header.Set(k, v)
		}
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		if resp.StatusCode >= 500 && !svc.PassthroughErrors {
			return replaceWithUpstreamError(resp)
		}
		return injectOverlay(resp)
	}
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			renderUpstreamError(w, r, http.StatusRequestEntityTooLarge)
			return
		}
		renderUpstreamError(w, r, http.StatusBadGateway)
	}
	rp.ServeHTTP(c.Response(), c.Request())
	return nil
}

// isUpgradeRequest reports whether the request is asking to switch protocols
// (e.g. a WebSocket handshake), which the reverse proxy serves by hijacking
// the connection for long-lived streaming.
func isUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

// SetDeadlines applies per-request read/write deadlines to the underlying
// connection via http.ResponseController. A zero duration clears the deadline
// (no timeout). Errors are ignored: if the writer doesn't support deadlines
// the request simply runs without them rather than failing.
func SetDeadlines(w http.ResponseWriter, read, write time.Duration) {
	rc := http.NewResponseController(w)
	now := time.Now()
	if read > 0 {
		_ = rc.SetReadDeadline(now.Add(read))
	} else {
		_ = rc.SetReadDeadline(time.Time{})
	}
	if write > 0 {
		_ = rc.SetWriteDeadline(now.Add(write))
	} else {
		_ = rc.SetWriteDeadline(time.Time{})
	}
}

// stripCookies rewrites the request's Cookie header to omit the named cookies.
// If no cookies remain, the header is removed entirely.
func stripCookies(req *http.Request, names ...string) {
	raw := req.Header.Get("Cookie")
	if raw == "" {
		return
	}
	skip := make(map[string]struct{}, len(names))
	for _, n := range names {
		skip[n] = struct{}{}
	}
	parts := strings.Split(raw, ";")
	kept := parts[:0]
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed == "" {
			continue
		}
		name := trimmed
		if eq := strings.IndexByte(trimmed, '='); eq >= 0 {
			name = trimmed[:eq]
		}
		if _, drop := skip[name]; drop {
			continue
		}
		kept = append(kept, p)
	}
	if len(kept) == 0 {
		req.Header.Del("Cookie")
		return
	}
	req.Header.Set("Cookie", strings.Join(kept, ";"))
}
