package proxy

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
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
	rp := httputil.NewSingleHostReverseProxy(svc.Target)
	originalDirector := rp.Director
	rp.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = svc.Target.Host

		// Disable upstream compression so we can splice the torii overlay
		// into HTML responses without having to decode gzip/br.
		req.Header.Del("Accept-Encoding")

		// Prevent the upstream from impersonating the torii user against
		// the torii API on its own hostname (or any other host that trusts
		// the torii access cookie / Bearer).
		req.Header.Del("Authorization")
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
	rp.ModifyResponse = injectOverlay
	rp.ServeHTTP(c.Response(), c.Request())
	return nil
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
