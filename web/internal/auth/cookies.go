package auth

import (
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v5"
)

// Cookie names are variables, not constants, because production uses the __Host-
// prefixed forms and dev cannot: the prefix requires Secure, which is off when
// APP_ENV=dev. UseHostPrefixedCookies switches them once at startup, before the
// server accepts a request; nothing mutates them afterwards.
//
// Why the prefix matters. torii's cookies are host-only (no Domain attribute) and
// were unprefixed, and per RFC 6265bis a stored cookie is matched on the tuple of
// name, domain, host-only flag and path — so HttpOnly only protects a write whose
// whole tuple matches. A script on a sibling host under the same registrable
// domain could therefore write the *same name* with Domain=example.com: a
// different key, unprotected by HttpOnly, accepted, and sent to every sibling
// host. stripUpstreamAuthCookies closed the Set-Cookie response direction and
// cannot see a document.cookie write. The __Host- prefix is what closes it: the
// browser refuses to store such a cookie unless it is Secure, Path=/ and carries
// no Domain, so it cannot be forged across the domain at all.
var (
	AccessCookie  = legacyAccessCookie
	RefreshCookie = legacyRefreshCookie
	// SessionCookie is a non-secret marker cookie at Path=/ that lives as long
	// as the refresh token. The refresh cookie itself is scoped to
	// /_torii/api/v1/ so it doesn't leak to upstream services on proxied
	// hosts; dispatch uses this marker's presence on service paths to decide
	// whether to bounce a navigation through /_torii/api/v1/refresh_and_redirect
	// or to the control plane.
	SessionCookie = legacySessionCookie
)

// The pre-prefix names. Kept so ClearAuthCookies can expire cookies a browser is
// still holding from before an upgrade — otherwise they linger forever, since the
// server would only ever clear the prefixed names.
const (
	legacyAccessCookie    = "access_token"
	legacyRefreshCookie   = "refresh_token"
	legacySessionCookie   = "torii_session"
	legacyCorrelatorCooky = "torii_handoff_cor"
)

const (
	// accessCookiePath stays "/" so the cookie rides along on requests to
	// proxied service paths, letting dispatch authenticate the user via the
	// cookie alone. proxy/service.go strips the cookie before forwarding so
	// it never reaches the upstream — the host is the trust boundary.
	// __Host- also mandates it.
	accessCookiePath = "/"
	// refreshCookiePath narrows the refresh cookie even further so it only
	// rides along on the auth endpoints that consume it. dispatch's 302 to
	// /_torii/api/v1/refresh_and_redirect is what makes cross-host refresh
	// work despite this tight scope.
	//
	// This is why the refresh cookie is the one cookie that cannot carry __Host-,
	// which mandates Path=/. Narrow scope was judged the better trade: it keeps
	// the cookie away from upstreams entirely. Its forgery is instead defeated
	// server-side by the host column on refresh_tokens (migration 0017), which
	// holds regardless of browser cookie semantics.
	refreshCookiePath = "/_torii/api/v1/"
)

// UseHostPrefixedCookies switches every cookie torii sets to its __Host- prefixed
// name. Call exactly once, at startup, and only when cookies will be Secure —
// a __Host- cookie sent without Secure is rejected outright by the browser, which
// would lock every user out. cmd/serve.go calls it when cfg.IsProd().
func UseHostPrefixedCookies() {
	AccessCookie = "__Host-" + legacyAccessCookie
	SessionCookie = "__Host-" + legacySessionCookie
	HandoffCorrelatorCookie = "__Host-" + legacyCorrelatorCooky
	// RefreshCookie deliberately keeps its plain name; see refreshCookiePath.
}

// ToriiCookieNames returns every cookie name torii owns under the *current*
// naming, plus the legacy spellings. The proxy uses it to strip them from
// forwarded requests and to reject upstream attempts to define them.
//
// A function rather than a package-level set because the names are decided at
// startup: a set built at init time would capture the unprefixed names and then
// silently forward the real ones to upstreams.
func ToriiCookieNames() []string {
	return []string{
		AccessCookie, RefreshCookie, SessionCookie, HandoffCorrelatorCookie,
		legacyAccessCookie, legacyRefreshCookie, legacySessionCookie, legacyCorrelatorCooky,
	}
}

func SetAccessCookie(c *echo.Context, token string, ttl time.Duration, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     AccessCookie,
		Value:    token,
		Path:     accessCookiePath,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func SetRefreshCookie(c *echo.Context, token string, ttl time.Duration, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     RefreshCookie,
		Value:    token,
		Path:     refreshCookiePath,
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	// Marker cookie at Path=/ so dispatch can detect "session refresh might
	// succeed" on requests that don't carry the path-scoped refresh cookie.
	// HttpOnly is fine — only the server side needs to read it.
	c.SetCookie(&http.Cookie{
		Name:     SessionCookie,
		Value:    "1",
		Path:     "/",
		Expires:  time.Now().Add(ttl),
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// ClearAuthCookies expires every session cookie torii may have set, under every
// name and scope it may have set it.
//
// Three sets are emitted, and all three are needed:
//
//   - The current names, host-only. The ordinary case.
//   - The legacy unprefixed names. After an upgrade to __Host- names a browser
//     still holds the old ones, and nothing else would ever expire them.
//   - Domain-scoped copies on each parent domain. This is the only way to clear a
//     cookie planted by a sibling host before the prefix rename shipped. Without
//     it a spent planted refresh cookie shadowed the victim's own forever, so
//     every refresh failed and no in-product logout could fix it.
func ClearAuthCookies(c *echo.Context, secure bool) {
	type spec struct {
		name string
		path string
	}
	specs := []spec{
		{AccessCookie, accessCookiePath},
		{RefreshCookie, refreshCookiePath},
		{SessionCookie, "/"},
		{legacyAccessCookie, accessCookiePath},
		{legacyRefreshCookie, refreshCookiePath},
		{legacySessionCookie, "/"},
	}
	for _, s := range specs {
		expireCookie(c, s.name, s.path, "", secure)
	}
	// A __Host- cookie cannot carry a Domain, so only the unprefixed spellings can
	// exist domain-scoped and only they are worth expiring this way.
	for _, domain := range parentDomains(c.Request().Host) {
		expireCookie(c, legacyAccessCookie, accessCookiePath, domain, secure)
		expireCookie(c, legacyRefreshCookie, refreshCookiePath, domain, secure)
		expireCookie(c, legacySessionCookie, "/", domain, secure)
	}
}

func expireCookie(c *echo.Context, name, path, domain string, secure bool) {
	c.SetCookie(&http.Cookie{
		Name:     name,
		Value:    "",
		Path:     path,
		Domain:   domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// parentDomains returns the ancestor domains of host that a cookie could have been
// scoped to, most specific first: a.b.example.com yields b.example.com and
// example.com.
//
// It stops at two labels rather than consulting the Public Suffix List, so for a
// multi-label TLD it can over-generate (foo.co.uk yields co.uk). That is harmless:
// the browser applies the PSL itself and ignores a Set-Cookie for a public suffix.
// Erring toward one ignored header beats failing to clear a real planted cookie.
func parentDomains(host string) []string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || net.ParseIP(host) != nil {
		return nil
	}
	labels := strings.Split(host, ".")
	var out []string
	for i := 1; len(labels)-i >= 2; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}
