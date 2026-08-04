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
	// as the refresh token. In dev the refresh cookie is scoped to
	// /_torii/api/v1/, so dispatch uses this marker's presence on service paths
	// to decide whether to bounce a navigation through
	// /_torii/api/v1/refresh_and_redirect or to the control plane.
	SessionCookie = legacySessionCookie

	// The four SSO temp cookies. They live for ten minutes across the IdP
	// round-trip and carry the CSRF state, the OIDC nonce, and the cross-host
	// return binding — a sibling host able to plant its own state/nonce pair
	// (with a real authorization code for its own IdP account) logs the victim
	// into the attacker's account, so they need the same __Host- treatment and
	// the same proxy stripping as the session cookies.
	SSOStateCookie      = legacySSOStateCookie
	SSONonceCookie      = legacySSONonceCookie
	SSOReturnHostCookie = legacySSOReturnHostCookie
	SSOHandoffCnfCookie = legacySSOHandoffCnfCookie
)

// The pre-prefix names. Kept so ClearAuthCookies can expire cookies a browser is
// still holding from before an upgrade — otherwise they linger forever, since the
// server would only ever clear the prefixed names.
const (
	legacyAccessCookie        = "access_token"
	legacyRefreshCookie       = "refresh_token"
	legacySessionCookie       = "torii_session"
	legacyCorrelatorCooky     = "torii_handoff_cor"
	legacySSOStateCookie      = "sso_state"
	legacySSONonceCookie      = "sso_nonce"
	legacySSOReturnHostCookie = "sso_return_host"
	legacySSOHandoffCnfCookie = "sso_handoff_cnf"
)

// accessCookiePath stays "/" so the cookie rides along on requests to proxied
// service paths, letting dispatch authenticate the user via the cookie alone.
// proxy/service.go strips the cookie before forwarding so it never reaches the
// upstream — the host is the trust boundary. __Host- also mandates it.
const accessCookiePath = "/"

// legacyRefreshCookiePath is the narrow scope the refresh cookie used before it
// carried __Host-. Still cleared under that path so a browser holding one from
// before the upgrade, or a plant plausibly made there, is expired rather than
// left to shadow the real cookie forever.
const legacyRefreshCookiePath = "/_torii/api/v1/"

// legacySSOCookiePath is the pre-prefix scope of the SSO temp cookies.
const legacySSOCookiePath = "/_torii/api/v1/oauth/"

// refreshCookiePath / ssoCookiePath are vars because __Host- mandates Path=/.
// Narrow scope was originally judged the better trade (it keeps the cookie away
// from upstreams entirely), but the proxy strips every name in ToriiCookieNames
// from forwarded requests anyway, so the scope bought nothing the strip did not
// already buy — while costing the prefix, and with it the only defence against a
// sibling host planting the cookie under a *different* path. Per RFC 6265 §5.4 a
// longer path sorts first, so a plant won (*http.Request).Cookie's first match,
// and no clearing path could remove it. refresh_tokens.host does not help: it
// records which host minted a token, not whose browser holds it.
var (
	refreshCookiePath = legacyRefreshCookiePath
	ssoCookiePath     = legacySSOCookiePath
)

// UseHostPrefixedCookies switches every cookie torii sets to its __Host- prefixed
// name. Call exactly once, at startup, and only when cookies will be Secure —
// a __Host- cookie sent without Secure is rejected outright by the browser, which
// would lock every user out. cmd/serve.go calls it when cfg.IsProd().
func UseHostPrefixedCookies() {
	AccessCookie = "__Host-" + legacyAccessCookie
	RefreshCookie = "__Host-" + legacyRefreshCookie
	SessionCookie = "__Host-" + legacySessionCookie
	HandoffCorrelatorCookie = "__Host-" + legacyCorrelatorCooky
	SSOStateCookie = "__Host-" + legacySSOStateCookie
	SSONonceCookie = "__Host-" + legacySSONonceCookie
	SSOReturnHostCookie = "__Host-" + legacySSOReturnHostCookie
	SSOHandoffCnfCookie = "__Host-" + legacySSOHandoffCnfCookie
	// __Host- mandates Path=/ for every one of them.
	refreshCookiePath = "/"
	ssoCookiePath = "/"
}

// SSOCookiePath exposes the current SSO temp-cookie scope to package api, which
// sets and clears them. Read at call time, never snapshotted — the value is
// decided at startup by UseHostPrefixedCookies.
func SSOCookiePath() string { return ssoCookiePath }

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
		SSOStateCookie, SSONonceCookie, SSOReturnHostCookie, SSOHandoffCnfCookie,
		legacyAccessCookie, legacyRefreshCookie, legacySessionCookie, legacyCorrelatorCooky,
		legacySSOStateCookie, legacySSONonceCookie, legacySSOReturnHostCookie, legacySSOHandoffCnfCookie,
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
		{legacySessionCookie, "/"},
		// Both refresh scopes: "/" catches the __Host- cookie and anything a
		// sibling host planted at the root, the narrow path catches a cookie a
		// browser still holds from before the prefix upgrade. Clearing only one
		// of them left the other to shadow the real cookie on every request,
		// which is an unremovable logout.
		{legacyRefreshCookie, "/"},
		{legacyRefreshCookie, legacyRefreshCookiePath},
	}
	for _, s := range specs {
		expireCookie(c, s.name, s.path, "", secure)
	}
	// A __Host- cookie cannot carry a Domain, so only the unprefixed spellings can
	// exist domain-scoped and only they are worth expiring this way.
	for _, domain := range parentDomains(c.Request().Host) {
		expireCookie(c, legacyAccessCookie, accessCookiePath, domain, secure)
		expireCookie(c, legacyRefreshCookie, "/", domain, secure)
		expireCookie(c, legacyRefreshCookie, legacyRefreshCookiePath, domain, secure)
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
//
// The length gate is load-bearing, not tidiness. This runs on the attacker's raw
// Host header — ClearAuthCookies is reached from the unauthenticated
// /token_refresh before any host validation — and building every suffix of an
// L-byte host costs O(L²) live bytes. net/http accepts a Host up to
// MaxHeaderBytes (1 MiB here), which without the gate is ~275 GB of allocation
// from one request, and a Go OOM is a fatal runtime error that takes the whole
// gateway with it. Anything past the DNS/cookie-domain limits is discarded by
// the browser anyway, so refusing it outright costs nothing real.
const (
	maxCookieHostLen    = 255
	maxCookieHostLabels = 24
)

func parentDomains(host string) []string {
	if len(host) > maxCookieHostLen+8 { // room for a ":65535" port
		return nil
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" || len(host) > maxCookieHostLen || net.ParseIP(host) != nil {
		return nil
	}
	labels := strings.Split(host, ".")
	if len(labels) > maxCookieHostLabels {
		return nil
	}
	var out []string
	for i := 1; len(labels)-i >= 2; i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}
