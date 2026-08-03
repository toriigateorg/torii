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
	"sync"
	"time"

	"github.com/labstack/echo/v5"

	"torii/internal/auth"
)

// Identity is the authenticated caller's session, forwarded to upstream
// services via signed X-Torii-* headers. Torii's own credential channels (the
// access cookie and the X-Torii-Authorization / X-Torii-Service-Token headers)
// are stripped from the proxied request so a compromised upstream cannot replay
// them against the torii API. The client's Authorization header is left intact
// for the upstream's own auth.
type Identity struct {
	UserID   string
	Username string
	Email    string
	Roles    []string
	// PrincipalType is auth.PrincipalUser or auth.PrincipalService. Username is
	// users.username for the former and api_users.name for the latter, and those
	// are separate tables with separate uniqueness — so without this an upstream
	// resolving X-Torii-Username cannot tell a machine credential named "alice"
	// from the human alice.
	PrincipalType string
}

// toriiOwnedHeaders are the headers torii asserts itself, in normalized form
// (lowercase, underscores folded to dashes). Every inbound spelling is dropped
// before the director re-sets the canonical dash form, so a client can never
// contribute one.
//
// Normalizing rather than matching exact names matters: Go treats
// "X_Torii_Roles" as a header distinct from "X-Torii-Roles" and passes it
// through untouched, but an upstream behind nginx with underscores_in_headers,
// or any CGI/PHP app folding "_" to "-", would read it as the roles assertion.
var toriiOwnedHeaders = map[string]struct{}{
	"x-torii-user":           {},
	"x-torii-username":       {},
	"x-torii-email":          {},
	"x-torii-roles":          {},
	"x-torii-issued-at":      {},
	"x-torii-signature":      {},
	"x-torii-principal-type": {},
	"x-torii-authorization": {}, // auth.AuthorizationHeader
	"x-torii-service-token": {}, // auth.ServiceTokenHeader
}

// shadowableForwardedHeaders are set authoritatively by torii (X-Forwarded-Host
// / -Proto) or appended by ReverseProxy (X-Forwarded-For). Only underscore
// spellings are dropped: the dash forms are torii's own output, and discarding
// an inbound X-Forwarded-For would throw away a trusted proxy's client chain
// before ReverseProxy appends to it.
var shadowableForwardedHeaders = map[string]struct{}{
	"x-forwarded-for":   {},
	"x-forwarded-host":  {},
	"x-forwarded-proto": {},
}

// Fail at startup rather than silently forwarding a credential header if one of
// the auth package's header names is ever renamed out from under the strip list.
func init() {
	for _, h := range []string{auth.AuthorizationHeader, auth.ServiceTokenHeader} {
		if _, ok := toriiOwnedHeaders[normalizeHeaderName(h)]; !ok {
			panic("proxy: " + h + " is missing from toriiOwnedHeaders")
		}
	}
}

func normalizeHeaderName(k string) string {
	return strings.ToLower(strings.ReplaceAll(k, "_", "-"))
}

// stripClientHeaders removes every inbound spelling of the headers torii owns.
func stripClientHeaders(h http.Header) {
	for k := range h {
		n := normalizeHeaderName(k)
		if _, owned := toriiOwnedHeaders[n]; owned {
			delete(h, k)
			continue
		}
		if strings.Contains(k, "_") {
			if _, shadow := shadowableForwardedHeaders[n]; shadow {
				delete(h, k)
			}
		}
	}
}

// ProxyTo reverse-proxies the request to the cached service's target. It
// strips torii-owned authentication material from the request, injects signed
// identity headers describing the caller, and applies the per-service header
// overlay last.
func ProxyTo(svc *CachedService, ident Identity, c *echo.Context) error {
	inbound := c.Request()
	origHost := inbound.Host
	// Client-facing scheme. Derived from the connection; the inbound
	// X-Forwarded-Proto is only consulted when the peer is a configured trusted
	// proxy, because any client can set it and upstreams build absolute links
	// and redirects from what we forward.
	origProto := "http"
	if inbound.TLS != nil {
		origProto = "https"
	} else if PeerIsTrustedProxy(inbound) && strings.EqualFold(inbound.Header.Get("X-Forwarded-Proto"), "https") {
		origProto = "https"
	}

	// Cap the request body torii forwards upstream. The control-plane API
	// keeps its own 1 MiB limit (see router.go); proxied traffic is governed
	// per-service so large uploads only flow to services that opt in. 0 means
	// no torii-imposed limit.
	if svc.MaxBodySize > 0 && inbound.Body != nil {
		inbound.Body = http.MaxBytesReader(c.Response(), inbound.Body, svc.MaxBodySize)
	}

	// WebSocket/upgrade requests hijack the connection for long-lived
	// bidirectional streaming, so deadlines have to come off eventually — but
	// "this is an upgrade" is a claim made purely in client headers. Clearing
	// deadlines on the claim alone let any authenticated caller with access to
	// a service opt out of every time limit by sending Connection: Upgrade and
	// then trickling bytes, with only ReadHeaderTimeout and the byte-counting
	// MaxBodySize left. So a claimed upgrade gets a bounded handshake window
	// here, and the deadlines are cleared in ModifyResponse only once the
	// upstream actually answers 101.
	upgrade := isUpgradeRequest(inbound)
	if upgrade {
		release, ok := acquireUpgradeSlot(ident.UserID)
		if !ok {
			renderUpstreamError(c.Response(), inbound, http.StatusTooManyRequests)
			return nil
		}
		defer release()
	}

	// Per-service read/write deadlines on the client<->torii connection. The
	// server-level ReadTimeout/WriteTimeout are disabled (see cmd/serve.go) so
	// these are the effective limits; a default is applied globally and
	// overridden here per service.
	read, write := svc.ReadTimeout, svc.WriteTimeout
	if upgrade {
		read, write = handshakeWindow(read), handshakeWindow(write)
	}
	SetDeadlines(c.Response(), read, write)

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

		// Drop every torii-owned header the client may have sent — the identity
		// assertions (so we control them end-to-end) and torii's own credential
		// channels (so a compromised upstream cannot replay them against the
		// torii API on its own hostname, or any host that trusts the access
		// cookie). Underscore spellings included; see toriiOwnedHeaders.
		//
		// The client's Authorization header is intentionally NOT stripped: on a
		// proxied host it belongs to the upstream (which may use it for its own
		// auth), and torii never reads it there — see auth.ClaimsFromProxyRequest,
		// which sources the torii credential from X-Torii-Authorization / the
		// access cookie instead.
		stripClientHeaders(req.Header)
		stripCookies(req, auth.AccessCookie, auth.RefreshCookie, auth.SessionCookie)

		// ReverseProxy strips hop-by-hop headers AFTER the director runs, and
		// that pass deletes every header named in the request's Connection
		// token list. Left alone, a client sending
		// "Connection: keep-alive, X-Torii-User, X-Torii-Signature" would
		// delete torii's identity assertions and the per-service credential
		// overlay on their way upstream — turning an authorized request into an
		// anonymous or unsigned one. The client can only delete, not forge, but
		// an upstream that trusts the absence of the headers is escalated to,
		// and disabling HMAC signing unilaterally defeats the point of it. So
		// Connection is set to exactly what torii intends and nothing else;
		// ReverseProxy re-derives it for confirmed upgrades either way.
		if upgrade {
			req.Header.Set("Connection", "Upgrade")
		} else {
			req.Header.Del("Connection")
		}

		issuedAt := strconv.FormatInt(time.Now().Unix(), 10)
		roles := strings.Join(ident.Roles, ",")
		principal := ident.PrincipalType
		if principal == "" {
			principal = auth.PrincipalUser
		}
		req.Header.Set("X-Torii-User", ident.UserID)
		req.Header.Set("X-Torii-Username", ident.Username)
		if ident.Email != "" {
			req.Header.Set("X-Torii-Email", ident.Email)
		}
		req.Header.Set("X-Torii-Roles", roles)
		req.Header.Set("X-Torii-Issued-At", issuedAt)
		req.Header.Set("X-Torii-Principal-Type", principal)

		if len(svc.SigningSecret) > 0 {
			mac := hmac.New(sha256.New, svc.SigningSecret)
			mac.Write([]byte(signaturePayload(ident.UserID, ident.Username, ident.Email, roles, issuedAt, principal)))
			req.Header.Set("X-Torii-Signature", hex.EncodeToString(mac.Sum(nil)))
		}

		for k, v := range svc.Headers {
			req.Header.Set(k, v)
		}
	}
	rp.ModifyResponse = func(resp *http.Response) error {
		stripUpstreamAuthCookies(resp.Header)
		if upgrade && resp.StatusCode == http.StatusSwitchingProtocols {
			// The upstream confirmed the protocol switch, so from here the
			// connection is a long-lived bidirectional stream that no read or
			// write deadline can survive. ReverseProxy calls ModifyResponse
			// before it hands the hijacked connection over.
			SetDeadlines(c.Response(), 0, 0)
			return nil
		}
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

// signaturePayload builds the string covered by X-Torii-Signature.
//
// Each field is length-prefixed rather than joined with a delimiter. Joining on
// "|" was not an injective encoding: nothing escaped or bounded the fields, and
// emailRe permitted "|" inside the email, so distinct identities could in
// principle serialize to the same payload and share a signature. The leading
// fixed-width UUID happened to make a cross-user collision unconstructible, but
// that is an accident of the field order rather than a property of the format —
// and the format is what an upstream has to reimplement to verify.
//
// UPSTREAM CONTRACT: payload = concat("<len(field)>:<field>") over
// user_id, username, email, roles, issued_at, principal_type — in that order,
// with byte lengths, and every field present even when empty. Changing the field
// set or order invalidates every upstream verifier.
func signaturePayload(userID, username, email, roles, issuedAt, principalType string) string {
	var b strings.Builder
	for _, f := range []string{userID, username, email, roles, issuedAt, principalType} {
		b.WriteString(strconv.Itoa(len(f)))
		b.WriteByte(':')
		b.WriteString(f)
	}
	return b.String()
}

// isUpgradeRequest reports whether the request is asking to switch protocols
// (e.g. a WebSocket handshake), which the reverse proxy serves by hijacking
// the connection for long-lived streaming. This is a client claim, not a fact:
// only a 101 from the upstream confirms it.
func isUpgradeRequest(r *http.Request) bool {
	return r.Header.Get("Upgrade") != "" ||
		strings.Contains(strings.ToLower(r.Header.Get("Connection")), "upgrade")
}

const (
	// upgradeHandshakeWindow bounds how long an unconfirmed upgrade may hold a
	// connection. A WebSocket handshake is one round trip; this only has to be
	// generous enough for a slow upstream to answer 101.
	upgradeHandshakeWindow = 30 * time.Second

	// maxUpgradesPerUser caps concurrent hijacked connections per account, so
	// one caller can't exhaust goroutines and file descriptors by opening
	// streams that legitimately have no deadline. Sized for a user with many
	// tabs open against several services at once.
	maxUpgradesPerUser = 32
)

// handshakeWindow bounds a deadline for a claimed-but-unconfirmed upgrade. A
// service configured with no limit (0) still gets the cap, and a service with a
// tighter limit keeps it.
func handshakeWindow(configured time.Duration) time.Duration {
	if configured <= 0 || configured > upgradeHandshakeWindow {
		return upgradeHandshakeWindow
	}
	return configured
}

var upgradeSlots = struct {
	sync.Mutex
	open map[string]int
}{open: make(map[string]int)}

// acquireUpgradeSlot reserves one of userID's concurrent-upgrade slots. The
// returned func releases it and must be called when the request finishes.
func acquireUpgradeSlot(userID string) (func(), bool) {
	upgradeSlots.Lock()
	defer upgradeSlots.Unlock()
	if upgradeSlots.open[userID] >= maxUpgradesPerUser {
		return nil, false
	}
	upgradeSlots.open[userID]++
	return func() {
		upgradeSlots.Lock()
		defer upgradeSlots.Unlock()
		if upgradeSlots.open[userID] <= 1 {
			delete(upgradeSlots.open, userID)
			return
		}
		upgradeSlots.open[userID]--
	}, true
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

// toriiReservedCookies are the cookie names torii sets itself. Nothing behind
// the proxy has any business defining them.
var toriiReservedCookies = map[string]struct{}{
	auth.AccessCookie:  {},
	auth.RefreshCookie: {},
	auth.SessionCookie: {},
}

// stripUpstreamAuthCookies drops Set-Cookie headers that would define one of
// torii's own session cookies. Cookie stripping is otherwise request-direction
// only, which left a session-fixation path open: torii's cookies are host-only
// by design, but a hostile or XSS'd upstream on a.corp.com can answer with
// "Set-Cookie: access_token=<attacker's token>; Domain=.corp.com; Path=/" and
// have it apply on sibling service host b.corp.com, where the victim usually
// has no cookie of their own yet. ClearAuthCookies emits no Domain, so the
// victim cannot log out of the tossed cookie either.
//
// Names are matched exactly: cookie names are case-sensitive, so a differently
// cased spelling is a different cookie to the browser and cannot shadow ours.
func stripUpstreamAuthCookies(h http.Header) {
	values := h.Values("Set-Cookie")
	if len(values) == 0 {
		return
	}
	kept := make([]string, 0, len(values))
	for _, v := range values {
		name := v
		if eq := strings.IndexByte(v, '='); eq >= 0 {
			name = v[:eq]
		}
		if _, reserved := toriiReservedCookies[strings.TrimSpace(name)]; reserved {
			continue
		}
		kept = append(kept, v)
	}
	if len(kept) == len(values) {
		return
	}
	h.Del("Set-Cookie")
	for _, v := range kept {
		h.Add("Set-Cookie", v)
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
