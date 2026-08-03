package api

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
	"torii/internal/netutil"
)

const (
	ssoStateCookie      = "sso_state"
	ssoNonceCookie      = "sso_nonce"
	ssoReturnHostCookie = "sso_return_host"
	ssoCookiePath       = "/_torii/api/v1/oauth/"
	ssoCookieTTL        = 10 * time.Minute
)

type cachedOIDCProvider struct {
	updatedAt time.Time
	provider  *oidc.Provider
}

var oidcProviderCache sync.Map // map[uuid.UUID]*cachedOIDCProvider

const (
	// oidcRequestTimeout bounds a single discovery / token / JWKS request.
	oidcRequestTimeout = 15 * time.Second
	// oidcMaxResponseBytes caps a response body from an identity provider.
	// go-oidc does an unbounded io.ReadAll on the discovery document, which
	// without this is a memory-amplification trigger reachable from the
	// unauthenticated /oauth/:slug/start once a hostile provider is registered.
	// Discovery documents and JWKS are a few KB.
	oidcMaxResponseBytes = 1 << 20
	// oidcMaxRedirects bounds the redirect chain an IdP can lead torii down.
	oidcMaxRedirects = 3
)

// limitedBodyTransport caps every response body it returns. Sits above the
// SSRF-guarded transport so both protections apply to the same requests.
type limitedBodyTransport struct {
	base  http.RoundTripper
	limit int64
}

func (t limitedBodyTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	resp.Body = struct {
		io.Reader
		io.Closer
	}{io.LimitReader(resp.Body, t.limit), resp.Body}
	return resp, nil
}

var oidcClientOnce sync.Once
var oidcClient *http.Client

// oidcHTTPClient is the only client torii uses to talk to an identity provider.
// http.DefaultClient is not safe here: the write-time IsSafeUpstreamHost check
// in adminCreateSSO validates the issuer host once and is never re-applied, so
// a registered issuer whose discovery document answers
// "302 Location: http://169.254.169.254/…" would have torii fetch cloud
// metadata — and discovery also supplies token_endpoint and jwks_uri, which
// torii fetches directly. The Control hook runs after DNS resolution on every
// dial, including each redirect hop and every later JWKS refresh, so it closes
// both the redirect path and the DNS-rebinding window. Mirrors the guard the
// proxy transports already carry (see proxy.ServiceCache.refreshLocked); the
// privilege delta was that sso.create escaped it while services.create did not.
func (h *authHandlers) oidcHTTPClient() *http.Client {
	oidcClientOnce.Do(func() {
		blockLoopback := h.cfg.BlockLoopbackUpstreams
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.MaxResponseHeaderBytes = 64 << 10
		tr.DialContext = (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
			Control: func(_, address string, _ syscall.RawConn) error {
				return netutil.IsSafeUpstreamAddr(address, blockLoopback)
			},
		}).DialContext
		oidcClient = &http.Client{
			Transport: limitedBodyTransport{base: tr, limit: oidcMaxResponseBytes},
			Timeout:   oidcRequestTimeout,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= oidcMaxRedirects {
					return errors.New("too many redirects from identity provider")
				}
				if req.URL.Scheme != "https" && req.URL.Scheme != "http" {
					return errors.New("unsupported redirect scheme " + req.URL.Scheme)
				}
				return nil
			},
		}
	})
	return oidcClient
}

// oidcContext attaches the hardened client so go-oidc and oauth2 use it for
// discovery, the JWKS fetch, and the code exchange.
func (h *authHandlers) oidcContext(ctx context.Context) context.Context {
	return oidc.ClientContext(ctx, h.oidcHTTPClient())
}

func (h *authHandlers) oidcProviderFor(ctx context.Context, p db.SsoProvider) (*oidc.Provider, error) {
	if v, ok := oidcProviderCache.Load(p.ID); ok {
		c := v.(*cachedOIDCProvider)
		if c.updatedAt.Equal(p.UpdatedAt.Time) {
			return c.provider, nil
		}
	}
	prov, err := oidc.NewProvider(h.oidcContext(ctx), p.IssuerUrl)
	if err != nil {
		return nil, err
	}
	oidcProviderCache.Store(p.ID, &cachedOIDCProvider{updatedAt: p.UpdatedAt.Time, provider: prov})
	return prov, nil
}

func (h *authHandlers) oauthRedirectURL(_ *echo.Context, slug string) string {
	// Build the OIDC redirect_uri purely from configured values. Reading
	// X-Forwarded-Host / X-Forwarded-Proto from the inbound request would
	// let an attacker override the redirect_uri to evil.com simply by
	// setting the header on /oauth/<slug>/start — IdPs that allow wildcard
	// redirect registration would then bounce the user (and the code) to
	// the attacker.
	scheme := "https"
	if !h.cfg.IsProd() {
		scheme = "http"
	}
	return scheme + "://" + h.cfg.ToriiURL + "/_torii/api/v1/oauth/" + slug + "/callback"
}

func (h *authHandlers) oauth2Config(c *echo.Context, prov *oidc.Provider, p db.SsoProvider) *oauth2.Config {
	scopes := strings.Fields(p.Scopes)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  h.oauthRedirectURL(c, p.Slug),
		Scopes:       scopes,
	}
}

type publicProviderDTO struct {
	Slug string `json:"slug"`
	Name string `json:"name"`
}

func (h *authHandlers) publicAuthConfig(c *echo.Context) error {
	ctx := c.Request().Context()
	rows, _ := h.q.ListEnabledSSOProviders(ctx)
	items := make([]publicProviderDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, publicProviderDTO{Slug: r.Slug, Name: r.Name})
	}
	return c.JSON(http.StatusOK, map[string]any{
		"providers":      items,
		"signup_enabled": h.getBoolSetting(ctx, settingSignupEnabled, true),
	})
}

func (h *authHandlers) publicListProviders(c *echo.Context) error {
	rows, err := h.q.ListEnabledSSOProviders(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list providers"})
	}
	items := make([]publicProviderDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, publicProviderDTO{Slug: r.Slug, Name: r.Name})
	}
	return c.JSON(http.StatusOK, map[string]any{"items": items})
}

func randomB64(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func (h *authHandlers) setSSOTempCookie(c *echo.Context, name, value string) {
	c.SetCookie(&http.Cookie{
		Name:     name,
		Value:    value,
		Path:     ssoCookiePath,
		Expires:  time.Now().Add(ssoCookieTTL),
		MaxAge:   int(ssoCookieTTL.Seconds()),
		HttpOnly: true,
		Secure:   h.cfg.IsProd(),
		SameSite: http.SameSiteLaxMode,
	})
}

// isKnownServiceHost reports whether host appears in the proxy's service
// cache. Used to gate cross-host SSO handoff so an attacker can't direct a
// freshly-issued handoff token at an arbitrary destination.
func (h *authHandlers) isKnownServiceHost(ctx context.Context, host string) bool {
	if h.cache == nil || host == "" {
		return false
	}
	_, ok := h.cache.Lookup(ctx, host)
	return ok
}

func (h *authHandlers) clearSSOTempCookie(c *echo.Context, name string) {
	c.SetCookie(&http.Cookie{
		Name:     name,
		Value:    "",
		Path:     ssoCookiePath,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   h.cfg.IsProd(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (h *authHandlers) oauthStart(c *echo.Context) error {
	slug := c.Param("slug")
	ctx := c.Request().Context()

	// SSO state/nonce cookies are scoped to whichever host /start runs on,
	// but the IdP's registered redirect_uri is fixed to cfg.ToriiURL. If a
	// user clicks "Sign in with X" from a service domain (or any non-torii
	// alias) the cookies would be set on the service host and the callback
	// — which always lands on torii — wouldn't see them. Bounce through
	// torii's /start first so cookies and callback share an origin.
	if !h.cfg.IsToriiHost(c.Request().Host) {
		scheme := "https"
		if !h.cfg.IsProd() {
			scheme = "http"
		}
		// Tag the bounce so /start on torii knows the user originated on a
		// non-torii host and should be handed back there post-SSO.
		q := c.Request().URL.Query()
		if q.Get("return_to_host") == "" {
			q.Set("return_to_host", c.Request().Host)
		}
		target := scheme + "://" + h.cfg.ToriiURL + c.Request().URL.Path + "?" + q.Encode()
		return c.Redirect(http.StatusFound, target)
	}

	// Originating host carried over from the cross-host bounce above.
	// Persist it in a cookie so /callback (which lands here on torii) can
	// recover it after the IdP round-trip. Only honor known service hosts
	// — falling back to torii otherwise — so an attacker can't use the
	// bounce to land users on an arbitrary post-SSO destination.
	if rh := c.QueryParam("return_to_host"); rh != "" {
		if h.isKnownServiceHost(ctx, rh) {
			h.setSSOTempCookie(c, ssoReturnHostCookie, rh)
		} else {
			h.clearSSOTempCookie(c, ssoReturnHostCookie)
		}
	} else {
		h.clearSSOTempCookie(c, ssoReturnHostCookie)
	}

	p, err := h.q.GetSSOProviderBySlug(ctx, slug)
	if err != nil || !p.Enabled {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_unknown")
	}
	prov, err := h.oidcProviderFor(ctx, p)
	if err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_discovery")
	}
	state, err := randomB64(32)
	if err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_internal")
	}
	nonce, err := randomB64(32)
	if err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_internal")
	}
	h.setSSOTempCookie(c, ssoStateCookie, state)
	h.setSSOTempCookie(c, ssoNonceCookie, nonce)

	cfg := h.oauth2Config(c, prov, p)
	return c.Redirect(http.StatusFound, cfg.AuthCodeURL(state, oidc.Nonce(nonce)))
}

type oidcUserClaims struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
}

var nonUsernameCharsRe = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

func usernameFromEmail(email string) string {
	// Lowercased here rather than relying on the caller: usernames carry a
	// lowercase CHECK constraint (migration 0016), so a mixed-case derivation
	// would fail the insert and break SSO signin outright.
	at := strings.IndexByte(email, '@')
	local := strings.ToLower(email)
	if at >= 0 {
		local = local[:at]
	}
	local = nonUsernameCharsRe.ReplaceAllString(local, "-")
	local = strings.Trim(local, "-_.")
	if len(local) < 3 {
		local = "user-" + local
	}
	if len(local) > 56 {
		local = local[:56]
	}
	return local
}

func (h *authHandlers) oauthCallback(c *echo.Context) error {
	slug := c.Param("slug")
	ctx := c.Request().Context()

	stateCookie, err := c.Cookie(ssoStateCookie)
	h.clearSSOTempCookie(c, ssoStateCookie)
	if err != nil || stateCookie.Value == "" {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_state")
	}
	// Constant-time comparison: defensive even though both sides are
	// server-issued, since the query value comes back through the IdP and
	// the user's browser. Avoids any timing channel that future logging
	// or framework changes might accidentally expose.
	if subtle.ConstantTimeCompare([]byte(stateCookie.Value), []byte(c.QueryParam("state"))) != 1 {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_state")
	}
	nonceCookie, err := c.Cookie(ssoNonceCookie)
	h.clearSSOTempCookie(c, ssoNonceCookie)
	if err != nil || nonceCookie.Value == "" {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_state")
	}

	if errParam := c.QueryParam("error"); errParam != "" {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_denied")
	}
	code := c.QueryParam("code")
	if code == "" {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_state")
	}

	p, err := h.q.GetSSOProviderBySlug(ctx, slug)
	if err != nil || !p.Enabled {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_unknown")
	}
	prov, err := h.oidcProviderFor(ctx, p)
	if err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_discovery")
	}
	cfg := h.oauth2Config(c, prov, p)

	// Both of these reach the provider over the network — the token endpoint and
	// the JWKS endpoint, whose URLs come from the discovery document — so both
	// carry the hardened client rather than http.DefaultClient.
	tok, err := cfg.Exchange(h.oidcContext(ctx), code)
	if err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_exchange")
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_no_id_token")
	}
	verifier := prov.Verifier(&oidc.Config{ClientID: p.ClientID})
	idToken, err := verifier.Verify(h.oidcContext(ctx), rawIDToken)
	if err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_verify")
	}
	if idToken.Nonce != nonceCookie.Value {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_state")
	}
	var claims oidcUserClaims
	if err := idToken.Claims(&claims); err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_claims")
	}
	if claims.Sub == "" {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_claims")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))

	user, outcome, err := h.findOrCreateSSOUser(ctx, p, claims, email)
	if err != nil {
		h.auditor.LogFromEcho(c, audit.Event{
			EventType: audit.EventSigninFailed,
			Metadata: map[string]any{
				"identifier_hash": hashIdentifier(email),
				"reason":          "sso_" + err.Error(),
				"provider":        p.Slug,
			},
		})
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_"+err.Error())
	}

	if _, _, _, err := h.issueSession(ctx, c, user); err != nil {
		return c.Redirect(http.StatusFound, "/_torii/signin?error=sso_internal")
	}
	uid := user.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:     audit.EventSigninSSO,
		ActorUserID:   &uid,
		ActorUsername: user.Username,
		TargetType:    audit.TargetUser,
		TargetID:      &uid,
		TargetName:    user.Username,
		Metadata: map[string]any{
			"provider":       p.Slug,
			"provider_name":  p.Name,
			"outcome":        outcome,
			"email":          email,
			"email_verified": claims.EmailVerified,
		},
	})

	// If the user originated on a service host, hand them back there with
	// a one-shot signed token so they end up authenticated on the host
	// they came from rather than stranded on torii's dashboard. The cookie
	// was set in /start; isKnownServiceHost was already enforced there.
	//
	// The token rides in the URL fragment, not the query: fragments are
	// never sent to a server, never logged, and never appear in a Referer.
	// The handoff SPA page on the service host reads it out of the hash and
	// POSTs it to /sso_handoff. Carrying it in the query would leak the live
	// token to the upstream via the Referer of the post-handoff navigation.
	if rh, err := c.Cookie(ssoReturnHostCookie); err == nil && rh.Value != "" {
		h.clearSSOTempCookie(c, ssoReturnHostCookie)
		if h.isKnownServiceHost(ctx, rh.Value) {
			tok, err := auth.IssueHandoffToken(user.ID, rh.Value, h.cfg.JWTSecret)
			if err == nil {
				scheme := "https"
				if !h.cfg.IsProd() {
					scheme = "http"
				}
				return c.Redirect(http.StatusFound, scheme+"://"+rh.Value+"/_torii/handoff#token="+tok)
			}
		}
	}
	return c.Redirect(http.StatusFound, "/_torii/dashboard")
}

// ssoHandoff is the cross-host counterpart to oauthCallback: it runs on a
// service domain after SSO completed on torii and exchanges the signed handoff
// token for a fresh session on this host (cookies are per-host so the torii
// session can't be seen here). The token is bound to this host, expires in
// 30s, and is single-use.
//
// It takes the token in a POST body rather than the query string so it never
// lands in a URL — from there it would leak to the upstream through the Referer
// of the follow-up navigation, and torii deliberately does not rewrite proxied
// response headers. The caller (client/app/pages/handoff.vue) hard-navigates
// to "/" afterwards so the Go dispatch re-evaluates with the new cookies.
func (h *authHandlers) ssoHandoff(c *echo.Context) error {
	c.Response().Header().Set("Referrer-Policy", "no-referrer")
	c.Response().Header().Set("Cache-Control", "no-store")

	var req struct {
		Token string `json:"token"`
	}
	if err := c.Bind(&req); err != nil || req.Token == "" {
		return handoffError(c)
	}
	claims, err := auth.ParseHandoffToken(req.Token, h.cfg.JWTSecret)
	if err != nil {
		return handoffError(c)
	}
	if !sameNormalizedHost(claims.TargetHost, c.Request().Host) {
		return handoffError(c)
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return handoffError(c)
	}
	if claims.ExpiresAt == nil || !auth.ConsumeHandoffJTI(claims.ID, claims.ExpiresAt.Time) {
		return handoffError(c)
	}
	user, err := h.q.GetUserByID(c.Request().Context(), uid)
	if err != nil {
		return handoffError(c)
	}
	if _, _, _, err := h.issueSession(c.Request().Context(), c, user); err != nil {
		return handoffError(c)
	}
	return c.JSON(http.StatusOK, map[string]bool{"ok": true})
}

func handoffError(c *echo.Context) error {
	return c.JSON(http.StatusUnauthorized, map[string]string{"error": "handoff"})
}

func sameNormalizedHost(a, b string) bool {
	return strings.EqualFold(strings.TrimSuffix(strings.TrimSuffix(a, ":443"), ":80"),
		strings.TrimSuffix(strings.TrimSuffix(b, ":443"), ":80"))
}

func (h *authHandlers) findOrCreateSSOUser(ctx context.Context, p db.SsoProvider, claims oidcUserClaims, email string) (db.User, string, error) {
	if ident, err := h.q.GetUserIdentity(ctx, db.GetUserIdentityParams{ProviderID: p.ID, Subject: claims.Sub}); err == nil {
		user, err := h.q.GetUserByID(ctx, ident.UserID)
		if err != nil {
			return db.User{}, "", errors.New("internal")
		}
		return user, "existing_identity", nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, "", errors.New("internal")
	}

	if p.LinkByEmail && claims.EmailVerified && email != "" {
		user, err := h.q.GetUserByUsernameOrEmail(ctx, email)
		if err == nil {
			if _, err := h.q.CreateUserIdentity(ctx, db.CreateUserIdentityParams{
				ProviderID: p.ID, Subject: claims.Sub, UserID: user.ID, Email: email,
			}); err != nil {
				return db.User{}, "", errors.New("internal")
			}
			return user, "linked_by_email", nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, "", errors.New("internal")
		}
	}

	if !p.AllowSignup {
		return db.User{}, "", errors.New("no_account")
	}
	if email == "" {
		return db.User{}, "", errors.New("no_email")
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return db.User{}, "", errors.New("internal")
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)

	base := usernameFromEmail(email)
	username := base
	var user db.User
	for i := 0; i < 6; i++ {
		var err error
		user, err = qtx.CreateUser(ctx, db.CreateUserParams{
			Username:     username,
			Email:        email,
			FirstName:    claims.GivenName,
			LastName:     claims.FamilyName,
			PasswordHash: pgtype.Text{Valid: false},
		})
		if err == nil {
			break
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			suffix, _ := randomB64(3)
			username = base + "-" + strings.ToLower(suffix)
			if len(username) > 64 {
				username = username[:64]
			}
			continue
		}
		return db.User{}, "", errors.New("internal")
	}
	if user.ID == uuid.Nil {
		return db.User{}, "", errors.New("internal")
	}

	allRole, err := qtx.GetRoleByName(ctx, "all")
	if err != nil {
		return db.User{}, "", errors.New("internal")
	}
	if err := qtx.AssignUserRole(ctx, db.AssignUserRoleParams{UserID: user.ID, RoleID: allRole.ID}); err != nil {
		return db.User{}, "", errors.New("internal")
	}
	if _, err := qtx.CreateUserIdentity(ctx, db.CreateUserIdentityParams{
		ProviderID: p.ID, Subject: claims.Sub, UserID: user.ID, Email: email,
	}); err != nil {
		return db.User{}, "", errors.New("internal")
	}
	if err := tx.Commit(ctx); err != nil {
		return db.User{}, "", errors.New("internal")
	}
	return user, "created", nil
}

