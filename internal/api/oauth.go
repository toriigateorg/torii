package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"
	"golang.org/x/oauth2"

	"sanmon/internal/db"
)

const (
	ssoStateCookie = "sso_state"
	ssoNonceCookie = "sso_nonce"
	ssoCookiePath  = "/api/v1/oauth/"
	ssoCookieTTL   = 10 * time.Minute
)

type cachedOIDCProvider struct {
	updatedAt time.Time
	provider  *oidc.Provider
}

var oidcProviderCache sync.Map // map[uuid.UUID]*cachedOIDCProvider

func (h *authHandlers) oidcProviderFor(ctx context.Context, p db.SsoProvider) (*oidc.Provider, error) {
	if v, ok := oidcProviderCache.Load(p.ID); ok {
		c := v.(*cachedOIDCProvider)
		if c.updatedAt.Equal(p.UpdatedAt.Time) {
			return c.provider, nil
		}
	}
	prov, err := oidc.NewProvider(ctx, p.IssuerUrl)
	if err != nil {
		return nil, err
	}
	oidcProviderCache.Store(p.ID, &cachedOIDCProvider{updatedAt: p.UpdatedAt.Time, provider: prov})
	return prov, nil
}

func (h *authHandlers) oauthRedirectURL(slug string) string {
	scheme := "http"
	if h.cfg.IsProd() {
		scheme = "https"
	}
	return scheme + "://" + h.cfg.SanmonURL + "/api/v1/oauth/" + slug + "/callback"
}

func (h *authHandlers) oauth2Config(prov *oidc.Provider, p db.SsoProvider) *oauth2.Config {
	scopes := strings.Fields(p.Scopes)
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	return &oauth2.Config{
		ClientID:     p.ClientID,
		ClientSecret: p.ClientSecret,
		Endpoint:     prov.Endpoint(),
		RedirectURL:  h.oauthRedirectURL(p.Slug),
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

	p, err := h.q.GetSSOProviderBySlug(ctx, slug)
	if err != nil || !p.Enabled {
		return c.Redirect(http.StatusFound, "/signin?error=sso_unknown")
	}
	prov, err := h.oidcProviderFor(ctx, p)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_discovery")
	}
	state, err := randomB64(32)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_internal")
	}
	nonce, err := randomB64(32)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_internal")
	}
	h.setSSOTempCookie(c, ssoStateCookie, state)
	h.setSSOTempCookie(c, ssoNonceCookie, nonce)

	cfg := h.oauth2Config(prov, p)
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
	at := strings.IndexByte(email, '@')
	local := email
	if at >= 0 {
		local = email[:at]
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
	if err != nil || stateCookie.Value == "" || stateCookie.Value != c.QueryParam("state") {
		return c.Redirect(http.StatusFound, "/signin?error=sso_state")
	}
	nonceCookie, err := c.Cookie(ssoNonceCookie)
	h.clearSSOTempCookie(c, ssoNonceCookie)
	if err != nil || nonceCookie.Value == "" {
		return c.Redirect(http.StatusFound, "/signin?error=sso_state")
	}

	if errParam := c.QueryParam("error"); errParam != "" {
		return c.Redirect(http.StatusFound, "/signin?error=sso_denied")
	}
	code := c.QueryParam("code")
	if code == "" {
		return c.Redirect(http.StatusFound, "/signin?error=sso_state")
	}

	p, err := h.q.GetSSOProviderBySlug(ctx, slug)
	if err != nil || !p.Enabled {
		return c.Redirect(http.StatusFound, "/signin?error=sso_unknown")
	}
	prov, err := h.oidcProviderFor(ctx, p)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_discovery")
	}
	cfg := h.oauth2Config(prov, p)

	tok, err := cfg.Exchange(ctx, code)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_exchange")
	}
	rawIDToken, ok := tok.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return c.Redirect(http.StatusFound, "/signin?error=sso_no_id_token")
	}
	verifier := prov.Verifier(&oidc.Config{ClientID: p.ClientID})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_verify")
	}
	if idToken.Nonce != nonceCookie.Value {
		return c.Redirect(http.StatusFound, "/signin?error=sso_state")
	}
	var claims oidcUserClaims
	if err := idToken.Claims(&claims); err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_claims")
	}
	if claims.Sub == "" {
		return c.Redirect(http.StatusFound, "/signin?error=sso_claims")
	}
	email := strings.ToLower(strings.TrimSpace(claims.Email))

	user, err := h.findOrCreateSSOUser(ctx, p, claims, email)
	if err != nil {
		return c.Redirect(http.StatusFound, "/signin?error="+err.Error())
	}

	if _, _, _, err := h.issueSession(ctx, c, user); err != nil {
		return c.Redirect(http.StatusFound, "/signin?error=sso_internal")
	}
	return c.Redirect(http.StatusFound, "/dashboard")
}

func (h *authHandlers) findOrCreateSSOUser(ctx context.Context, p db.SsoProvider, claims oidcUserClaims, email string) (db.User, error) {
	if ident, err := h.q.GetUserIdentity(ctx, db.GetUserIdentityParams{ProviderID: p.ID, Subject: claims.Sub}); err == nil {
		user, err := h.q.GetUserByID(ctx, ident.UserID)
		if err != nil {
			return db.User{}, errors.New("sso_internal")
		}
		return user, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return db.User{}, errors.New("sso_internal")
	}

	if p.LinkByEmail && claims.EmailVerified && email != "" {
		user, err := h.q.GetUserByUsernameOrEmail(ctx, email)
		if err == nil {
			if _, err := h.q.CreateUserIdentity(ctx, db.CreateUserIdentityParams{
				ProviderID: p.ID, Subject: claims.Sub, UserID: user.ID, Email: email,
			}); err != nil {
				return db.User{}, errors.New("sso_internal")
			}
			return user, nil
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return db.User{}, errors.New("sso_internal")
		}
	}

	if !p.AllowSignup {
		return db.User{}, errors.New("sso_no_account")
	}
	if email == "" {
		return db.User{}, errors.New("sso_no_email")
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return db.User{}, errors.New("sso_internal")
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
		return db.User{}, errors.New("sso_internal")
	}
	if user.ID == uuid.Nil {
		return db.User{}, errors.New("sso_internal")
	}

	allRole, err := qtx.GetRoleByName(ctx, "all")
	if err != nil {
		return db.User{}, errors.New("sso_internal")
	}
	if err := qtx.AssignUserRole(ctx, db.AssignUserRoleParams{UserID: user.ID, RoleID: allRole.ID}); err != nil {
		return db.User{}, errors.New("sso_internal")
	}
	if _, err := qtx.CreateUserIdentity(ctx, db.CreateUserIdentityParams{
		ProviderID: p.ID, Subject: claims.Sub, UserID: user.ID, Email: email,
	}); err != nil {
		return db.User{}, errors.New("sso_internal")
	}
	if err := tx.Commit(ctx); err != nil {
		return db.User{}, errors.New("sso_internal")
	}
	return user, nil
}

