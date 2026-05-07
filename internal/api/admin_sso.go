package api

import (
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"

	"sanmon/internal/db"
)

var ssoSlugRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?$`)

type ssoProviderDTO struct {
	ID           string `json:"id"`
	Slug         string `json:"slug"`
	Name         string `json:"name"`
	IssuerURL    string `json:"issuer_url"`
	ClientID     string `json:"client_id"`
	HasSecret    bool   `json:"has_secret"`
	Scopes       string `json:"scopes"`
	Enabled      bool   `json:"enabled"`
	AllowSignup  bool   `json:"allow_signup"`
	LinkByEmail  bool   `json:"link_by_email"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

type adminSSOListResp struct {
	pageMeta
	Items []ssoProviderDTO `json:"items"`
}

type adminSSOReq struct {
	Slug         string  `json:"slug"`
	Name         string  `json:"name"`
	IssuerURL    string  `json:"issuer_url"`
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret"`
	Scopes       string  `json:"scopes"`
	Enabled      *bool   `json:"enabled"`
	AllowSignup  *bool   `json:"allow_signup"`
	LinkByEmail  *bool   `json:"link_by_email"`
}

func toSSOProviderDTO(p db.SsoProvider) ssoProviderDTO {
	return ssoProviderDTO{
		ID:          p.ID.String(),
		Slug:        p.Slug,
		Name:        p.Name,
		IssuerURL:   p.IssuerUrl,
		ClientID:    p.ClientID,
		HasSecret:   p.ClientSecret != "",
		Scopes:      p.Scopes,
		Enabled:     p.Enabled,
		AllowSignup: p.AllowSignup,
		LinkByEmail: p.LinkByEmail,
		CreatedAt:   tsString(p.CreatedAt),
		UpdatedAt:   tsString(p.UpdatedAt),
	}
}

func validateSSOReq(req *adminSSOReq) string {
	req.Slug = strings.ToLower(strings.TrimSpace(req.Slug))
	req.Name = strings.TrimSpace(req.Name)
	req.IssuerURL = strings.TrimSpace(req.IssuerURL)
	req.ClientID = strings.TrimSpace(req.ClientID)
	req.Scopes = strings.TrimSpace(req.Scopes)

	if !ssoSlugRe.MatchString(req.Slug) || len(req.Slug) > 64 {
		return "slug must be lowercase alphanumeric with optional dashes (1-64 chars)"
	}
	if n := len(req.Name); n < 1 || n > 128 {
		return "name must be 1-128 chars"
	}
	u, err := url.Parse(req.IssuerURL)
	if err != nil || u.Host == "" {
		return "issuer_url must be a valid http(s) URL"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "issuer_url scheme must be http or https"
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "issuer_url must not contain a query or fragment"
	}
	req.IssuerURL = strings.TrimRight(req.IssuerURL, "/")
	if req.ClientID == "" {
		return "client_id is required"
	}
	if req.Scopes == "" {
		req.Scopes = "openid email profile"
	}
	hasOpenID := false
	for _, s := range strings.Fields(req.Scopes) {
		if s == "openid" {
			hasOpenID = true
			break
		}
	}
	if !hasOpenID {
		return "scopes must include openid"
	}
	return ""
}

func (h *authHandlers) adminListSSO(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListSSOProviders(ctx, db.ListSSOProvidersParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list providers"})
	}
	total, err := h.q.CountSSOProviders(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count providers"})
	}
	items := make([]ssoProviderDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, toSSOProviderDTO(r))
	}
	return c.JSON(http.StatusOK, adminSSOListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminCreateSSO(c *echo.Context) error {
	var req adminSSOReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if msg := validateSSOReq(&req); msg != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}
	if req.ClientSecret == nil || strings.TrimSpace(*req.ClientSecret) == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "client_secret is required"})
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	allowSignup := false
	if req.AllowSignup != nil {
		allowSignup = *req.AllowSignup
	}
	linkByEmail := true
	if req.LinkByEmail != nil {
		linkByEmail = *req.LinkByEmail
	}

	p, err := h.q.CreateSSOProvider(c.Request().Context(), db.CreateSSOProviderParams{
		Slug:         req.Slug,
		Name:         req.Name,
		IssuerUrl:    req.IssuerURL,
		ClientID:     req.ClientID,
		ClientSecret: strings.TrimSpace(*req.ClientSecret),
		Scopes:       req.Scopes,
		Enabled:      enabled,
		AllowSignup:  allowSignup,
		LinkByEmail:  linkByEmail,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "slug already in use"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create provider"})
	}
	return c.JSON(http.StatusCreated, toSSOProviderDTO(p))
}

func (h *authHandlers) adminUpdateSSO(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req adminSSOReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if msg := validateSSOReq(&req); msg != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}

	ctx := c.Request().Context()
	existing, err := h.q.GetSSOProviderByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	secret := existing.ClientSecret
	if req.ClientSecret != nil && strings.TrimSpace(*req.ClientSecret) != "" {
		secret = strings.TrimSpace(*req.ClientSecret)
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	allowSignup := existing.AllowSignup
	if req.AllowSignup != nil {
		allowSignup = *req.AllowSignup
	}
	linkByEmail := existing.LinkByEmail
	if req.LinkByEmail != nil {
		linkByEmail = *req.LinkByEmail
	}

	p, err := h.q.UpdateSSOProvider(ctx, db.UpdateSSOProviderParams{
		ID:           id,
		Slug:         req.Slug,
		Name:         req.Name,
		IssuerUrl:    req.IssuerURL,
		ClientID:     req.ClientID,
		ClientSecret: secret,
		Scopes:       req.Scopes,
		Enabled:      enabled,
		AllowSignup:  allowSignup,
		LinkByEmail:  linkByEmail,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "slug already in use"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not update provider"})
	}
	return c.JSON(http.StatusOK, toSSOProviderDTO(p))
}

func (h *authHandlers) adminDeleteSSO(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.q.DeleteSSOProvider(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete provider"})
	}
	return c.NoContent(http.StatusNoContent)
}
