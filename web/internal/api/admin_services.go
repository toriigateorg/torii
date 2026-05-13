package api

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/db"
	"torii/internal/netutil"
)

var (
	domainRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]+)?$`)
	headerNameRe = regexp.MustCompile(`^[A-Za-z0-9-]+$`)
)

// validateHeaderOverlay rejects per-service overlay entries that would
// corrupt request parsing or undermine torii's identity contract:
//   - header names with characters outside [A-Za-z0-9-] (parser quirks).
//   - X-Torii-* names: torii itself injects these (signed identity headers)
//     and the overlay is applied last, so allowing them here would let an
//     admin forge the user identity sent to upstreams that verify the HMAC.
//   - values containing CR/LF: classic HTTP request smuggling vector.
//
// Authorization, Cookie, Host, X-Forwarded-* and similar are intentionally
// NOT blocked — they're load-bearing for legitimate identity-aware-proxy
// configurations (e.g., setting a service-account Bearer for upstream apps
// that have their own auth, or pinning Host for SNI/virtual hosting).
func validateHeaderOverlay(headers map[string]string) string {
	for k, v := range headers {
		if !headerNameRe.MatchString(k) {
			return "header name must match [A-Za-z0-9-]+: " + k
		}
		if strings.HasPrefix(strings.ToLower(k), "x-torii-") {
			return "header name X-Torii-* is reserved for torii-signed identity assertions: " + k
		}
		if strings.ContainsAny(v, "\r\n") {
			return "header value must not contain CR or LF: " + k
		}
	}
	return ""
}

type serviceDTO struct {
	ID           string            `json:"id"`
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	ServiceURL   string            `json:"service_url"`
	Domain       string            `json:"domain"`
	Headers      map[string]string `json:"headers"`
	PreserveHost bool              `json:"preserve_host"`
	CreatedAt    string            `json:"created_at"`
	UpdatedAt    string            `json:"updated_at"`
}

type adminServiceListResp struct {
	pageMeta
	Items []serviceDTO `json:"items"`
}

type adminServiceReq struct {
	Title        string            `json:"title"`
	Description  string            `json:"description"`
	ServiceURL   string            `json:"service_url"`
	Domain       string            `json:"domain"`
	Headers      map[string]string `json:"headers"`
	PreserveHost bool              `json:"preserve_host"`
}

func toServiceDTO(s db.Service) serviceDTO {
	headers := map[string]string{}
	if len(s.Headers) > 0 {
		_ = json.Unmarshal(s.Headers, &headers)
	}
	return serviceDTO{
		ID:           s.ID.String(),
		Title:        s.Title,
		Description:  s.Description,
		ServiceURL:   s.ServiceUrl,
		Domain:       s.Domain,
		Headers:      headers,
		PreserveHost: s.PreserveHost,
		CreatedAt:    tsString(s.CreatedAt),
		UpdatedAt:    tsString(s.UpdatedAt),
	}
}

func (h *authHandlers) validateServiceReq(req *adminServiceReq) (headersJSON []byte, errMsg string) {
	req.Title = strings.TrimSpace(req.Title)
	req.Description = strings.TrimSpace(req.Description)
	req.ServiceURL = strings.TrimSpace(req.ServiceURL)
	req.Domain = strings.ToLower(strings.TrimSpace(req.Domain))

	if n := len(req.Title); n < 1 || n > 200 {
		return nil, "title must be 1-200 chars"
	}
	if len(req.Description) > 2000 {
		return nil, "description must be at most 2000 chars"
	}
	if !domainRe.MatchString(req.Domain) {
		return nil, "domain must be a hostname[:port], no scheme, no path"
	}
	u, err := url.Parse(req.ServiceURL)
	if err != nil || u.Host == "" {
		return nil, "service_url must be a valid http(s) URL"
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, "service_url scheme must be http or https"
	}
	if !(u.Path == "" || u.Path == "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, "service_url must not contain a path, query, or fragment"
	}
	if err := netutil.IsSafeUpstreamHost(u.Host, h.cfg.BlockLoopbackUpstreams); err != nil {
		return nil, "service_url rejected: " + err.Error()
	}
	if req.Headers == nil {
		req.Headers = map[string]string{}
	}
	if msg := validateHeaderOverlay(req.Headers); msg != "" {
		return nil, msg
	}
	headersJSON, err = json.Marshal(req.Headers)
	if err != nil {
		return nil, "invalid headers"
	}
	return headersJSON, ""
}

func (h *authHandlers) adminListServices(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListServices(ctx, db.ListServicesParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list services"})
	}
	total, err := h.q.CountServices(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count services"})
	}

	items := make([]serviceDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, toServiceDTO(r))
	}
	return c.JSON(http.StatusOK, adminServiceListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminCreateService(c *echo.Context) error {
	var req adminServiceReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	headers, msg := h.validateServiceReq(&req)
	if msg != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}

	svc, err := h.q.CreateService(c.Request().Context(), db.CreateServiceParams{
		Title:        req.Title,
		Description:  req.Description,
		ServiceUrl:   req.ServiceURL,
		Domain:       req.Domain,
		Headers:      headers,
		PreserveHost: req.PreserveHost,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "domain already in use"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create service"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	sid := svc.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventServiceCreated,
		TargetType: audit.TargetService,
		TargetID:   &sid,
		TargetName: svc.Title,
		Metadata:   map[string]any{"after": audit.SnapshotService(svc)},
	})
	return c.JSON(http.StatusCreated, toServiceDTO(svc))
}

func (h *authHandlers) adminUpdateService(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req adminServiceReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	headers, msg := h.validateServiceReq(&req)
	if msg != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}

	ctx := c.Request().Context()
	prev, _ := h.q.GetServiceByID(ctx, id)
	svc, err := h.q.UpdateService(ctx, db.UpdateServiceParams{
		ID:           id,
		Title:        req.Title,
		Description:  req.Description,
		ServiceUrl:   req.ServiceURL,
		Domain:       req.Domain,
		Headers:      headers,
		PreserveHost: req.PreserveHost,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "domain already in use"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not update service"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	sid := svc.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventServiceUpdated,
		TargetType: audit.TargetService,
		TargetID:   &sid,
		TargetName: svc.Title,
		Metadata:   map[string]any{"before": audit.SnapshotService(prev), "after": audit.SnapshotService(svc)},
	})
	return c.JSON(http.StatusOK, toServiceDTO(svc))
}

// adminRotateServiceSigningSecret generates a new 32-byte secret, persists it
// on the service, and returns it once to the caller. The secret is used by
// torii to HMAC-sign the X-Torii-* identity headers it injects when proxying.
// Upstream operators must store the returned value and verify
// X-Torii-Signature on incoming requests if they rely on the headers for
// authorization.
func (h *authHandlers) adminRotateServiceSigningSecret(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	svc, err := h.q.RotateServiceSigningSecret(c.Request().Context(), db.RotateServiceSigningSecretParams{
		ID:            id,
		SigningSecret: secret,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not rotate signing secret"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	sid := svc.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventServiceUpdated,
		TargetType: audit.TargetService,
		TargetID:   &sid,
		TargetName: svc.Title,
		Metadata:   map[string]any{"action": "rotate_signing_secret"},
	})
	return c.JSON(http.StatusOK, map[string]string{
		"signing_secret": base64.StdEncoding.EncodeToString(secret),
	})
}

// healthCheckClient is a singleton with a short timeout, no redirect
// following, and TLS verification skipped. Skipping verification matches the
// proxy path's behavior toward upstreams (operators legitimately point torii
// at LAN services with self-signed certs); the goal here is reachability, not
// trust.
var healthCheckClient = &http.Client{
	Timeout: 3 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:       &tls.Config{InsecureSkipVerify: true},
		ResponseHeaderTimeout: 3 * time.Second,
		DisableKeepAlives:     true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type serviceHealthResp struct {
	OK        bool   `json:"ok"`
	Status    int    `json:"status,omitempty"`
	LatencyMS int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}

func (h *authHandlers) adminCheckServiceHealth(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	svc, err := h.q.GetServiceByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "service not found"})
	}

	// Re-validate against SSRF guard at probe time: the safe-host check at
	// create/update may have allowed a hostname that now resolves to a
	// private IP, and we don't want the healthcheck to become an internal
	// network scanner via DNS rebinding.
	u, err := url.Parse(svc.ServiceUrl)
	if err != nil || u.Host == "" {
		return c.JSON(http.StatusOK, serviceHealthResp{OK: false, Error: "invalid service_url"})
	}
	if err := netutil.IsSafeUpstreamHost(u.Host, h.cfg.BlockLoopbackUpstreams); err != nil {
		return c.JSON(http.StatusOK, serviceHealthResp{OK: false, Error: err.Error()})
	}

	ctx, cancel := context.WithTimeout(c.Request().Context(), 3*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, svc.ServiceUrl, nil)
	if err != nil {
		return c.JSON(http.StatusOK, serviceHealthResp{OK: false, Error: err.Error()})
	}
	req.Header.Set("User-Agent", "torii-healthcheck/1")

	// Mirror what the proxy path does for a real request: always surface
	// the torii-facing domain via X-Forwarded-Host, and additionally
	// rewrite Host when preserve_host is set so vhost-routed upstreams
	// (Frappe, Nginx, etc.) pick the right site.
	if svc.Domain != "" {
		req.Header.Set("X-Forwarded-Host", svc.Domain)
	}
	if svc.PreserveHost {
		req.Host = svc.Domain
	}
	if len(svc.Headers) > 0 {
		var overlay map[string]string
		if err := json.Unmarshal(svc.Headers, &overlay); err == nil {
			for k, v := range overlay {
				req.Header.Set(k, v)
			}
		}
	}

	start := time.Now()
	resp, err := healthCheckClient.Do(req)
	latency := time.Since(start).Milliseconds()
	if err != nil {
		return c.JSON(http.StatusOK, serviceHealthResp{OK: false, LatencyMS: latency, Error: err.Error()})
	}
	defer resp.Body.Close()
	return c.JSON(http.StatusOK, serviceHealthResp{
		OK:        resp.StatusCode < 500,
		Status:    resp.StatusCode,
		LatencyMS: latency,
	})
}

func (h *authHandlers) adminDeleteService(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	prev, _ := h.q.GetServiceByID(ctx, id)
	if err := h.q.DeleteService(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete service"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	sid := id
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventServiceDeleted,
		TargetType: audit.TargetService,
		TargetID:   &sid,
		TargetName: prev.Title,
		Metadata:   map[string]any{"before": audit.SnapshotService(prev)},
	})
	return c.NoContent(http.StatusNoContent)
}
