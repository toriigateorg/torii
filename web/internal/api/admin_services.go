package api

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
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
	ID                string            `json:"id"`
	Title             string            `json:"title"`
	Description       string            `json:"description"`
	ServiceURL        string            `json:"service_url"`
	Domain            string            `json:"domain"`
	Headers           map[string]string `json:"headers"`
	PreserveHost      bool              `json:"preserve_host"`
	PassthroughErrors bool              `json:"passthrough_errors"`
	MaxBodySize       int64             `json:"max_body_size"`
	ReadTimeoutSecs   int32             `json:"read_timeout_secs"`
	WriteTimeoutSecs  int32             `json:"write_timeout_secs"`
	DialTimeoutSecs   int32             `json:"dial_timeout_secs"`
	// HasSigningSecret reports whether X-Torii-Signature is being emitted for
	// this upstream. The secret itself is never in a DTO. Without this the
	// documented "upstreams verify the signature" contract was unobservable: a
	// service with a NULL secret looks identical to one with a rotated secret, so
	// an operator following the docs could believe identity assertions were
	// authenticated when the headers were arriving unsigned.
	HasSigningSecret bool   `json:"has_signing_secret"`
	CreatedAt        string `json:"created_at"`
	UpdatedAt        string `json:"updated_at"`
}

type adminServiceListResp struct {
	pageMeta
	Items []serviceDTO `json:"items"`
}

// Every optional field is a pointer so an omitted key is distinguishable from a
// zero value. Headers and PreserveHost were plain values, which made an absent
// key look identical to "no overlay" and "false" — and on the PATCH path absent
// keys resolved to global defaults rather than to the row's current values. A
// partial PATCH therefore silently wiped the upstream credential overlay and
// flipped passthrough_errors on, exposing upstream error pages. Only the shipped
// SPA escaped it, by always sending the full object.
type adminServiceReq struct {
	Title             string             `json:"title"`
	Description       string             `json:"description"`
	ServiceURL        string             `json:"service_url"`
	Domain            string             `json:"domain"`
	Headers           *map[string]string `json:"headers"`
	PreserveHost      *bool              `json:"preserve_host"`
	PassthroughErrors *bool              `json:"passthrough_errors"`
	MaxBodySize       *int64             `json:"max_body_size"`
	ReadTimeoutSecs   *int32             `json:"read_timeout_secs"`
	WriteTimeoutSecs  *int32             `json:"write_timeout_secs"`
	DialTimeoutSecs   *int32             `json:"dial_timeout_secs"`
}

// timeoutCeiling bounds each per-service timeout (seconds). 0 means "no
// timeout"; the ceiling guards against fat-finger values that would tie up a
// connection indefinitely.
const timeoutCeiling = 3600

// Timeout helpers default to the same values as the global server defaults so
// legacy API clients that omit them keep today's behavior.
func (r *adminServiceReq) readTimeoutSecs() int32 {
	if r.ReadTimeoutSecs == nil {
		return 30
	}
	return *r.ReadTimeoutSecs
}

func (r *adminServiceReq) writeTimeoutSecs() int32 {
	if r.WriteTimeoutSecs == nil {
		return 60
	}
	return *r.WriteTimeoutSecs
}

func (r *adminServiceReq) dialTimeoutSecs() int32 {
	if r.DialTimeoutSecs == nil {
		return 30
	}
	return *r.DialTimeoutSecs
}

// maxBodySizeCeiling bounds the per-service request-body cap. It's generous
// (5 GiB) — high enough for any realistic upload while rejecting fat-finger or
// hostile values that would let a single request exhaust memory/disk upstream.
const maxBodySizeCeiling = 5 << 30

// maxBodySize defaults to 1 MiB when the caller omits the field, matching the
// torii control-plane limit so legacy API clients that don't know about this
// field keep today's behavior rather than getting an unbounded body.
func (r *adminServiceReq) maxBodySize() int64 {
	if r.MaxBodySize == nil {
		return 1 << 20
	}
	return *r.MaxBodySize
}

// passthroughErrors defaults to true when the caller omits the field, so legacy
// API clients that don't know about this flag get the safer pass-through path
// rather than torii silently masking upstream 5xx with its own page.
func (r *adminServiceReq) passthroughErrors() bool {
	if r.PassthroughErrors == nil {
		return true
	}
	return *r.PassthroughErrors
}

func toServiceDTO(s db.Service) serviceDTO {
	headers := map[string]string{}
	if len(s.Headers) > 0 {
		_ = json.Unmarshal(s.Headers, &headers)
	}
	return serviceDTO{
		ID:                s.ID.String(),
		Title:             s.Title,
		Description:       s.Description,
		ServiceURL:        s.ServiceUrl,
		Domain:            s.Domain,
		Headers:           headers,
		PreserveHost:      s.PreserveHost,
		PassthroughErrors: s.PassthroughErrors,
		MaxBodySize:       s.MaxBodySize,
		ReadTimeoutSecs:   s.ReadTimeoutSecs,
		WriteTimeoutSecs:  s.WriteTimeoutSecs,
		DialTimeoutSecs:   s.DialTimeoutSecs,
		HasSigningSecret:  len(s.SigningSecret) > 0,
		CreatedAt:         tsString(s.CreatedAt),
		UpdatedAt:         tsString(s.UpdatedAt),
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
	if req.MaxBodySize != nil && (*req.MaxBodySize < 0 || *req.MaxBodySize > maxBodySizeCeiling) {
		return nil, "max_body_size must be between 0 (unlimited) and 5368709120 (5 GiB)"
	}
	for _, t := range []struct {
		name string
		v    *int32
	}{
		{"read_timeout_secs", req.ReadTimeoutSecs},
		{"write_timeout_secs", req.WriteTimeoutSecs},
		{"dial_timeout_secs", req.DialTimeoutSecs},
	} {
		if t.v != nil && (*t.v < 0 || *t.v > timeoutCeiling) {
			return nil, t.name + " must be between 0 (no timeout) and 3600 seconds"
		}
	}
	// nil headersJSON means "the caller did not mention headers". Create turns
	// that into an empty overlay; update keeps whatever the row already has.
	if req.Headers == nil {
		return nil, ""
	}
	if msg := validateHeaderOverlay(*req.Headers); msg != "" {
		return nil, msg
	}
	headersJSON, err = json.Marshal(*req.Headers)
	if err != nil {
		return nil, "invalid headers"
	}
	return headersJSON, ""
}

// preserveHost reports the requested value, defaulting to false on create.
func (r *adminServiceReq) preserveHost() bool {
	return r.PreserveHost != nil && *r.PreserveHost
}

func (h *authHandlers) adminListServices(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	var search pgtype.Text
	if q := strings.TrimSpace(c.QueryParam("search")); q != "" {
		search = pgtype.Text{String: q, Valid: true}
	}

	rows, err := h.q.ListServices(ctx, db.ListServicesParams{Lim: limit, Off: offset, Search: search})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list services"})
	}
	total, err := h.q.CountFilteredServices(ctx, search)
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

	if headers == nil {
		headers = []byte("{}")
	}
	svc, err := h.q.CreateService(c.Request().Context(), db.CreateServiceParams{
		Title:             req.Title,
		Description:       req.Description,
		ServiceUrl:        req.ServiceURL,
		Domain:            req.Domain,
		Headers:           headers,
		PreserveHost:      req.preserveHost(),
		PassthroughErrors: req.passthroughErrors(),
		MaxBodySize:       req.maxBodySize(),
		ReadTimeoutSecs:   req.readTimeoutSecs(),
		WriteTimeoutSecs:  req.writeTimeoutSecs(),
		DialTimeoutSecs:   req.dialTimeoutSecs(),
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "domain already in use"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create service"})
	}
	// Give every service a signing secret at birth. It used to be NULL until an
	// operator called rotate_signing_secret, which no client ever did, so the
	// documented contract — "upstreams verify X-Torii-Signature" — was
	// unsatisfiable through the product and every identity assertion torii
	// injected arrived unsigned. The value is not returned here; the operator
	// fetches it by rotating, same as for an existing service.
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if rotated, err := h.q.RotateServiceSigningSecret(c.Request().Context(), db.RotateServiceSigningSecretParams{
		ID:            svc.ID,
		SigningSecret: secret,
	}); err == nil {
		svc = rotated
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
	// The error was previously discarded, so a failed lookup left prev as a zero
	// Service and every omitted field merged against zero values.
	prev, err := h.q.GetServiceByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "service not found"})
	}
	// Omitted fields keep the row's existing value. UpdateService writes every
	// column, so anything not merged here is silently reset.
	if headers == nil {
		headers = prev.Headers
	}
	preserveHost := prev.PreserveHost
	if req.PreserveHost != nil {
		preserveHost = *req.PreserveHost
	}
	passthroughErrors := prev.PassthroughErrors
	if req.PassthroughErrors != nil {
		passthroughErrors = *req.PassthroughErrors
	}
	maxBodySize := prev.MaxBodySize
	if req.MaxBodySize != nil {
		maxBodySize = *req.MaxBodySize
	}
	readTimeout := prev.ReadTimeoutSecs
	if req.ReadTimeoutSecs != nil {
		readTimeout = *req.ReadTimeoutSecs
	}
	writeTimeout := prev.WriteTimeoutSecs
	if req.WriteTimeoutSecs != nil {
		writeTimeout = *req.WriteTimeoutSecs
	}
	dialTimeout := prev.DialTimeoutSecs
	if req.DialTimeoutSecs != nil {
		dialTimeout = *req.DialTimeoutSecs
	}
	svc, err := h.q.UpdateService(ctx, db.UpdateServiceParams{
		ID:                id,
		Title:             req.Title,
		Description:       req.Description,
		ServiceUrl:        req.ServiceURL,
		Domain:            req.Domain,
		Headers:           headers,
		PreserveHost:      preserveHost,
		PassthroughErrors: passthroughErrors,
		MaxBodySize:       maxBodySize,
		ReadTimeoutSecs:   readTimeout,
		WriteTimeoutSecs:  writeTimeout,
		DialTimeoutSecs:   dialTimeout,
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

var (
	healthCheckOnce   sync.Once
	healthCheckClient *http.Client
)

// healthProbeClient is the client behind GET /admin/services/:id/health: short
// timeout, no redirect following, and TLS verified.
//
// Verification used to be disabled here, on the stated grounds that it matched
// the proxy path. It did not: the proxy transport (proxy.ServiceCache
// refreshLocked) never touches TLSClientConfig, so real proxied traffic to an
// https upstream is verified, and this was the only InsecureSkipVerify in the
// tree. The probe also forwards the per-service header overlay, which is
// documented as the place upstream credentials live — so an on-path attacker
// needing no torii permission at all could present any certificate and collect
// them. A self-signed LAN upstream now fails the probe the same way it fails a
// proxied request, which is the honest answer.
//
// blockLoopback is threaded from the config rather than hardcoded false, so the
// socket-level backstop enforces the same deny set as the pre-check above it.
func (h *authHandlers) healthProbeClient() *http.Client {
	healthCheckOnce.Do(func() {
		blockLoopback := h.cfg != nil && h.cfg.BlockLoopbackUpstreams
		healthCheckClient = &http.Client{
			Timeout: 3 * time.Second,
			Transport: &http.Transport{
				ResponseHeaderTimeout: 3 * time.Second,
				DisableKeepAlives:     true,
				// http.DefaultTransport carries Proxy: ProxyFromEnvironment. A
				// HTTP_PROXY in the environment would route the probe through it
				// and hand the deny set nothing to inspect but the proxy's own
				// address, so this transport is built from scratch and never
				// sets Proxy.
				//
				// Socket-level backstop for the resolve-then-connect gap in the
				// probe below: the address here is post-resolution.
				DialContext: (&net.Dialer{
					Timeout: 3 * time.Second,
					Control: func(network, address string, _ syscall.RawConn) error {
						return netutil.IsSafeUpstreamAddr(address, blockLoopback)
					},
				}).DialContext,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	})
	return healthCheckClient
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
	// The per-service header overlay is deliberately NOT replayed. It is
	// documented as holding upstream credentials, and this probe is a
	// reachability check — sending them buys nothing the status code doesn't
	// already tell us, while giving every https misconfiguration and every
	// on-path observer a copy. An upstream that 401s an unauthenticated GET
	// still answers, which is what "reachable" means here.

	start := time.Now()
	resp, err := h.healthProbeClient().Do(req)
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
