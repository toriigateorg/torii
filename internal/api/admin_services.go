package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"

	"sanmon/internal/db"
)

var domainRe = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*(:[0-9]+)?$`)

type serviceDTO struct {
	ID          string            `json:"id"`
	Title       string            `json:"title"`
	Description string            `json:"description"`
	ServiceURL  string            `json:"service_url"`
	Domain      string            `json:"domain"`
	Headers     map[string]string `json:"headers"`
	CreatedAt   string            `json:"created_at"`
	UpdatedAt   string            `json:"updated_at"`
}

type adminServiceListResp struct {
	pageMeta
	Items []serviceDTO `json:"items"`
}

type adminServiceReq struct {
	Title       string            `json:"title"`
	Description string            `json:"description"`
	ServiceURL  string            `json:"service_url"`
	Domain      string            `json:"domain"`
	Headers     map[string]string `json:"headers"`
}

func toServiceDTO(s db.Service) serviceDTO {
	headers := map[string]string{}
	if len(s.Headers) > 0 {
		_ = json.Unmarshal(s.Headers, &headers)
	}
	return serviceDTO{
		ID:          s.ID.String(),
		Title:       s.Title,
		Description: s.Description,
		ServiceURL:  s.ServiceUrl,
		Domain:      s.Domain,
		Headers:     headers,
		CreatedAt:   tsString(s.CreatedAt),
		UpdatedAt:   tsString(s.UpdatedAt),
	}
}

func validateServiceReq(req *adminServiceReq) (headersJSON []byte, errMsg string) {
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
	if req.Headers == nil {
		req.Headers = map[string]string{}
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
	headers, msg := validateServiceReq(&req)
	if msg != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}

	svc, err := h.q.CreateService(c.Request().Context(), db.CreateServiceParams{
		Title:       req.Title,
		Description: req.Description,
		ServiceUrl:  req.ServiceURL,
		Domain:      req.Domain,
		Headers:     headers,
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
	headers, msg := validateServiceReq(&req)
	if msg != "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": msg})
	}

	svc, err := h.q.UpdateService(c.Request().Context(), db.UpdateServiceParams{
		ID:          id,
		Title:       req.Title,
		Description: req.Description,
		ServiceUrl:  req.ServiceURL,
		Domain:      req.Domain,
		Headers:     headers,
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
	return c.JSON(http.StatusOK, toServiceDTO(svc))
}

func (h *authHandlers) adminDeleteService(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	if err := h.q.DeleteService(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete service"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	return c.NoContent(http.StatusNoContent)
}
