package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"torii/internal/auth"
)

// myServiceDTO is the public view of a service: presentation fields plus the
// domain the user browses to. Deliberately NOT the admin serviceDTO — that one
// carries the per-service header overlay (which by design holds upstream
// credentials) and the internal service_url, neither of which any signed-in
// user should be able to read.
type myServiceDTO struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Domain      string `json:"domain"`
}

func (h *authHandlers) myServices(c *echo.Context) error {
	claims := auth.ClaimsFrom(c)
	if claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid subject"})
	}
	rows, err := h.q.ListServicesForUser(c.Request().Context(), uid)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list services"})
	}
	items := make([]myServiceDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, myServiceDTO{
			ID:          r.ID.String(),
			Title:       r.Title,
			Description: r.Description,
			Domain:      r.Domain,
		})
	}
	return c.JSON(http.StatusOK, map[string]any{"items": items})
}
