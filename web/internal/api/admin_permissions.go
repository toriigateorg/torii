package api

import (
	"net/http"

	"github.com/labstack/echo/v5"

	"torii/internal/auth"
)

func (h *authHandlers) adminListPermissions(c *echo.Context) error {
	return c.JSON(http.StatusOK, map[string][]string{"items": auth.AllPermissions})
}
