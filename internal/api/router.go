package api

import (
	"net/http"

	"github.com/labstack/echo/v5"
)

// Register mounts the /api/v1 routes on the given echo instance.
func Register(e *echo.Echo) {
	v1 := e.Group("/api/v1")

	v1.GET("/health", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})
}
