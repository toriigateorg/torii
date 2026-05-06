package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
)

// Register mounts the /api/v1 routes on the given echo instance.
func Register(e *echo.Echo, pool *pgxpool.Pool) {
	v1 := e.Group("/api/v1")

	v1.GET("/health", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"status": "ok"})
	})

	v1.GET("/ht/", func(c *echo.Context) error {
		dbOK := false
		if pool != nil {
			ctx, cancel := context.WithTimeout(c.Request().Context(), 2*time.Second)
			defer cancel()
			if err := pool.Ping(ctx); err == nil {
				dbOK = true
			}
		}
		return c.JSON(http.StatusOK, map[string]bool{
			"all": dbOK,
			"db":  dbOK,
			"api": true,
		})
	})
}
