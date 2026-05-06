package api

import (
	"context"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"

	"sanmon/internal/auth"
	"sanmon/internal/config"
	"sanmon/internal/db"
)

// Register mounts the /api/v1 routes on the given echo instance.
func Register(e *echo.Echo, pool *pgxpool.Pool, cfg *config.Config) {
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

	if pool == nil || cfg == nil {
		return
	}

	h := &authHandlers{q: db.New(pool), cfg: cfg}

	v1.POST("/signup", h.signup)
	v1.POST("/signin", h.signin)
	v1.POST("/token_refresh", h.tokenRefresh)
	v1.POST("/logout", h.logout)
	v1.GET("/me", h.me, auth.RequireUser(cfg.JWTSecret))

	admin := v1.Group("/admin", auth.RequireAdmin(cfg.JWTSecret))
	admin.GET("/users", h.adminListUsers)
	admin.POST("/users", h.adminCreateUser)
	admin.DELETE("/users/:id", h.adminDeleteUser)
	admin.GET("/tokens", h.adminListTokens)
	admin.DELETE("/tokens/:id", h.adminRevokeToken)
	admin.POST("/tokens/cleanup", h.adminCleanupTokens)
}
