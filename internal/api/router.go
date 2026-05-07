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
	"sanmon/internal/proxy"
)

// Register mounts the /api/v1 routes on the given echo instance.
func Register(e *echo.Echo, pool *pgxpool.Pool, cfg *config.Config, cache *proxy.ServiceCache) {
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

	h := &authHandlers{pool: pool, q: db.New(pool), cfg: cfg, cache: cache}

	v1.POST("/signup", h.signup)
	v1.POST("/signin", h.signin)
	v1.POST("/token_refresh", h.tokenRefresh)
	v1.POST("/logout", h.logout)
	v1.GET("/me", h.me, auth.RequireUser(cfg.JWTSecret))

	secret := cfg.JWTSecret
	gate := func(perm string) echo.MiddlewareFunc { return auth.RequirePermission(secret, perm) }

	v1.GET("/admin/users", h.adminListUsers, gate(auth.PermUsersRead))
	v1.POST("/admin/users", h.adminCreateUser, gate(auth.PermUsersCreate))
	v1.DELETE("/admin/users/:id", h.adminDeleteUser, gate(auth.PermUsersDelete))
	v1.GET("/admin/users/:id/roles", h.adminListUserRoles, gate(auth.PermUserRolesRead))
	v1.POST("/admin/users/:id/roles", h.adminAssignUserRole, gate(auth.PermUserRolesCreate))
	v1.DELETE("/admin/users/:id/roles/:rid", h.adminRevokeUserRole, gate(auth.PermUserRolesDelete))

	v1.GET("/admin/tokens", h.adminListTokens, gate(auth.PermTokensRead))
	v1.DELETE("/admin/tokens/:id", h.adminRevokeToken, gate(auth.PermTokensDelete))
	v1.POST("/admin/tokens/cleanup", h.adminCleanupTokens, gate(auth.PermTokensDelete))

	v1.GET("/admin/services", h.adminListServices, gate(auth.PermServicesRead))
	v1.POST("/admin/services", h.adminCreateService, gate(auth.PermServicesCreate))
	v1.PATCH("/admin/services/:id", h.adminUpdateService, gate(auth.PermServicesUpdate))
	v1.DELETE("/admin/services/:id", h.adminDeleteService, gate(auth.PermServicesDelete))

	v1.GET("/admin/roles", h.adminListRoles, gate(auth.PermRolesRead))
	v1.POST("/admin/roles", h.adminCreateRole, gate(auth.PermRolesCreate))
	v1.GET("/admin/roles/:id", h.adminGetRole, gate(auth.PermRolesRead))
	v1.PATCH("/admin/roles/:id", h.adminUpdateRole, gate(auth.PermRolesUpdate))
	v1.DELETE("/admin/roles/:id", h.adminDeleteRole, gate(auth.PermRolesDelete))
	v1.GET("/admin/roles/:id/permissions", h.adminGetRolePermissions, gate(auth.PermPermissionsRead))
	v1.PUT("/admin/roles/:id/permissions", h.adminSetRolePermissions, gate(auth.PermRolesUpdate))
	v1.GET("/admin/roles/:id/services", h.adminListRoleServices, gate(auth.PermRoleServicesRead))
	v1.POST("/admin/roles/:id/services", h.adminAssignRoleService, gate(auth.PermRoleServicesCreate))
	v1.DELETE("/admin/roles/:id/services/:sid", h.adminRevokeRoleService, gate(auth.PermRoleServicesDelete))
	v1.GET("/admin/roles/:id/users", h.adminListRoleUsers, gate(auth.PermRolesRead))

	v1.GET("/admin/permissions", h.adminListPermissions, gate(auth.PermPermissionsRead))

	v1.GET("/admin/sso", h.adminListSSO, gate(auth.PermSSORead))
	v1.POST("/admin/sso", h.adminCreateSSO, gate(auth.PermSSOCreate))
	v1.PATCH("/admin/sso/:id", h.adminUpdateSSO, gate(auth.PermSSOUpdate))
	v1.DELETE("/admin/sso/:id", h.adminDeleteSSO, gate(auth.PermSSODelete))

	v1.GET("/admin/settings", h.adminGetSettings, gate(auth.PermSettingsRead))
	v1.PUT("/admin/settings", h.adminUpdateSettings, gate(auth.PermSettingsUpdate))

	v1.GET("/auth/config", h.publicAuthConfig)
	v1.GET("/auth/providers", h.publicListProviders)
	v1.GET("/oauth/:slug/start", h.oauthStart)
	v1.GET("/oauth/:slug/callback", h.oauthCallback)
}
