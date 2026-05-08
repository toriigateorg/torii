package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"golang.org/x/time/rate"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/config"
	"torii/internal/db"
	"torii/internal/proxy"
)

// toriiHostOnlyPathPrefixes is the deny-list of /api/v1/* paths that must
// only be reachable on cfg.ToriiURL. The primary case is /api/v1/admin/*:
// without this gate, an upstream backend that lifted the torii access cookie
// from a proxied request could replay it against the admin API on its own
// hostname (dispatch otherwise serves /api/v1/* on every host because the v1
// group is mounted on the global Echo). With Wave 1.1's cookie stripping the
// cookie shouldn't reach upstream in the first place; this is defense in
// depth.
//
// All other auth/me/token endpoints stay reachable cross-host because the
// SPA renders on service domains too (dispatch falls through to the SPA for
// unauthenticated requests on proxied hosts) and needs them to function.
var toriiHostOnlyPathPrefixes = []string{
	"/api/v1/admin/",
}

func requireToriiHost(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg.IsToriiHost(c.Request().Host) {
				return next(c)
			}
			path := c.Request().URL.Path
			for _, blocked := range toriiHostOnlyPathPrefixes {
				if strings.HasPrefix(path, blocked) {
					return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
				}
			}
			return next(c)
		}
	}
}

// SessionRefresher rotates the caller's session using the refresh cookie,
// sets fresh auth cookies on the response, and returns the resulting claims.
// Implemented by *authHandlers so the proxy dispatch can recover from an
// expired access token without bouncing the user through the SPA.
type SessionRefresher interface {
	AttemptCookieRefresh(c *echo.Context) (*auth.Claims, error)
}

// Register mounts the /api/v1 routes on the given echo instance and returns
// a SessionRefresher (nil when no DB pool / config is wired).
func Register(e *echo.Echo, pool *pgxpool.Pool, cfg *config.Config, cache *proxy.ServiceCache, auditor *audit.Logger) SessionRefresher {
	v1 := e.Group("/api/v1")
	if cfg != nil {
		v1.Use(requireToriiHost(cfg))
	}

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
		return nil
	}

	h := &authHandlers{pool: pool, q: db.New(pool), cfg: cfg, cache: cache, auditor: auditor}
	auth.SetAPITokenResolver(h.resolveAPIToken)

	// authLimiter: 10 req/min/IP, burst 5. Tight because each signin/signup
	// triggers argon2id (64 MiB, t=2) — without a limit a single attacker
	// can both DoS and brute-force.
	authLimiter := rateLimit(rate.Every(6*time.Second), 5)
	// refreshLimiter: looser. token_refresh and refresh_and_redirect don't
	// run argon2 and rotate an already-secret 32-byte refresh token, so
	// they don't need credential-stuffing-grade limits — only a DoS cap.
	// The SPA legitimately bursts these on page reloads (bootstrap → /me →
	// 401 → /token_refresh) and across multiple tabs.
	refreshLimiter := rateLimit(rate.Every(time.Second), 30)
	v1.POST("/signup", h.signup, authLimiter)
	v1.POST("/signin", h.signin, authLimiter)
	v1.POST("/token_refresh", h.tokenRefresh, refreshLimiter)
	v1.GET("/refresh_and_redirect", h.refreshAndRedirect, refreshLimiter)
	v1.POST("/logout", h.logout)
	v1.GET("/me", h.me, auth.RequireUser(cfg.JWTSecret))
	v1.GET("/me/services", h.myServices, auth.RequireUser(cfg.JWTSecret))

	secret := cfg.JWTSecret
	onDenied := func(c *echo.Context, perm string) {
		if auditor == nil {
			return
		}
		auditor.LogFromEcho(c, audit.Event{
			EventType: audit.EventAuthzDenied,
			Metadata: map[string]any{
				"required_permission": perm,
				"path":                c.Request().URL.Path,
				"method":              c.Request().Method,
			},
		})
	}
	gate := func(perm string) echo.MiddlewareFunc { return auth.RequirePermission(secret, perm, onDenied) }

	v1.GET("/admin/users", h.adminListUsers, gate(auth.PermUsersRead))
	v1.POST("/admin/users", h.adminCreateUser, gate(auth.PermUsersCreate))
	v1.DELETE("/admin/users/:id", h.adminDeleteUser, gate(auth.PermUsersDelete))
	v1.GET("/admin/users/:id/roles", h.adminListUserRoles, gate(auth.PermUserRolesRead))
	v1.POST("/admin/users/:id/roles", h.adminAssignUserRole, gate(auth.PermUserRolesCreate))
	v1.DELETE("/admin/users/:id/roles/:rid", h.adminRevokeUserRole, gate(auth.PermUserRolesDelete))

	v1.GET("/admin/tokens", h.adminListTokens, gate(auth.PermTokensRead))
	v1.DELETE("/admin/tokens/:id", h.adminRevokeToken, gate(auth.PermTokensDelete))
	v1.POST("/admin/tokens/cleanup", h.adminCleanupTokens, gate(auth.PermTokensDelete))

	v1.GET("/admin/api_tokens", h.adminListAPITokens, gate(auth.PermAPITokensRead))
	v1.POST("/admin/api_tokens", h.adminCreateAPIToken, gate(auth.PermAPITokensCreate))
	v1.DELETE("/admin/api_tokens/:id", h.adminDeleteAPIToken, gate(auth.PermAPITokensDelete))

	v1.GET("/admin/services", h.adminListServices, gate(auth.PermServicesRead))
	v1.POST("/admin/services", h.adminCreateService, gate(auth.PermServicesCreate))
	v1.PATCH("/admin/services/:id", h.adminUpdateService, gate(auth.PermServicesUpdate))
	v1.DELETE("/admin/services/:id", h.adminDeleteService, gate(auth.PermServicesDelete))
	v1.POST("/admin/services/:id/rotate_signing_secret", h.adminRotateServiceSigningSecret, gate(auth.PermServicesUpdate))

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

	v1.GET("/admin/audit", h.adminListAuditLogs, gate(auth.PermAuditRead))
	v1.GET("/admin/stats", h.adminGetStats, gate(auth.PermAuditRead))

	v1.GET("/auth/config", h.publicAuthConfig)
	v1.GET("/auth/providers", h.publicListProviders)
	v1.GET("/oauth/:slug/start", h.oauthStart, authLimiter)
	v1.GET("/oauth/:slug/callback", h.oauthCallback, authLimiter)

	return h
}
