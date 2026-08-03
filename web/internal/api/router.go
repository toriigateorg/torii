package api

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"
	"github.com/labstack/echo/v5/middleware"
	"golang.org/x/time/rate"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/config"
	"torii/internal/db"
	"torii/internal/proxy"
	"torii/internal/version"
)

// SessionRefresher rotates the caller's session using the refresh cookie,
// sets fresh auth cookies on the response, and returns the resulting claims.
// Implemented by *authHandlers so the proxy dispatch can recover from an
// expired access token without bouncing the user through the SPA.
type SessionRefresher interface {
	AttemptCookieRefresh(c *echo.Context) (*auth.Claims, error)
}

const apiPrefix = "/_torii/api/v1"

// crossHostEndpoints are the only API paths answered on a proxied service host.
// A service host needs exactly enough of the API to get a user signed in there
// (cookies are host-scoped, so the flow reruns per domain) and to keep the
// signin / forbidden pages functional. Everything else — the whole /admin
// surface above all — is control plane and belongs to TORII_URL only.
var crossHostEndpoints = map[string]struct{}{
	"/health":               {},
	"/ht/":                  {},
	"/signin":               {},
	"/signup":               {},
	"/logout":               {},
	"/token_refresh":        {},
	"/refresh_and_redirect": {},
	"/sso_handoff":          {},
	"/me":                   {},
	"/auth/config":          {},
	"/auth/providers":       {},
}

// controlPlaneHostGate 404s control-plane endpoints on any host other than
// TORII_URL. Without it the entire API answers on every proxied domain, and
// since the access cookie is host-scoped at Path=/ and cookie auth is only
// CSRF-gated on state-changing methods, script running on an upstream origin
// (an XSS in that app, or a hostile upstream) could read the full admin GET
// surface as the signed-in victim. Scoping the routes removes the reachability
// rather than relying on the per-request credential checks.
func controlPlaneHostGate(cfg *config.Config) echo.MiddlewareFunc {
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if cfg == nil || cfg.IsToriiHost(c.Request().Host) {
				return next(c)
			}
			path := strings.TrimPrefix(c.Request().URL.Path, apiPrefix)
			if _, ok := crossHostEndpoints[path]; ok {
				return next(c)
			}
			// OAuth start/callback are per-provider and must work on the
			// service host the user landed on.
			if strings.HasPrefix(path, "/oauth/") {
				return next(c)
			}
			return c.JSON(http.StatusNotFound, map[string]string{"error": "not found"})
		}
	}
}

// Register mounts the /_torii/api/v1 routes on the given echo instance and
// returns a SessionRefresher (nil when no DB pool / config is wired).
func Register(e *echo.Echo, pool *pgxpool.Pool, cfg *config.Config, cache *proxy.ServiceCache, auditor *audit.Logger) SessionRefresher {
	// torii's own control-plane API only ever takes small JSON payloads, so
	// keep it pinned at 1 MiB. Proxied upstream traffic is NOT mounted here —
	// it's governed per-service via Service.MaxBodySize in the proxy path.
	v1 := e.Group("/_torii/api/v1", middleware.BodyLimit(1<<20), controlPlaneHostGate(cfg))

	v1.GET("/health", func(c *echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{
			"status":  "ok",
			"version": version.Version,
		})
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
		// Audit state is reported so a disabled file sink is observable here
		// rather than being discovered by someone looking for a trail that was
		// never written. It is deliberately excluded from "all": the database
		// sink still records everything, so a bad log directory should not take
		// the deployment out of rotation.
		auditFileOK := auditor != nil && auditor.FileOK()
		return c.JSON(http.StatusOK, map[string]bool{
			"all":        dbOK,
			"db":         dbOK,
			"api":        true,
			"audit_db":   auditor != nil && dbOK,
			"audit_file": auditFileOK,
		})
	})

	if pool == nil || cfg == nil {
		return nil
	}

	h := &authHandlers{pool: pool, q: db.New(pool), cfg: cfg, cache: cache, auditor: auditor}
	auth.SetAPITokenResolver(h.resolveAPIToken)
	auth.SetServiceTokenResolver(h.resolveServiceToken)

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
	// ssoLimiter: OAuth start/callback don't run argon2 and the callback is
	// gated by a torii-issued state token, so they don't need credential-
	// stuffing-grade limits. They legitimately burst: the SPA does silent
	// prompt=none re-auth, and cross-domain login re-runs the flow once per
	// service domain a user opens. Only a DoS cap is needed.
	ssoLimiter := rateLimit(rate.Every(time.Second), 30)
	v1.POST("/signup", h.signup, authLimiter)
	v1.POST("/signin", h.signin, authLimiter)
	v1.POST("/token_refresh", h.tokenRefresh, refreshLimiter)
	v1.GET("/refresh_and_redirect", h.refreshAndRedirect, refreshLimiter)
	// logoutLimiter: /logout is unauthenticated, allowlisted on every proxied
	// host, and writes an audit event to two sinks per call, which made it the
	// cheapest unauthenticated write amplifier in the API. It gets its own
	// bucket rather than sharing authLimiter, so a burst of logouts from one NAT
	// egress can't consume that IP's signin budget.
	logoutLimiter := rateLimit(rate.Every(time.Second), 10)
	v1.POST("/logout", h.logout, logoutLimiter)
	v1.GET("/me", h.me, auth.RequireUser(cfg.JWTSecret))
	v1.GET("/me/services", h.myServices, auth.RequireUser(cfg.JWTSecret))
	// authLimiter here for the same reason as signin/signup: changeMyPassword
	// runs argon2id to check the current password, so a wrong guess still costs
	// a full 64 MiB derivation. Being authenticated is not much of a barrier —
	// one ordinary account is enough to drive it.
	v1.POST("/me/password", h.changeMyPassword, auth.RequireUser(cfg.JWTSecret), authLimiter)

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
	v1.POST("/admin/users/:id/password", h.adminResetUserPassword, gate(auth.PermUsersUpdate))
	v1.POST("/admin/users/:id/revoke_sessions", h.adminRevokeUserSessions, gate(auth.PermUsersUpdate))
	v1.POST("/admin/users/:id/unlock", h.adminUnlockUser, gate(auth.PermUsersUpdate))
	v1.GET("/admin/users/:id/roles", h.adminListUserRoles, gate(auth.PermUserRolesRead))
	v1.POST("/admin/users/:id/roles", h.adminAssignUserRole, gate(auth.PermUserRolesCreate))
	v1.DELETE("/admin/users/:id/roles/:rid", h.adminRevokeUserRole, gate(auth.PermUserRolesDelete))

	v1.GET("/admin/tokens", h.adminListTokens, gate(auth.PermTokensRead))
	v1.DELETE("/admin/tokens/:id", h.adminRevokeToken, gate(auth.PermTokensDelete))
	v1.POST("/admin/tokens/cleanup", h.adminCleanupTokens, gate(auth.PermTokensDelete))

	v1.GET("/admin/api_tokens", h.adminListAPITokens, gate(auth.PermAPITokensRead))
	v1.POST("/admin/api_tokens", h.adminCreateAPIToken, gate(auth.PermAPITokensCreate))
	v1.DELETE("/admin/api_tokens/:id", h.adminDeleteAPIToken, gate(auth.PermAPITokensDelete))

	v1.GET("/admin/api_users", h.adminListAPIUsers, gate(auth.PermAPIUsersRead))
	v1.POST("/admin/api_users", h.adminCreateAPIUser, gate(auth.PermAPIUsersCreate))
	v1.GET("/admin/api_users/:id", h.adminGetAPIUser, gate(auth.PermAPIUsersRead))
	v1.DELETE("/admin/api_users/:id", h.adminDeleteAPIUser, gate(auth.PermAPIUsersDelete))
	v1.POST("/admin/api_users/:id/regenerate_token", h.adminRegenerateAPIUserToken, gate(auth.PermAPIUsersUpdate))
	v1.GET("/admin/api_users/:id/roles", h.adminListAPIUserRoles, gate(auth.PermAPIUsersRead))
	v1.POST("/admin/api_users/:id/roles", h.adminAssignAPIUserRole, gate(auth.PermAPIUsersUpdate))
	v1.DELETE("/admin/api_users/:id/roles/:rid", h.adminRevokeAPIUserRole, gate(auth.PermAPIUsersUpdate))

	v1.GET("/admin/services", h.adminListServices, gate(auth.PermServicesRead))
	v1.POST("/admin/services", h.adminCreateService, gate(auth.PermServicesCreate))
	v1.PATCH("/admin/services/:id", h.adminUpdateService, gate(auth.PermServicesUpdate))
	v1.DELETE("/admin/services/:id", h.adminDeleteService, gate(auth.PermServicesDelete))
	v1.POST("/admin/services/:id/rotate_signing_secret", h.adminRotateServiceSigningSecret, gate(auth.PermServicesUpdate))
	v1.GET("/admin/services/:id/health", h.adminCheckServiceHealth, gate(auth.PermServicesRead))

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
	v1.GET("/oauth/:slug/start", h.oauthStart, ssoLimiter)
	v1.GET("/oauth/:slug/callback", h.oauthCallback, ssoLimiter)
	// Cross-host SSO handoff: called from the handoff page on a service
	// domain, exchanges a short-lived single-use torii-signed token for
	// cookies on that host. Reachable on any host because that's the whole
	// point. POST-only so the token stays out of URLs and Referers.
	v1.POST("/sso_handoff", h.ssoHandoff, refreshLimiter)

	return h
}
