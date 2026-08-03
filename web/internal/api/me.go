package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
)

type changePasswordReq struct {
	Current string `json:"current"`
	New     string `json:"new"`
}

// changeMyPassword lets a signed-in user rotate their own password. Requires
// the current password (defense against an attacker who only has a session
// cookie, not the password). On success all of that user's refresh tokens
// are invalidated so any leaked refresh cookie elsewhere stops working —
// the SPA re-issues itself a fresh refresh token via issueSession.
func (h *authHandlers) changeMyPassword(c *echo.Context) error {
	claims := auth.ClaimsFrom(c)
	if claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid subject"})
	}
	var req changePasswordReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if req.Current == "" || req.New == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "current and new password required"})
	}
	if h.cfg.IsProd() {
		if err := auth.ValidatePasswordStrength(req.New); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
	}
	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, uid)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	if !user.PasswordHash.Valid || !auth.VerifyPassword(user.PasswordHash.String, req.Current) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "current password is incorrect"})
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if err := h.q.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{
		ID:           uid,
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	_ = h.q.DeleteRefreshTokensForUser(ctx, uid)
	// Re-issue a session for the caller so their next request still works.
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:     audit.EventPasswordChanged,
		ActorUserID:   &uid,
		ActorUsername: user.Username,
		TargetType:    audit.TargetUser,
		TargetID:      &uid,
		TargetName:    user.Username,
	})
	return h.issueAndRespond(c, user)
}

// adminResetUserPassword: admin reset, no current-password check, audit-logged.
// Invalidates all of the target user's refresh tokens.
func (h *authHandlers) adminResetUserPassword(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req changePasswordReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	if req.New == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "new password required"})
	}
	if h.cfg.IsProd() {
		if err := auth.ValidatePasswordStrength(req.New); err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
	}
	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	if ok, err := h.guardOutranksTarget(c, id, user.Username, "reset the password of"); !ok {
		return err
	}
	hash, err := auth.HashPassword(req.New)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if err := h.q.UpdateUserPassword(ctx, db.UpdateUserPasswordParams{
		ID:           id,
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	_ = h.q.DeleteRefreshTokensForUser(ctx, id)
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventPasswordResetByAdmin,
		TargetType: audit.TargetUser,
		TargetID:   &id,
		TargetName: user.Username,
	})
	return c.NoContent(http.StatusNoContent)
}

// adminRevokeUserSessions deletes every credential the account can authenticate
// with: refresh tokens and personal access tokens. Forces them to
// re-authenticate everywhere (and within the access-token TTL — 60s by
// default — they lose proxy access too).
//
// PATs are included because this is the endpoint an operator reaches for during
// an incident. Deleting only refresh tokens left a PAT minted during the
// compromise alive and unbounded, so the documented containment action did not
// contain: the attacker keeps full control-plane access through a credential
// that survives this call, a password reset, and even deletion of their own
// account.
func (h *authHandlers) adminRevokeUserSessions(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	if err := h.q.DeleteRefreshTokensForUser(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if err := h.q.DeleteAPITokensForUser(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventSessionsRevoked,
		TargetType: audit.TargetUser,
		TargetID:   &id,
		TargetName: user.Username,
		Metadata:   map[string]any{"revoked": []string{"refresh_tokens", "api_tokens"}},
	})
	return c.NoContent(http.StatusNoContent)
}

// adminUnlockUser clears a failed-login lockout. Without it the only way out of
// a lockout is waiting for the window to lapse without another failed attempt,
// which an attacker can prevent indefinitely. If every admin is locked out at
// once, `torii users unlock` is the offline equivalent.
func (h *authHandlers) adminUnlockUser(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	if err := h.q.ResetFailedLogin(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventLockoutCleared,
		TargetType: audit.TargetUser,
		TargetID:   &id,
		TargetName: user.Username,
		Metadata: map[string]any{
			"via":                "admin_api",
			"failed_login_count": user.FailedLoginCount,
		},
	})
	return c.NoContent(http.StatusNoContent)
}
