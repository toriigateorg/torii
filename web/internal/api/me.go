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

// adminRevokeUserSessions deletes all refresh tokens for a user. Forces them
// to re-authenticate everywhere (and within the access-token TTL — 60s by
// default — they lose proxy access too).
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
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventSessionsRevoked,
		TargetType: audit.TargetUser,
		TargetID:   &id,
		TargetName: user.Username,
	})
	return c.NoContent(http.StatusNoContent)
}
