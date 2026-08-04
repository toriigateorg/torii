package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
)

type adminUserRoleAssignReq struct {
	RoleID string `json:"role_id"`
}

func (h *authHandlers) adminListUserRoles(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	rows, err := h.q.ListUserRoles(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list roles"})
	}
	items := make([]roleDTO, 0, len(rows))
	for _, r := range rows {
		dto, err := h.toRoleDTO(c.Request().Context(), r)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not load permissions"})
		}
		items = append(items, dto)
	}
	return c.JSON(http.StatusOK, map[string][]roleDTO{"items": items})
}

func (h *authHandlers) adminAssignUserRole(c *echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}
	var req adminUserRoleAssignReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	roleID, err := uuid.Parse(req.RoleID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
	}
	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	role, err := h.q.GetRoleByID(ctx, roleID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	if role.IsSystem && role.Name == "all" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "the 'all' role is auto-assigned and cannot be managed"})
	}
	if ok, err := h.callerCanGrantRole(ctx, auth.ClaimsFrom(c), roleID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	} else if !ok {
		h.logRoleGrantDenied(c, audit.TargetUser, userID, user.Username, role)
		return c.JSON(http.StatusForbidden, map[string]string{"error": errCannotGrantRole})
	}
	if err := h.q.AssignUserRole(ctx, db.AssignUserRoleParams{UserID: userID, RoleID: roleID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not assign role"})
	}
	uid := user.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventUserRoleAssigned,
		TargetType: audit.TargetUser,
		TargetID:   &uid,
		TargetName: user.Username,
		Metadata: map[string]any{
			"role_id":   role.ID.String(),
			"role_name": role.Name,
		},
	})
	return c.NoContent(http.StatusCreated)
}

func (h *authHandlers) adminRevokeUserRole(c *echo.Context) error {
	userID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user id"})
	}
	roleID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, roleID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	if role.IsSystem && role.Name == "all" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot revoke the 'all' role"})
	}
	user, err := h.q.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	// Revocation needs both guards. Without the outranks check, stripping a
	// target's permission-bearing roles makes callerOutranksTarget vacuously
	// true, clearing the way to reset their password and sign in as them — while
	// their service-only roles, and the identity torii asserts to upstreams,
	// stay intact. Without the grant check, a role could be taken away by
	// someone who could not have handed it out.
	if ok, err := h.guardOutranksTarget(c, userID, user.Username, "revoke a role from"); !ok {
		return err
	}
	if ok, err := h.callerCanGrantRole(ctx, auth.ClaimsFrom(c), roleID); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	} else if !ok {
		h.logRoleGrantDenied(c, audit.TargetUser, userID, user.Username, role)
		return c.JSON(http.StatusForbidden, map[string]string{"error": errCannotRevokeRole})
	}
	// The last-admin check and the revoke share one transaction and the
	// admin-guard advisory lock, so two concurrent revocations cannot each see a
	// count of two and between them leave the deployment with no administrator.
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", adminGuardLock); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	qtx := h.q.WithTx(tx)
	if role.IsSystem && role.Name == "admin" {
		count, err := qtx.CountAdmins(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
		if count <= 1 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot revoke admin from the sole admin user"})
		}
	}
	if err := qtx.RevokeUserRole(ctx, db.RevokeUserRoleParams{UserID: userID, RoleID: roleID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not revoke role"})
	}
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not revoke role"})
	}
	uid := userID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventUserRoleRevoked,
		TargetType: audit.TargetUser,
		TargetID:   &uid,
		TargetName: user.Username,
		Metadata: map[string]any{
			"role_id":   role.ID.String(),
			"role_name": role.Name,
		},
	})
	return c.NoContent(http.StatusNoContent)
}
