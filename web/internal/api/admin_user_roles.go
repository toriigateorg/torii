package api

import (
	"net/http"

	"github.com/google/uuid"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
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
	if role.IsSystem && role.Name == "admin" {
		count, err := h.q.CountAdmins(ctx)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
		if count <= 1 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot revoke admin from the sole admin user"})
		}
	}
	user, _ := h.q.GetUserByID(ctx, userID)
	if err := h.q.RevokeUserRole(ctx, db.RevokeUserRoleParams{UserID: userID, RoleID: roleID}); err != nil {
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
