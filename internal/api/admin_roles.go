package api

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"

	"sanmon/internal/audit"
	"sanmon/internal/auth"
	"sanmon/internal/db"
)

type roleDTO struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type adminRoleListResp struct {
	pageMeta
	Items []roleDTO `json:"items"`
}

type adminRoleCreateReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type adminRoleUpdateReq struct {
	Name        *string `json:"name"`
	Description *string `json:"description"`
}

type adminRolePermissionsReq struct {
	Permissions []string `json:"permissions"`
}

type adminRoleServiceReq struct {
	ServiceID string `json:"service_id"`
}

var roleNameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{1,64}$`)

func (h *authHandlers) toRoleDTO(ctx context.Context, r db.Role) (roleDTO, error) {
	perms, err := h.q.ListRolePermissions(ctx, r.ID)
	if err != nil {
		return roleDTO{}, err
	}
	if perms == nil {
		perms = []string{}
	}
	return roleDTO{
		ID:          r.ID.String(),
		Name:        r.Name,
		Description: r.Description,
		IsSystem:    r.IsSystem,
		Permissions: perms,
		CreatedAt:   tsString(r.CreatedAt),
		UpdatedAt:   tsString(r.UpdatedAt),
	}, nil
}

func (h *authHandlers) adminListRoles(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListRoles(ctx, db.ListRolesParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list roles"})
	}
	total, err := h.q.CountRoles(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count roles"})
	}

	items := make([]roleDTO, 0, len(rows))
	for _, r := range rows {
		dto, err := h.toRoleDTO(c.Request().Context(), r)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not load permissions"})
		}
		items = append(items, dto)
	}
	return c.JSON(http.StatusOK, adminRoleListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminGetRole(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	r, err := h.q.GetRoleByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	dto, err := h.toRoleDTO(c.Request().Context(), r)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	return c.JSON(http.StatusOK, dto)
}

func (h *authHandlers) adminCreateRole(c *echo.Context) error {
	var req adminRoleCreateReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if !roleNameRe.MatchString(req.Name) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name must be 1-64 chars: letters, digits, _ . -"})
	}
	if len(req.Description) > 2000 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "description must be at most 2000 chars"})
	}
	for _, p := range req.Permissions {
		if !auth.IsValidPermission(p) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown permission: " + p})
		}
	}

	ctx := c.Request().Context()
	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)

	role, err := qtx.CreateRole(ctx, db.CreateRoleParams{
		Name:        req.Name,
		Description: req.Description,
		IsSystem:    false,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "role name already taken"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create role"})
	}
	for _, p := range req.Permissions {
		if err := qtx.InsertRolePermission(ctx, db.InsertRolePermissionParams{RoleID: role.ID, Permission: p}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not assign permission"})
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	rid := role.ID
	after := audit.SnapshotRole(role)
	after["permissions"] = req.Permissions
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventRoleCreated,
		TargetType: audit.TargetRole,
		TargetID:   &rid,
		TargetName: role.Name,
		Metadata:   map[string]any{"after": after},
	})
	dto, err := h.toRoleDTO(c.Request().Context(), role)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	return c.JSON(http.StatusCreated, dto)
}

func (h *authHandlers) adminUpdateRole(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req adminRoleUpdateReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	newName := role.Name
	newDesc := role.Description
	if req.Name != nil {
		n := strings.TrimSpace(*req.Name)
		if n != role.Name {
			if role.IsSystem {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot rename a system role"})
			}
			if !roleNameRe.MatchString(n) {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": "name must be 1-64 chars: letters, digits, _ . -"})
			}
			newName = n
		}
	}
	if req.Description != nil {
		d := strings.TrimSpace(*req.Description)
		if len(d) > 2000 {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "description must be at most 2000 chars"})
		}
		newDesc = d
	}
	before := audit.SnapshotRole(role)
	updated, err := h.q.UpdateRole(ctx, db.UpdateRoleParams{ID: id, Name: newName, Description: newDesc})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "role name already taken"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not update role"})
	}
	rid := updated.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventRoleUpdated,
		TargetType: audit.TargetRole,
		TargetID:   &rid,
		TargetName: updated.Name,
		Metadata:   map[string]any{"before": before, "after": audit.SnapshotRole(updated)},
	})
	dto, err := h.toRoleDTO(c.Request().Context(), updated)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	return c.JSON(http.StatusOK, dto)
}

func (h *authHandlers) adminDeleteRole(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if role.IsSystem {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete a system role"})
	}
	before := audit.SnapshotRole(role)
	if err := h.q.DeleteRole(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete role"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	rid := role.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventRoleDeleted,
		TargetType: audit.TargetRole,
		TargetID:   &rid,
		TargetName: role.Name,
		Metadata:   map[string]any{"before": before},
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *authHandlers) adminGetRolePermissions(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	perms, err := h.q.ListRolePermissions(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list permissions"})
	}
	if perms == nil {
		perms = []string{}
	}
	return c.JSON(http.StatusOK, map[string][]string{"permissions": perms})
}

func (h *authHandlers) adminSetRolePermissions(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req adminRolePermissionsReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	for _, p := range req.Permissions {
		if !auth.IsValidPermission(p) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown permission: " + p})
		}
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	if role.IsSystem && role.Name == "admin" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot edit permissions on the admin role"})
	}

	beforePerms, _ := h.q.ListRolePermissions(ctx, id)
	if beforePerms == nil {
		beforePerms = []string{}
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)

	if err := qtx.DeleteRolePermissions(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	for _, p := range req.Permissions {
		if err := qtx.InsertRolePermission(ctx, db.InsertRolePermissionParams{RoleID: id, Permission: p}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	out := req.Permissions
	if out == nil {
		out = []string{}
	}
	rid := id
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventRolePermsChanged,
		TargetType: audit.TargetRole,
		TargetID:   &rid,
		TargetName: role.Name,
		Metadata:   map[string]any{"before": beforePerms, "after": out},
	})
	return c.JSON(http.StatusOK, map[string][]string{"permissions": out})
}

func (h *authHandlers) adminListRoleServices(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	rows, err := h.q.ListRoleServices(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list services"})
	}
	items := make([]serviceDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, toServiceDTO(r))
	}
	return c.JSON(http.StatusOK, map[string][]serviceDTO{"items": items})
}

func (h *authHandlers) adminAssignRoleService(c *echo.Context) error {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	var req adminRoleServiceReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	svcID, err := uuid.Parse(req.ServiceID)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid service_id"})
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, roleID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	svc, err := h.q.GetServiceByID(ctx, svcID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "service not found"})
	}
	if err := h.q.AssignRoleService(ctx, db.AssignRoleServiceParams{RoleID: roleID, ServiceID: svcID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not assign service"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	rid := roleID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventRoleServiceAssigned,
		TargetType: audit.TargetRole,
		TargetID:   &rid,
		TargetName: role.Name,
		Metadata: map[string]any{
			"service_id":    svc.ID.String(),
			"service_title": svc.Title,
		},
	})
	return c.NoContent(http.StatusCreated)
}

func (h *authHandlers) adminRevokeRoleService(c *echo.Context) error {
	roleID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	svcID, err := uuid.Parse(c.Param("sid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid service id"})
	}
	ctx := c.Request().Context()
	role, _ := h.q.GetRoleByID(ctx, roleID)
	svc, _ := h.q.GetServiceByID(ctx, svcID)
	if err := h.q.RevokeRoleService(ctx, db.RevokeRoleServiceParams{RoleID: roleID, ServiceID: svcID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not revoke service"})
	}
	if h.cache != nil {
		h.cache.Invalidate()
	}
	rid := roleID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventRoleServiceRevoked,
		TargetType: audit.TargetRole,
		TargetID:   &rid,
		TargetName: role.Name,
		Metadata: map[string]any{
			"service_id":    svc.ID.String(),
			"service_title": svc.Title,
		},
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *authHandlers) adminListRoleUsers(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)
	rows, err := h.q.ListUsersInRole(ctx, db.ListUsersInRoleParams{RoleID: id, Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list users"})
	}
	total, err := h.q.CountUsersInRole(ctx, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count users"})
	}
	items := make([]userDTO, 0, len(rows))
	for _, u := range rows {
		roles, perms, _, err := h.loadUserAuthz(ctx, u.ID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not load roles"})
		}
		items = append(items, toDTO(u, roles, perms))
	}
	return c.JSON(http.StatusOK, adminUserListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}
