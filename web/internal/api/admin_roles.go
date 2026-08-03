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
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
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

// Permissions is a pointer so an absent key is distinguishable from an explicit
// empty list. Echo's BindBody returns early on ContentLength == 0 without
// touching the target, so a plain []string left a Content-Length: 0 PUT looking
// exactly like a deliberate "set this role's permissions to none".
type adminRolePermissionsReq struct {
	Permissions *[]string `json:"permissions"`
}

type adminRoleServiceReq struct {
	ServiceID string `json:"service_id"`
	// ConfirmPublicExposure must be set to bind a service to the system 'all'
	// role, which every account carries. See adminAssignRoleService.
	ConfirmPublicExposure bool `json:"confirm_public_exposure"`
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

	var search pgtype.Text
	if q := strings.TrimSpace(c.QueryParam("search")); q != "" {
		search = pgtype.Text{String: q, Valid: true}
	}

	rows, err := h.q.ListRoles(ctx, db.ListRolesParams{Lim: limit, Off: offset, Search: search})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list roles"})
	}
	total, err := h.q.CountFilteredRoles(ctx, search)
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
	// Same subset check the update path enforces. Without it, roles.create alone
	// authored a role carrying permissions the creator does not hold: the creator
	// can't assign it (callerCanGrantRole blocks that), but it sits there as a
	// benign-sounding trap waiting for a real administrator to hand it out, and
	// the assignment dialog shows name and description rather than permissions.
	claims := auth.ClaimsFrom(c)
	if claims == nil || !callerHoldsAll(claims, req.Permissions) {
		h.auditor.LogFromEcho(c, audit.Event{
			EventType:  audit.EventAuthzDenied,
			TargetType: audit.TargetRole,
			TargetName: req.Name,
			Metadata: map[string]any{
				"reason": "requested permissions exceed the caller's own",
				"path":   c.Request().URL.Path,
				"method": c.Request().Method,
			},
		})
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: cannot grant permissions you do not hold"})
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
	if req.Permissions == nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "permissions is required"})
	}
	perms := *req.Permissions
	for _, p := range perms {
		if !auth.IsValidPermission(p) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "unknown permission: " + p})
		}
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	// Both system roles are off limits: admin is the full permission set, and
	// 'all' is auto-assigned to every account, so a write here grants whatever
	// it contains to the entire user base.
	if role.IsSystem && (role.Name == "admin" || role.Name == "all") {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot edit permissions on the " + role.Name + " role"})
	}
	beforePerms, _ := h.q.ListRolePermissions(ctx, id)
	if beforePerms == nil {
		beforePerms = []string{}
	}

	// A caller can only put permissions into a role that they already hold
	// themselves — otherwise roles.update alone escalates to anything.
	//
	// The role's *current* permissions are checked too, because this is a
	// wholesale replace: authorizing only the incoming list made
	// callerHoldsAll(claims, nil) vacuously true, so anyone with roles.update
	// could empty any non-system role and silently strip every delegated
	// administrator holding it — recoverable only by someone who still had the
	// permissions being restored.
	claims := auth.ClaimsFrom(c)
	if claims == nil || !callerHoldsAll(claims, perms) || !callerHoldsAll(claims, beforePerms) {
		h.auditor.LogFromEcho(c, audit.Event{
			EventType:  audit.EventAuthzDenied,
			TargetType: audit.TargetRole,
			TargetID:   &id,
			TargetName: role.Name,
			Metadata: map[string]any{
				"reason": "requested or existing permissions exceed the caller's own",
				"path":   c.Request().URL.Path,
				"method": c.Request().Method,
			},
		})
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: cannot grant or remove permissions you do not hold"})
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
	for _, p := range perms {
		if err := qtx.InsertRolePermission(ctx, db.InsertRolePermissionParams{RoleID: id, Permission: p}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	out := perms
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
	// 'all' is auto-assigned to every account, so binding a service to it
	// publishes that upstream to the entire user base. That is a categorically
	// different act from granting one team access, and role_services.create is a
	// delegated permission — so require it to be stated deliberately rather than
	// being one indistinguishable checkbox among the others.
	if role.IsSystem && role.Name == "all" && !req.ConfirmPublicExposure {
		return c.JSON(http.StatusConflict, map[string]string{
			"error": "binding a service to the 'all' role exposes it to every account; set confirm_public_exposure to proceed",
		})
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
			"service_id":      svc.ID.String(),
			"service_title":   svc.Title,
			"public_exposure": role.IsSystem && role.Name == "all",
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
