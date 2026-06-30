package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
)

type apiUserDTO struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Description string  `json:"description"`
	Prefix      string  `json:"prefix"`
	Disabled    bool    `json:"disabled"`
	CreatedAt   string  `json:"created_at"`
	ExpiresAt   *string `json:"expires_at"`
	LastUsedAt  *string `json:"last_used_at"`
}

type apiUserCreateDTO struct {
	apiUserDTO
	Token string `json:"token"`
}

type adminAPIUserListResp struct {
	pageMeta
	Items []apiUserDTO `json:"items"`
}

type adminAPIUserCreateReq struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	RoleIDs     []string `json:"role_ids"`
	ExpiresAt   *string  `json:"expires_at"`
}

type adminAPIUserRegenerateReq struct {
	ExpiresAt *string `json:"expires_at"`
}

func toAPIUserDTO(u db.ApiUser) apiUserDTO {
	return apiUserDTO{
		ID:          u.ID.String(),
		Name:        u.Name,
		Description: u.Description,
		Prefix:      u.TokenPrefix,
		Disabled:    u.Disabled,
		CreatedAt:   tsString(u.CreatedAt),
		ExpiresAt:   nullableTSString(u.ExpiresAt),
		LastUsedAt:  nullableTSString(u.LastUsedAt),
	}
}

// parseExpiresAt reads an optional RFC3339 expiry from the request, rejecting
// past timestamps. Shared by create and regenerate.
func parseExpiresAt(raw *string) (pgtype.Timestamptz, error) {
	if raw == nil || strings.TrimSpace(*raw) == "" {
		return pgtype.Timestamptz{}, nil
	}
	t, err := time.Parse(time.RFC3339, strings.TrimSpace(*raw))
	if err != nil {
		return pgtype.Timestamptz{}, errors.New("expires_at must be RFC3339")
	}
	if t.Before(time.Now()) {
		return pgtype.Timestamptz{}, errors.New("expires_at is in the past")
	}
	return pgtype.Timestamptz{Time: t, Valid: true}, nil
}

func (h *authHandlers) adminListAPIUsers(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListAPIUsers(ctx, db.ListAPIUsersParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list api users"})
	}
	total, err := h.q.CountAPIUsers(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count api users"})
	}

	items := make([]apiUserDTO, 0, len(rows))
	for _, u := range rows {
		items = append(items, toAPIUserDTO(u))
	}
	return c.JSON(http.StatusOK, adminAPIUserListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminGetAPIUser(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	u, err := h.q.GetAPIUserByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "api user not found"})
	}
	return c.JSON(http.StatusOK, toAPIUserDTO(u))
}

func (h *authHandlers) adminCreateAPIUser(c *echo.Context) error {
	var req adminAPIUserCreateReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Name = strings.TrimSpace(req.Name)
	req.Description = strings.TrimSpace(req.Description)
	if n := len(req.Name); n < 1 || n > 200 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name must be 1-200 chars"})
	}
	if len(req.Description) > 2000 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "description must be at most 2000 chars"})
	}
	expiresAt, err := parseExpiresAt(req.ExpiresAt)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	ctx := c.Request().Context()

	// Resolve and validate the requested roles up front so a bad role id fails
	// before we mint a token.
	roleIDs := make([]uuid.UUID, 0, len(req.RoleIDs))
	for _, raw := range req.RoleIDs {
		rid, err := uuid.Parse(strings.TrimSpace(raw))
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role_id"})
		}
		role, err := h.q.GetRoleByID(ctx, rid)
		if err != nil {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		if role.IsSystem && role.Name == "all" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "the 'all' role is auto-assigned and cannot be managed"})
		}
		roleIDs = append(roleIDs, rid)
	}

	raw, hash, prefix, err := auth.NewServiceAPIToken()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate token"})
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)

	row, err := qtx.CreateAPIUser(ctx, db.CreateAPIUserParams{
		Name:        req.Name,
		Description: req.Description,
		TokenHash:   hash,
		TokenPrefix: prefix,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "name already taken"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create api user"})
	}
	for _, rid := range roleIDs {
		if err := qtx.AssignAPIUserRole(ctx, db.AssignAPIUserRoleParams{ApiUserID: row.ID, RoleID: rid}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not assign role"})
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	aid := row.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAPIUserCreated,
		TargetType: audit.TargetAPIUser,
		TargetID:   &aid,
		TargetName: row.Name,
	})

	return c.JSON(http.StatusCreated, apiUserCreateDTO{
		apiUserDTO: toAPIUserDTO(row),
		Token:      raw,
	})
}

func (h *authHandlers) adminRegenerateAPIUserToken(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	var req adminAPIUserRegenerateReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	expiresAt, err := parseExpiresAt(req.ExpiresAt)
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
	}

	ctx := c.Request().Context()
	if _, err := h.q.GetAPIUserByID(ctx, id); err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "api user not found"})
	}

	raw, hash, prefix, err := auth.NewServiceAPIToken()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate token"})
	}
	row, err := h.q.UpdateAPIUserToken(ctx, db.UpdateAPIUserTokenParams{
		ID:          id,
		TokenHash:   hash,
		TokenPrefix: prefix,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not regenerate token"})
	}

	aid := row.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAPIUserTokenRegenerated,
		TargetType: audit.TargetAPIUser,
		TargetID:   &aid,
		TargetName: row.Name,
	})

	return c.JSON(http.StatusOK, apiUserCreateDTO{
		apiUserDTO: toAPIUserDTO(row),
		Token:      raw,
	})
}

func (h *authHandlers) adminDeleteAPIUser(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	row, err := h.q.GetAPIUserByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "api user not found"})
	}
	if err := h.q.DeleteAPIUser(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete api user"})
	}
	aid := id
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAPIUserDeleted,
		TargetType: audit.TargetAPIUser,
		TargetID:   &aid,
		TargetName: row.Name,
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *authHandlers) adminListAPIUserRoles(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	rows, err := h.q.ListAPIUserRoles(c.Request().Context(), id)
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

func (h *authHandlers) adminAssignAPIUserRole(c *echo.Context) error {
	apiUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid api user id"})
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
	apiUser, err := h.q.GetAPIUserByID(ctx, apiUserID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "api user not found"})
	}
	role, err := h.q.GetRoleByID(ctx, roleID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
	}
	if role.IsSystem && role.Name == "all" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "the 'all' role is auto-assigned and cannot be managed"})
	}
	if err := h.q.AssignAPIUserRole(ctx, db.AssignAPIUserRoleParams{ApiUserID: apiUserID, RoleID: roleID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not assign role"})
	}
	aid := apiUser.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventUserRoleAssigned,
		TargetType: audit.TargetAPIUser,
		TargetID:   &aid,
		TargetName: apiUser.Name,
		Metadata: map[string]any{
			"role_id":   role.ID.String(),
			"role_name": role.Name,
		},
	})
	return c.NoContent(http.StatusCreated)
}

func (h *authHandlers) adminRevokeAPIUserRole(c *echo.Context) error {
	apiUserID, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid api user id"})
	}
	roleID, err := uuid.Parse(c.Param("rid"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid role id"})
	}
	ctx := c.Request().Context()
	role, err := h.q.GetRoleByID(ctx, roleID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusNotFound, map[string]string{"error": "role not found"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	apiUser, _ := h.q.GetAPIUserByID(ctx, apiUserID)
	if err := h.q.RevokeAPIUserRole(ctx, db.RevokeAPIUserRoleParams{ApiUserID: apiUserID, RoleID: roleID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not revoke role"})
	}
	aid := apiUserID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventUserRoleRevoked,
		TargetType: audit.TargetAPIUser,
		TargetID:   &aid,
		TargetName: apiUser.Name,
		Metadata: map[string]any{
			"role_id":   role.ID.String(),
			"role_name": role.Name,
		},
	})
	return c.NoContent(http.StatusNoContent)
}

// resolveServiceToken is wired into auth.SetServiceTokenResolver during Register
// so the reverse-proxy dispatch accepts `Authorization: Bearer torii_sat_*` for
// a Service API user. It loads the api user's role ids for RBAC. Permissions are
// intentionally empty: a service token can never satisfy a control-plane gate.
func (h *authHandlers) resolveServiceToken(ctx context.Context, raw string) (*auth.Claims, error) {
	hash := auth.HashAPIToken(raw)
	row, err := h.q.GetAPIUserByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid service token")
		}
		return nil, err
	}
	if row.Disabled {
		return nil, errors.New("service api user disabled")
	}
	if row.ExpiresAt.Valid && time.Now().After(row.ExpiresAt.Time) {
		return nil, errors.New("service token expired")
	}

	roleIDs, err := h.q.GetAPIUserRoleIDs(ctx, row.ID)
	if err != nil {
		return nil, err
	}
	roleStrs := make([]string, len(roleIDs))
	for i, r := range roleIDs {
		roleStrs[i] = r.String()
	}

	scheduleTouchAPIUser(h.q, row.ID)

	claims := &auth.Claims{
		Username:    row.Name,
		Permissions: []string{},
		RoleIDs:     roleStrs,
	}
	claims.Subject = row.ID.String()
	return claims, nil
}
