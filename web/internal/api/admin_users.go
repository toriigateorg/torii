package api

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
)

type adminUserListResp struct {
	pageMeta
	Items []userDTO `json:"items"`
}

type adminCreateUserReq struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	// SsoOnly creates the account with no password hash, so it can only sign in
	// through an SSO provider. A password must not be supplied alongside it.
	SsoOnly bool `json:"sso_only"`
}

func (h *authHandlers) adminListUsers(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	var search pgtype.Text
	if q := strings.TrimSpace(c.QueryParam("search")); q != "" {
		search = pgtype.Text{String: q, Valid: true}
	}

	rows, err := h.q.ListUsers(ctx, db.ListUsersParams{Lim: limit, Off: offset, Search: search})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list users"})
	}
	total, err := h.q.CountFilteredUsers(ctx, search)
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

func (h *authHandlers) adminCreateUser(c *echo.Context) error {
	var req adminCreateUserReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)

	if !usernameRe.MatchString(req.Username) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "username must be 3-64 chars: letters, digits, _ . -"})
	}
	if !emailRe.MatchString(req.Email) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid email"})
	}
	// An sso_only account carries no password hash; it authenticates purely via
	// an SSO provider. Reject a password supplied alongside the flag so callers
	// don't think one was set.
	passwordHash := pgtype.Text{Valid: false}
	if req.SsoOnly {
		if req.Password != "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "password must not be set for an sso_only user"})
		}
	} else {
		if h.cfg.IsProd() {
			if err := auth.ValidatePasswordStrength(req.Password); err != nil {
				return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
			}
		} else if req.Password == "" {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "password required"})
		}
		hash, err := auth.HashPassword(req.Password)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
		passwordHash = pgtype.Text{String: hash, Valid: true}
	}

	ctx := c.Request().Context()

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	defer tx.Rollback(ctx)
	qtx := h.q.WithTx(tx)

	user, err := qtx.CreateUser(ctx, db.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		PasswordHash: passwordHash,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "username or email already taken"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create user"})
	}
	allRole, err := qtx.GetRoleByName(ctx, "all")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if err := qtx.AssignUserRole(ctx, db.AssignUserRoleParams{UserID: user.ID, RoleID: allRole.ID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	uid := user.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventUserCreated,
		TargetType: audit.TargetUser,
		TargetID:   &uid,
		TargetName: user.Username,
		Metadata:   map[string]any{"after": audit.SnapshotUser(user)},
	})

	roles, perms, _, err := h.loadUserAuthz(ctx, user.ID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not load roles"})
	}
	return c.JSON(http.StatusCreated, toDTO(user, roles, perms))
}

func (h *authHandlers) adminDeleteUser(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	claims := auth.ClaimsFrom(c)
	if claims != nil && claims.Subject == id.String() {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete your own account"})
	}
	ctx := c.Request().Context()

	if sole, err := h.userIsSoleAdmin(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	} else if sole {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete the sole admin user"})
	}

	target, _ := h.q.GetUserByID(ctx, id)
	if err := h.q.DeleteUser(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete user"})
	}
	uid := id
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventUserDeleted,
		TargetType: audit.TargetUser,
		TargetID:   &uid,
		TargetName: target.Username,
		Metadata:   map[string]any{"before": audit.SnapshotUser(target)},
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *authHandlers) userIsSoleAdmin(ctx context.Context, userID uuid.UUID) (bool, error) {
	roles, err := h.q.ListUserRoles(ctx, userID)
	if err != nil {
		return false, err
	}
	hasAdmin := false
	for _, r := range roles {
		if r.Name == "admin" {
			hasAdmin = true
			break
		}
	}
	if !hasAdmin {
		return false, nil
	}
	count, err := h.q.CountAdmins(ctx)
	if err != nil {
		return false, err
	}
	return count <= 1, nil
}
