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

const (
	errCannotGrantRole  = "forbidden: cannot grant a role conferring permissions or service access you do not hold"
	errCannotRevokeRole = "forbidden: cannot revoke a role you could not grant"
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
	// Lowercased to match signin's case-folding; see the note in signup.
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
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

// callerOutranksTarget reports whether the caller's own permission set is a
// superset of the target user's. Without it, a delegated operator holding a
// single write permission (users.update) could act on an account more
// privileged than their own — resetting an admin's password and then signing
// in as them, since signin loads the target's live roles into the JWT.
func (h *authHandlers) callerOutranksTarget(ctx context.Context, claims *auth.Claims, targetID uuid.UUID) (bool, error) {
	if claims == nil {
		return false, nil
	}
	if claims.Subject == targetID.String() {
		return true, nil
	}
	targetPerms, err := h.q.GetUserPermissions(ctx, targetID)
	if err != nil {
		return false, err
	}
	return callerHoldsAll(claims, targetPerms), nil
}

// guardOutranksTarget applies callerOutranksTarget, writing the 403 and the
// audit trail when it fails. It returns (true, nil) when the caller may act on
// the target; otherwise the returned error is the response and the caller must
// return it. action reads into "cannot <action> a more privileged user".
func (h *authHandlers) guardOutranksTarget(c *echo.Context, targetID uuid.UUID, targetName, action string) (bool, error) {
	ctx := c.Request().Context()
	ok, err := h.callerOutranksTarget(ctx, auth.ClaimsFrom(c), targetID)
	if err != nil {
		return false, c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if ok {
		return true, nil
	}
	id := targetID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAuthzDenied,
		TargetType: audit.TargetUser,
		TargetID:   &id,
		TargetName: targetName,
		Metadata: map[string]any{
			"reason": "target holds permissions the caller lacks",
			"path":   c.Request().URL.Path,
			"method": c.Request().Method,
		},
	})
	return false, c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: cannot " + action + " a more privileged user"})
}

// callerCanGrantRole reports whether the caller may hand out a role: only if
// every authority the role carries is one the caller already holds. Assigning a
// role the caller doesn't fully hold — the admin role above all — is privilege
// escalation, since the grantee's next token refresh reloads roles and
// permissions from the DB.
//
// A role carries two independent authorities: control-plane permissions
// (role_permissions) and upstream access (role_services). Both must be covered.
func (h *authHandlers) callerCanGrantRole(ctx context.Context, claims *auth.Claims, roleID uuid.UUID) (bool, error) {
	if claims == nil {
		return false, nil
	}
	rolePerms, err := h.q.ListRolePermissions(ctx, roleID)
	if err != nil {
		return false, err
	}
	if !callerHoldsAll(claims, rolePerms) {
		return false, nil
	}
	return h.callerReachesRoleServices(ctx, claims, roleID)
}

// callerReachesRoleServices reports whether every upstream a role grants is one
// the caller can already reach. Checking permissions alone leaves the common
// case wide open: a role with zero permissions but service bindings looks empty
// to callerHoldsAll, yet the admin UI documents exactly those permission-less
// roles as the way to model who can reach which app.
func (h *authHandlers) callerReachesRoleServices(ctx context.Context, claims *auth.Claims, roleID uuid.UUID) (bool, error) {
	roleServices, err := h.q.ListRoleServices(ctx, roleID)
	if err != nil {
		return false, err
	}
	if len(roleServices) == 0 {
		return true, nil
	}
	// role_services.create already lets its holder bind any service to any role,
	// so requiring them to reach the service first would gate nothing.
	if claims.Has(auth.PermRoleServicesCreate) {
		return true, nil
	}
	callerID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return false, nil
	}
	reachable, err := h.q.ListServicesForUser(ctx, callerID)
	if err != nil {
		return false, err
	}
	held := make(map[uuid.UUID]struct{}, len(reachable))
	for _, s := range reachable {
		held[s.ID] = struct{}{}
	}
	for _, s := range roleServices {
		if _, ok := held[s.ID]; !ok {
			return false, nil
		}
	}
	return true, nil
}

func (h *authHandlers) logRoleGrantDenied(c *echo.Context, targetType string, targetID uuid.UUID, targetName string, role db.Role) {
	id := targetID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAuthzDenied,
		TargetType: targetType,
		TargetID:   &id,
		TargetName: targetName,
		Metadata: map[string]any{
			"reason":    "role confers permissions or service access the caller does not hold",
			"role_id":   role.ID.String(),
			"role_name": role.Name,
			"path":      c.Request().URL.Path,
			"method":    c.Request().Method,
		},
	})
}

func callerHoldsAll(claims *auth.Claims, perms []string) bool {
	held := make(map[string]struct{}, len(claims.Permissions))
	for _, p := range claims.Permissions {
		held[p] = struct{}{}
	}
	for _, p := range perms {
		if _, ok := held[p]; !ok {
			return false
		}
	}
	return true
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
