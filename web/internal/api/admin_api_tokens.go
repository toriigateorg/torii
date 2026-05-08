package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/db"
)

type apiTokenDTO struct {
	ID         string  `json:"id"`
	UserID     string  `json:"user_id"`
	Username   string  `json:"username"`
	Email      string  `json:"email"`
	Name       string  `json:"name"`
	Prefix     string  `json:"prefix"`
	CreatedAt  string  `json:"created_at"`
	ExpiresAt  *string `json:"expires_at"`
	LastUsedAt *string `json:"last_used_at"`
}

type apiTokenCreateDTO struct {
	apiTokenDTO
	Token string `json:"token"`
}

type adminAPITokenListResp struct {
	pageMeta
	Items []apiTokenDTO `json:"items"`
}

type adminAPITokenCreateReq struct {
	UserID    string  `json:"user_id"`
	Name      string  `json:"name"`
	ExpiresAt *string `json:"expires_at"`
}

func nullableTSString(t pgtype.Timestamptz) *string {
	if !t.Valid {
		return nil
	}
	s := t.Time.UTC().Format(time.RFC3339)
	return &s
}

func (h *authHandlers) adminListAPITokens(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListAPITokensWithUsers(ctx, db.ListAPITokensWithUsersParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list api tokens"})
	}
	total, err := h.q.CountAPITokens(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count api tokens"})
	}

	items := make([]apiTokenDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, apiTokenDTO{
			ID:         r.ID.String(),
			UserID:     r.UserID.String(),
			Username:   r.Username,
			Email:      r.Email,
			Name:       r.Name,
			Prefix:     r.TokenPrefix,
			CreatedAt:  tsString(r.CreatedAt),
			ExpiresAt:  nullableTSString(r.ExpiresAt),
			LastUsedAt: nullableTSString(r.LastUsedAt),
		})
	}
	return c.JSON(http.StatusOK, adminAPITokenListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminCreateAPIToken(c *echo.Context) error {
	var req adminAPITokenCreateReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Name = strings.TrimSpace(req.Name)
	if n := len(req.Name); n < 1 || n > 200 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "name must be 1-200 chars"})
	}
	userID, err := uuid.Parse(strings.TrimSpace(req.UserID))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid user_id"})
	}

	var expiresAt pgtype.Timestamptz
	if req.ExpiresAt != nil && strings.TrimSpace(*req.ExpiresAt) != "" {
		t, err := time.Parse(time.RFC3339, strings.TrimSpace(*req.ExpiresAt))
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "expires_at must be RFC3339"})
		}
		if t.Before(time.Now()) {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "expires_at is in the past"})
		}
		expiresAt = pgtype.Timestamptz{Time: t, Valid: true}
	}

	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, userID)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}

	raw, hash, prefix, err := auth.NewAPIToken()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not generate token"})
	}

	row, err := h.q.CreateAPIToken(ctx, db.CreateAPITokenParams{
		UserID:      user.ID,
		Name:        req.Name,
		TokenHash:   hash,
		TokenPrefix: prefix,
		ExpiresAt:   expiresAt,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create api token"})
	}

	tid := row.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAPITokenCreated,
		TargetType: audit.TargetAPIToken,
		TargetID:   &tid,
		TargetName: row.Name,
		Metadata: map[string]any{
			"user_id":  user.ID.String(),
			"username": user.Username,
		},
	})

	return c.JSON(http.StatusCreated, apiTokenCreateDTO{
		apiTokenDTO: apiTokenDTO{
			ID:         row.ID.String(),
			UserID:     row.UserID.String(),
			Username:   user.Username,
			Email:      user.Email,
			Name:       row.Name,
			Prefix:     row.TokenPrefix,
			CreatedAt:  tsString(row.CreatedAt),
			ExpiresAt:  nullableTSString(row.ExpiresAt),
			LastUsedAt: nullableTSString(row.LastUsedAt),
		},
		Token: raw,
	})
}

func (h *authHandlers) adminDeleteAPIToken(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()
	row, err := h.q.GetAPITokenByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}
	if err := h.q.DeleteAPIToken(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete api token"})
	}
	tid := id
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventAPITokenDeleted,
		TargetType: audit.TargetAPIToken,
		TargetID:   &tid,
		TargetName: row.Name,
		Metadata:   map[string]any{"user_id": row.UserID.String()},
	})
	return c.NoContent(http.StatusNoContent)
}

// resolveAPIToken is wired into auth.SetAPITokenResolver during Register so
// auth.RequireUser/RequirePermission accept `Authorization: Bearer torii_pat_*`
// in addition to JWTs. It loads the owning user's permissions and role ids and
// returns a Claims value with the same shape as a freshly-issued access token.
func (h *authHandlers) resolveAPIToken(ctx context.Context, raw string) (*auth.Claims, error) {
	hash := auth.HashAPIToken(raw)
	row, err := h.q.GetAPITokenByHash(ctx, hash)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, errors.New("invalid api token")
		}
		return nil, err
	}
	if row.ExpiresAt.Valid && time.Now().After(row.ExpiresAt.Time) {
		return nil, errors.New("api token expired")
	}

	user, err := h.q.GetUserByID(ctx, row.UserID)
	if err != nil {
		return nil, errors.New("api token owner missing")
	}
	perms, err := h.q.GetUserPermissions(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	roleIDs, err := h.q.GetUserRoleIDs(ctx, user.ID)
	if err != nil {
		return nil, err
	}
	if perms == nil {
		perms = []string{}
	}
	roleStrs := make([]string, len(roleIDs))
	for i, r := range roleIDs {
		roleStrs[i] = r.String()
	}

	go func(id uuid.UUID) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = h.q.TouchAPITokenLastUsed(ctx, id)
	}(row.ID)

	claims := &auth.Claims{
		Username:    user.Username,
		Permissions: perms,
		RoleIDs:     roleStrs,
	}
	claims.Subject = user.ID.String()
	return claims, nil
}
