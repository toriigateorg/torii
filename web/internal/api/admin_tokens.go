package api

import (
	"crypto/subtle"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"sanmon/internal/audit"
	"sanmon/internal/auth"
	"sanmon/internal/db"
)

type tokenStatus string

const (
	tokenStatusActive  tokenStatus = "active"
	tokenStatusRevoked tokenStatus = "revoked"
	tokenStatusExpired tokenStatus = "expired"
)

type tokenSessionDTO struct {
	ID        string      `json:"id"`
	UserID    string      `json:"user_id"`
	Username  string      `json:"username"`
	Email     string      `json:"email"`
	CreatedAt string      `json:"created_at"`
	ExpiresAt string      `json:"expires_at"`
	RevokedAt *string     `json:"revoked_at"`
	Status    tokenStatus `json:"status"`
	IsCurrent bool        `json:"is_current"`
}

type adminTokenListResp struct {
	pageMeta
	Items []tokenSessionDTO `json:"items"`
}

func (h *authHandlers) adminListTokens(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListRefreshTokensWithUsers(ctx, db.ListRefreshTokensWithUsersParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list tokens"})
	}
	total, err := h.q.CountRefreshTokens(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count tokens"})
	}

	currentHash := callerRefreshHash(c)

	items := make([]tokenSessionDTO, 0, len(rows))
	for _, r := range rows {
		dto := tokenSessionDTO{
			ID:        r.ID.String(),
			UserID:    r.UserID.String(),
			Username:  r.Username,
			Email:     r.Email,
			CreatedAt: tsString(r.CreatedAt),
			ExpiresAt: tsString(r.ExpiresAt),
			Status:    classifyToken(r.ExpiresAt, r.RevokedAt),
		}
		if r.RevokedAt.Valid {
			s := tsString(r.RevokedAt)
			dto.RevokedAt = &s
		}
		if currentHash != nil && subtle.ConstantTimeCompare(currentHash, r.TokenHash) == 1 {
			dto.IsCurrent = true
		}
		items = append(items, dto)
	}
	return c.JSON(http.StatusOK, adminTokenListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminRevokeToken(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	ctx := c.Request().Context()

	row, err := h.q.GetRefreshTokenByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "token not found"})
	}

	if currentHash := callerRefreshHash(c); currentHash != nil &&
		subtle.ConstantTimeCompare(currentHash, row.TokenHash) == 1 {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot revoke your own current session; use /logout"})
	}

	if err := h.q.RevokeRefreshToken(ctx, id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not revoke token"})
	}
	tid := id
	targetUser := row.UserID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:  audit.EventTokenRevokedByAdmin,
		TargetType: audit.TargetToken,
		TargetID:   &tid,
		Metadata: map[string]any{
			"user_id":    targetUser.String(),
			"created_at": audit.TimestamptzToString(row.CreatedAt),
			"expires_at": audit.TimestamptzToString(row.ExpiresAt),
		},
	})
	return c.NoContent(http.StatusNoContent)
}

func (h *authHandlers) adminCleanupTokens(c *echo.Context) error {
	n, err := h.q.DeleteExpiredOrRevokedRefreshTokens(c.Request().Context())
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not cleanup tokens"})
	}
	h.auditor.LogFromEcho(c, audit.Event{
		EventType: audit.EventTokenCleanup,
		Metadata:  map[string]any{"deleted": n},
	})
	return c.JSON(http.StatusOK, map[string]int64{"deleted": n})
}

func callerRefreshHash(c *echo.Context) []byte {
	ck, err := c.Cookie(auth.RefreshCookie)
	if err != nil || ck.Value == "" {
		return nil
	}
	return auth.HashRefreshToken(ck.Value)
}

func tsString(t pgtype.Timestamptz) string {
	if !t.Valid {
		return ""
	}
	return t.Time.UTC().Format(time.RFC3339)
}

func classifyToken(expiresAt, revokedAt pgtype.Timestamptz) tokenStatus {
	if revokedAt.Valid {
		return tokenStatusRevoked
	}
	if expiresAt.Valid && time.Now().After(expiresAt.Time) {
		return tokenStatusExpired
	}
	return tokenStatusActive
}
