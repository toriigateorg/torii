package api

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/db"
)

type auditLogDTO struct {
	ID            string         `json:"id"`
	CreatedAt     string         `json:"created_at"`
	EventType     string         `json:"event_type"`
	ActorUserID   *string        `json:"actor_user_id"`
	ActorUsername string         `json:"actor_username"`
	TargetType    string         `json:"target_type"`
	TargetID      *string        `json:"target_id"`
	TargetName    string         `json:"target_name"`
	ClientIP      string         `json:"client_ip"`
	UserAgent     string         `json:"user_agent"`
	Metadata      map[string]any `json:"metadata"`
}

type adminAuditListResp struct {
	pageMeta
	Items []auditLogDTO `json:"items"`
}

func toAuditLogDTO(r db.AuditLog) auditLogDTO {
	dto := auditLogDTO{
		ID:            r.ID.String(),
		CreatedAt:     tsString(r.CreatedAt),
		EventType:     r.EventType,
		ActorUsername: r.ActorUsername,
		TargetType:    r.TargetType,
		TargetName:    r.TargetName,
		ClientIP:      r.ClientIp,
		UserAgent:     r.UserAgent,
	}
	if r.ActorUserID.Valid {
		s := r.ActorUserID.UUID.String()
		dto.ActorUserID = &s
	}
	if r.TargetID.Valid {
		s := r.TargetID.UUID.String()
		dto.TargetID = &s
	}
	if len(r.Metadata) > 0 {
		var m map[string]any
		if err := json.Unmarshal(r.Metadata, &m); err == nil {
			dto.Metadata = m
		}
	}
	if dto.Metadata == nil {
		dto.Metadata = map[string]any{}
	}
	return dto
}

func (h *authHandlers) adminListAuditLogs(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	params := db.ListAuditLogsParams{Lim: limit, Off: offset}
	countParams := db.CountAuditLogsParams{}

	if v := c.QueryParam("actor_user_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid actor_user_id"})
		}
		params.ActorUserID = uuid.NullUUID{UUID: id, Valid: true}
		countParams.ActorUserID = uuid.NullUUID{UUID: id, Valid: true}
	}
	if v := c.QueryParam("event_type"); v != "" {
		params.EventType = pgtype.Text{String: v, Valid: true}
		countParams.EventType = pgtype.Text{String: v, Valid: true}
	}
	if v := c.QueryParam("target_type"); v != "" {
		params.TargetType = pgtype.Text{String: v, Valid: true}
		countParams.TargetType = pgtype.Text{String: v, Valid: true}
	}
	if v := c.QueryParam("target_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid target_id"})
		}
		params.TargetID = uuid.NullUUID{UUID: id, Valid: true}
		countParams.TargetID = uuid.NullUUID{UUID: id, Valid: true}
	}
	if v := c.QueryParam("from"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid from (RFC3339)"})
		}
		params.FromTs = pgtype.Timestamptz{Time: t, Valid: true}
		countParams.FromTs = pgtype.Timestamptz{Time: t, Valid: true}
	}
	if v := c.QueryParam("to"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid to (RFC3339)"})
		}
		params.ToTs = pgtype.Timestamptz{Time: t, Valid: true}
		countParams.ToTs = pgtype.Timestamptz{Time: t, Valid: true}
	}

	rows, err := h.q.ListAuditLogs(ctx, params)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list audit logs"})
	}
	total, err := h.q.CountAuditLogs(ctx, countParams)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count audit logs"})
	}

	items := make([]auditLogDTO, 0, len(rows))
	for _, r := range rows {
		items = append(items, toAuditLogDTO(r))
	}
	return c.JSON(http.StatusOK, adminAuditListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}
