package api

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/db"
)

const settingSignupEnabled = "signup_enabled"

type settingsDTO struct {
	SignupEnabled bool `json:"signup_enabled"`
}

type updateSettingsReq struct {
	SignupEnabled *bool `json:"signup_enabled"`
}

func (h *authHandlers) getBoolSetting(ctx context.Context, key string, def bool) bool {
	return getBoolSettingWith(ctx, h.q, key, def)
}

// getBoolSettingWith reads a setting through a caller-supplied querier.
//
// Callers holding an open transaction must pass their own qtx, never h.q: h.q
// issues on the pool, so reading a setting on it while a transaction is checked
// out is a second connection acquisition made while holding the first. signup did
// exactly that under an advisory lock, which turned four concurrent unauthenticated
// requests into a pool-wide deadlock.
func getBoolSettingWith(ctx context.Context, q *db.Queries, key string, def bool) bool {
	row, err := q.GetSetting(ctx, key)
	if err != nil {
		return def
	}
	switch row.Value {
	case "true", "1", "yes":
		return true
	case "false", "0", "no":
		return false
	}
	return def
}

func (h *authHandlers) currentSettings(ctx context.Context) settingsDTO {
	return settingsDTO{
		SignupEnabled: h.getBoolSetting(ctx, settingSignupEnabled, true),
	}
}

func (h *authHandlers) adminGetSettings(c *echo.Context) error {
	return c.JSON(http.StatusOK, h.currentSettings(c.Request().Context()))
}

func (h *authHandlers) adminUpdateSettings(c *echo.Context) error {
	var req updateSettingsReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	ctx := c.Request().Context()
	if req.SignupEnabled != nil {
		before := h.getBoolSetting(ctx, settingSignupEnabled, true)
		val := "false"
		if *req.SignupEnabled {
			val = "true"
		}
		if _, err := h.q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingSignupEnabled, Value: val}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not update settings"})
		}
		h.auditor.LogFromEcho(c, audit.Event{
			EventType:  audit.EventSettingsUpdated,
			TargetType: audit.TargetSetting,
			TargetName: settingSignupEnabled,
			Metadata: map[string]any{
				"key":    settingSignupEnabled,
				"before": before,
				"after":  *req.SignupEnabled,
			},
		})
	}
	return c.JSON(http.StatusOK, h.currentSettings(ctx))
}
