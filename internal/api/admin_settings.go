package api

import (
	"context"
	"net/http"

	"github.com/labstack/echo/v5"

	"sanmon/internal/db"
)

const settingSignupEnabled = "signup_enabled"

type settingsDTO struct {
	SignupEnabled bool `json:"signup_enabled"`
}

type updateSettingsReq struct {
	SignupEnabled *bool `json:"signup_enabled"`
}

func (h *authHandlers) getBoolSetting(ctx context.Context, key string, def bool) bool {
	row, err := h.q.GetSetting(ctx, key)
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
		val := "false"
		if *req.SignupEnabled {
			val = "true"
		}
		if _, err := h.q.UpsertSetting(ctx, db.UpsertSettingParams{Key: settingSignupEnabled, Value: val}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not update settings"})
		}
	}
	return c.JSON(http.StatusOK, h.currentSettings(ctx))
}
