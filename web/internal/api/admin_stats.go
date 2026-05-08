package api

import (
	"net/http"
	"time"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"sanmon/internal/db"
)

type statsCounters struct {
	Users          int64 `json:"users"`
	Admins         int64 `json:"admins"`
	Services       int64 `json:"services"`
	Roles          int64 `json:"roles"`
	SSOProviders   int64 `json:"sso_providers"`
	ActiveSessions int64 `json:"active_sessions"`
}

type statsBucket struct {
	Day   string `json:"day"`
	Count int64  `json:"count"`
}

type statsTopService struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Domain      string `json:"domain"`
	AccessCount int64  `json:"access_count"`
}

type statsResp struct {
	Window      string            `json:"window"`
	Counters    statsCounters     `json:"counters"`
	Activity    []statsBucket     `json:"activity"`
	TopServices []statsTopService `json:"top_services"`
}

func parseStatsWindow(s string) (string, time.Duration) {
	switch s {
	case "30d":
		return "30d", 30 * 24 * time.Hour
	case "90d":
		return "90d", 90 * 24 * time.Hour
	default:
		return "7d", 7 * 24 * time.Hour
	}
}

func (h *authHandlers) adminGetStats(c *echo.Context) error {
	ctx := c.Request().Context()
	window, dur := parseStatsWindow(c.QueryParam("window"))

	now := time.Now().UTC()
	to := now
	// Anchor `from` to UTC midnight at the start of the window so the daily
	// buckets line up cleanly and the chart always shows whole days.
	startDay := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	from := startDay.Add(-dur).Add(24 * time.Hour) // include today, exclude oldest day's predecessor

	users, err := h.q.CountUsers(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count users"})
	}
	admins, err := h.q.CountAdmins(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count admins"})
	}
	services, err := h.q.CountServices(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count services"})
	}
	roles, err := h.q.CountRoles(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count roles"})
	}
	ssoProviders, err := h.q.CountSSOProviders(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count sso providers"})
	}
	activeSessions, err := h.q.CountActiveRefreshTokens(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count active sessions"})
	}

	rangeFrom := pgtype.Timestamptz{Time: from, Valid: true}
	rangeTo := pgtype.Timestamptz{Time: to, Valid: true}

	dayRows, err := h.q.CountAuditLogsByDay(ctx, db.CountAuditLogsByDayParams{
		FromTs: rangeFrom,
		ToTs:   rangeTo,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not aggregate audit logs"})
	}

	// Pad the series so every day in the window has a bucket, even zero ones.
	days := int(dur / (24 * time.Hour))
	activity := make([]statsBucket, 0, days)
	byDay := make(map[string]int64, len(dayRows))
	for _, r := range dayRows {
		if r.Day.Valid {
			byDay[r.Day.Time.UTC().Format("2006-01-02")] = r.Count
		}
	}
	for i := 0; i < days; i++ {
		d := startDay.Add(time.Duration(-(days-1-i)) * 24 * time.Hour)
		key := d.Format("2006-01-02")
		activity = append(activity, statsBucket{Day: key, Count: byDay[key]})
	}

	topRows, err := h.q.TopServicesByAccess(ctx, db.TopServicesByAccessParams{
		FromTs: rangeFrom,
		ToTs:   rangeTo,
		Lim:    5,
	})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list top services"})
	}
	topServices := make([]statsTopService, 0, len(topRows))
	for _, r := range topRows {
		topServices = append(topServices, statsTopService{
			ID:          r.ID.String(),
			Title:       r.Title,
			Domain:      r.Domain,
			AccessCount: r.AccessCount,
		})
	}

	return c.JSON(http.StatusOK, statsResp{
		Window: window,
		Counters: statsCounters{
			Users:          users,
			Admins:         admins,
			Services:       services,
			Roles:          roles,
			SSOProviders:   ssoProviders,
			ActiveSessions: activeSessions,
		},
		Activity:    activity,
		TopServices: topServices,
	})
}
