package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"torii/internal/auth"
	"torii/internal/db"
)

const (
	ProxyAccessDebounce = 5 * time.Minute

	TargetUser        = "user"
	TargetRole        = "role"
	TargetService     = "service"
	TargetSSOProvider = "sso_provider"
	TargetSetting     = "setting"
	TargetToken       = "refresh_token"
	TargetRoleService = "role_service"
	TargetUserRole    = "user_role"

	EventSignupSuccess        = "auth.signup.success"
	EventSignupFailed         = "auth.signup.failed"
	EventSigninSuccess        = "auth.signin.success"
	EventSigninFailed         = "auth.signin.failed"
	EventSigninSSO            = "auth.signin.sso"
	EventLogout               = "auth.logout"
	EventTokenRefreshFailed   = "auth.token_refresh.failed"
	EventAuthzDenied          = "authz.denied"
	EventUserCreated          = "rbac.user.created"
	EventUserDeleted          = "rbac.user.deleted"
	EventRoleCreated          = "rbac.role.created"
	EventRoleUpdated          = "rbac.role.updated"
	EventRoleDeleted          = "rbac.role.deleted"
	EventRolePermsChanged     = "rbac.role.permissions_changed"
	EventRoleServiceAssigned  = "rbac.role.service_assigned"
	EventRoleServiceRevoked   = "rbac.role.service_revoked"
	EventUserRoleAssigned     = "rbac.user_role.assigned"
	EventUserRoleRevoked      = "rbac.user_role.revoked"
	EventServiceCreated       = "service.created"
	EventServiceUpdated       = "service.updated"
	EventServiceDeleted       = "service.deleted"
	EventSSOProviderCreated   = "sso.provider.created"
	EventSSOProviderUpdated   = "sso.provider.updated"
	EventSSOProviderDeleted   = "sso.provider.deleted"
	EventSettingsUpdated      = "settings.updated"
	EventTokenRevokedByAdmin  = "token.revoked_by_admin"
	EventTokenCleanup         = "token.cleanup"
	EventProxyAccess          = "proxy.access"
	EventProxyDenied          = "proxy.denied"
)

type Logger struct {
	q        *db.Queries
	file     *os.File
	fileMu   sync.Mutex
	debounce sync.Map // key "userID|serviceID" -> time.Time
}

type Event struct {
	EventType     string
	ActorUserID   *uuid.UUID
	ActorUsername string
	TargetType    string
	TargetID      *uuid.UUID
	TargetName    string
	ClientIP      string
	UserAgent     string
	Metadata      map[string]any
}

func New(q *db.Queries, dir string) (*Logger, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("audit: open %s: %w", path, err)
	}
	return &Logger{q: q, file: f}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	return l.file.Close()
}

func (l *Logger) Log(ctx context.Context, e Event) {
	if l == nil {
		return
	}
	now := time.Now().UTC()

	metaBytes, err := json.Marshal(e.Metadata)
	if err != nil || metaBytes == nil {
		metaBytes = []byte("{}")
	}

	var actorID, targetID uuid.NullUUID
	if e.ActorUserID != nil {
		actorID = uuid.NullUUID{UUID: *e.ActorUserID, Valid: true}
	}
	if e.TargetID != nil {
		targetID = uuid.NullUUID{UUID: *e.TargetID, Valid: true}
	}

	if l.q != nil {
		_, dbErr := l.q.InsertAuditLog(ctx, db.InsertAuditLogParams{
			EventType:     e.EventType,
			ActorUserID:   actorID,
			ActorUsername: e.ActorUsername,
			TargetType:    e.TargetType,
			TargetID:      targetID,
			TargetName:    e.TargetName,
			ClientIp:      e.ClientIP,
			UserAgent:     e.UserAgent,
			Metadata:      metaBytes,
		})
		if dbErr != nil {
			fmt.Fprintln(os.Stderr, "[audit] db insert failed:", dbErr)
		}
	}

	line := map[string]any{
		"ts":             now.Format(time.RFC3339Nano),
		"event_type":     e.EventType,
		"actor_user_id":  nullableUUID(e.ActorUserID),
		"actor_username": e.ActorUsername,
		"target_type":    e.TargetType,
		"target_id":      nullableUUID(e.TargetID),
		"target_name":    e.TargetName,
		"client_ip":      e.ClientIP,
		"user_agent":     e.UserAgent,
		"metadata":       e.Metadata,
	}
	buf, err := json.Marshal(line)
	if err != nil {
		return
	}
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file != nil {
		_, _ = l.file.Write(append(buf, '\n'))
	}
}

func (l *Logger) LogFromEcho(c *echo.Context, e Event) {
	if l == nil {
		return
	}
	if c != nil {
		if e.ClientIP == "" {
			e.ClientIP = c.RealIP()
		}
		if e.UserAgent == "" {
			e.UserAgent = c.Request().UserAgent()
		}
		if e.ActorUserID == nil || e.ActorUsername == "" {
			if claims := auth.ClaimsFrom(c); claims != nil {
				if e.ActorUserID == nil {
					if id, err := uuid.Parse(claims.Subject); err == nil {
						e.ActorUserID = &id
					}
				}
				if e.ActorUsername == "" {
					e.ActorUsername = claims.Username
				}
			}
		}
		l.Log(c.Request().Context(), e)
		return
	}
	l.Log(context.Background(), e)
}

func (l *Logger) LogProxyAccess(c *echo.Context, userID uuid.UUID, username string, svcID uuid.UUID, svcName string) {
	if l == nil {
		return
	}
	key := userID.String() + "|" + svcID.String()
	now := time.Now()
	if v, ok := l.debounce.Load(key); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < ProxyAccessDebounce {
			return
		}
	}
	l.debounce.Store(key, now)

	uid := userID
	sid := svcID
	l.LogFromEcho(c, Event{
		EventType:     EventProxyAccess,
		ActorUserID:   &uid,
		ActorUsername: username,
		TargetType:    TargetService,
		TargetID:      &sid,
		TargetName:    svcName,
		Metadata: map[string]any{
			"host":   c.Request().Host,
			"path":   c.Request().URL.Path,
			"method": c.Request().Method,
		},
	})
}

func nullableUUID(p *uuid.UUID) any {
	if p == nil {
		return nil
	}
	return p.String()
}

// TimestamptzToString helps callers turn pgtype timestamps into strings for snapshots.
func TimestamptzToString(t pgtype.Timestamptz) any {
	if !t.Valid {
		return nil
	}
	return t.Time.UTC().Format(time.RFC3339Nano)
}
