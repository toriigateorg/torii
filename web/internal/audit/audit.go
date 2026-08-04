package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	TargetAPIToken    = "api_token"
	TargetAPIUser     = "api_user"

	EventSignupSuccess        = "auth.signup.success"
	EventSignupFailed         = "auth.signup.failed"
	EventSigninSuccess        = "auth.signin.success"
	EventSigninFailed         = "auth.signin.failed"
	EventSigninSSO            = "auth.signin.sso"
	EventLogout               = "auth.logout"
	EventPasswordChanged      = "auth.password.changed"
	EventPasswordResetByAdmin = "auth.password.reset_by_admin"
	EventSessionsRevoked      = "auth.sessions.revoked_by_admin"
	EventLockoutCleared       = "auth.lockout.cleared"
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
	EventAPITokenCreated      = "api_token.created"
	EventAPITokenDeleted      = "api_token.deleted"

	EventAPIUserCreated          = "api_user.created"
	EventAPIUserDeleted          = "api_user.deleted"
	EventAPIUserTokenRegenerated = "api_user.token_regenerated"
)

const (
	// Bounds on attacker-influenced strings. Everything below is either supplied
	// by an unauthenticated caller (user agent, request path) or by an operator,
	// and every event is written synchronously to two sinks — so without a cap a
	// client controls how many bytes each of its own requests costs on disk and
	// in the audit table.
	maxUserAgentLen = 256
	maxPathLen      = 2048
	maxMetaStrLen   = 4096

	// maxAuditFileBytes is the size at which audit.jsonl is rotated, and
	// auditFileKeep is how many rotated generations are retained. Unbounded
	// growth on a bind-mounted directory eventually fills the host filesystem,
	// which takes the gateway down with it.
	maxAuditFileBytes = 64 << 20
	auditFileKeep     = 5

	// deniedDebounce collapses repeated proxy denials from the same client for
	// the same service, mirroring ProxyAccessDebounce on the allow path. The deny
	// path is reachable unauthenticated, so it was the cheaper of the two to
	// drive and the only one with no debounce at all.
	deniedDebounce = 1 * time.Minute
)

type Logger struct {
	q        *db.Queries
	file     *os.File
	filePath string
	fileSize int64
	fileErr  error
	fileMu   sync.Mutex
	debounce sync.Map // key "userID|serviceID" -> time.Time
	// dbFailures counts audit rows the database sink rejected. Surfaced at /ht/
	// so a sink divergence is observable rather than only being visible as a
	// stderr line nobody is tailing.
	dbFailures atomic.Int64
}

// FileOK reports whether the JSON-lines sink is operational. Exposed so the
// health endpoint can surface a disabled file sink instead of leaving it to be
// discovered when someone goes looking for an audit trail that isn't there.
func (l *Logger) FileOK() bool {
	if l == nil {
		return false
	}
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	return l.file != nil && l.fileErr == nil
}

// DBFailures reports how many events the database sink has rejected since
// startup. Non-zero means the trail the product reads is missing records the file
// sink has.
func (l *Logger) DBFailures() int64 {
	if l == nil {
		return 0
	}
	return l.dbFailures.Load()
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

// New builds a logger over both sinks. The database sink is always constructed;
// a file-system failure disables only the file sink and is reported, rather than
// failing the constructor.
//
// The sinks used to be coupled: any error here returned nil, the caller logged
// one line and left auditor nil, and every Log call then short-circuited on the
// nil receiver. So an AUDIT_LOG_DIR the process could not write — the documented
// deployment needs a manual chown of the bind mount, which a redeploy can
// silently undo — discarded the *entire* audit trail, including everything the
// database was perfectly able to record.
func New(q *db.Queries, dir string) (*Logger, error) {
	l := &Logger{q: q, filePath: filepath.Join(dir, "audit.jsonl")}
	if err := l.openFile(dir); err != nil {
		l.fileErr = err
		fmt.Fprintln(os.Stderr, "[audit] file sink disabled, database sink still active:", err)
	}
	go l.sweepDebounce()
	return l, nil
}

// sweepDebounce evicts expired debounce entries. The deny-path key includes the
// client IP, so without this the map would grow once per distinct source address
// — trading the write amplification the debounce exists to stop for an unbounded
// allocation driven by the same unauthenticated caller.
func (l *Logger) sweepDebounce() {
	t := time.NewTicker(ProxyAccessDebounce)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-ProxyAccessDebounce)
		l.debounce.Range(func(k, v any) bool {
			if last, ok := v.(time.Time); ok && last.Before(cutoff) {
				l.debounce.Delete(k)
			}
			return true
		})
	}
}

// openFile prepares the JSON-lines sink. Caller must not hold fileMu.
func (l *Logger) openFile(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("audit: mkdir %s: %w", dir, err)
	}
	// 0o640: owner read/write, group read, world none. The audit log
	// records signin failures with identifiers (and PII when audit
	// metadata isn't redacted), so it should not be world-readable. Run
	// torii under a dedicated user so only its group can tail the log.
	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return fmt.Errorf("audit: open %s: %w", l.filePath, err)
	}
	size := int64(0)
	if st, serr := f.Stat(); serr == nil {
		size = st.Size()
	}
	l.fileMu.Lock()
	l.file, l.fileSize, l.fileErr = f, size, nil
	l.fileMu.Unlock()
	return nil
}

// rotateLocked closes the current file, shifts the retained generations down,
// and reopens an empty one. Caller must hold fileMu.
func (l *Logger) rotateLocked() {
	_ = l.file.Close()
	l.file = nil
	// audit.jsonl.4 -> .5, ... .1 -> .2, audit.jsonl -> .1
	oldest := fmt.Sprintf("%s.%d", l.filePath, auditFileKeep)
	_ = os.Remove(oldest)
	for i := auditFileKeep - 1; i >= 1; i-- {
		_ = os.Rename(fmt.Sprintf("%s.%d", l.filePath, i), fmt.Sprintf("%s.%d", l.filePath, i+1))
	}
	if err := os.Rename(l.filePath, l.filePath+".1"); err != nil {
		l.fileErr = err
		fmt.Fprintln(os.Stderr, "[audit] rotate failed:", err)
		return
	}
	f, err := os.OpenFile(l.filePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		l.fileErr = err
		fmt.Fprintln(os.Stderr, "[audit] reopen after rotate failed:", err)
		return
	}
	l.file, l.fileSize, l.fileErr = f, 0, nil
}

func (l *Logger) Close() error {
	if l == nil {
		return nil
	}
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file == nil {
		return nil
	}
	return l.file.Close()
}

// Log writes the event to both sinks. It returns the database sink's error, if
// any: the database is the sink every product surface reads, so a caller that
// gates state on "this was recorded" — the proxy-access debounce — has to be able
// to tell. A file-sink failure is not returned; it is reported through FileOK.
func (l *Logger) Log(ctx context.Context, e Event) error {
	if l == nil {
		return nil
	}
	now := time.Now().UTC()
	e.clamp()

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

	var dbErr error
	if l.q != nil {
		_, dbErr = l.q.InsertAuditLog(ctx, db.InsertAuditLogParams{
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
			l.dbFailures.Add(1)
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
	// Record the divergence in the sink that did accept the record, so "present in
	// audit.jsonl, absent from audit_logs" is a stated fact rather than something
	// to be discovered by diffing the two.
	if dbErr != nil {
		line["db_insert_error"] = dbErr.Error()
	}
	buf, err := json.Marshal(line)
	if err != nil {
		return dbErr
	}
	buf = append(buf, '\n')
	l.fileMu.Lock()
	defer l.fileMu.Unlock()
	if l.file == nil {
		return dbErr
	}
	if l.fileSize+int64(len(buf)) > maxAuditFileBytes {
		l.rotateLocked()
		if l.file == nil {
			return dbErr
		}
	}
	n, werr := l.file.Write(buf)
	l.fileSize += int64(n)
	if werr != nil {
		l.fileErr = werr
	}
	return dbErr
}

// clamp bounds and sanitises every attacker-influenced string on the event.
// Nothing here is security-relevant to keep verbatim: the values are for human
// reading, an unbounded one lets a caller choose how many bytes its own request
// costs in both sinks, and a control byte in one lets a caller decide whether the
// record persists at all.
func (e *Event) clamp() {
	e.EventType = clampField(e.EventType, maxMetaStrLen)
	e.ActorUsername = clampField(e.ActorUsername, maxMetaStrLen)
	e.TargetName = clampField(e.TargetName, maxMetaStrLen)
	e.ClientIP = clampField(e.ClientIP, maxMetaStrLen)
	e.UserAgent = clampField(e.UserAgent, maxUserAgentLen)
	clampMap(e.Metadata, 0)
}

// maxMetaDepth bounds recursion through nested metadata. Snapshots are shallow;
// this only exists so a pathological structure cannot recurse without limit.
const maxMetaDepth = 8

// clampMap sanitises a metadata map in place, recursing into nested maps and
// slices. Recursion matters: the snapshot helpers nest a whole "before"/"after"
// sub-map under one key, and clamping only top-level values left every one of
// those unsanitised.
func clampMap(m map[string]any, depth int) {
	if m == nil || depth > maxMetaDepth {
		return
	}
	for k, v := range m {
		limit := maxMetaStrLen
		if k == "path" || k == "host" {
			limit = maxPathLen
		}
		m[k] = clampValue(v, limit, depth)
	}
}

func clampValue(v any, limit, depth int) any {
	switch t := v.(type) {
	case string:
		return clampField(t, limit)
	case map[string]any:
		clampMap(t, depth+1)
		return t
	case []any:
		if depth <= maxMetaDepth {
			for i, e := range t {
				t[i] = clampValue(e, limit, depth+1)
			}
		}
		return t
	case []string:
		if depth <= maxMetaDepth {
			for i, e := range t {
				t[i] = clampField(e, limit)
			}
		}
		return t
	default:
		return v
	}
}

func clampField(s string, limit int) string {
	return stripControlBytes(truncate(s, limit))
}

// stripControlBytes replaces C0 control characters and DEL with U+FFFD.
//
// This is load-bearing, not cosmetic. json.Marshal happily encodes a NUL as its
// six-character JSON escape, but PostgreSQL's jsonb input function rejects that
// escape (it cannot be represented in text), and TEXT columns reject a literal
// NUL — so the INSERT into audit_logs failed while the JSONL sink wrote the record
// successfully. Every product surface that reads the trail (GET /admin/audit,
// /admin/stats, `torii audit prune`) reads only the database, so a single
// percent-encoded NUL in a path segment the caller chooses removed the event from
// the entire product. The events this matters for are the authenticated ones: the
// onDenied hook shared by every RequirePermission gate records URL.Path, as do the
// privilege-guard denials — precisely the escalation attempts an incident
// responder queries for.
//
// Tab, LF and CR are stripped along with the rest: nothing in an audit field has
// a legitimate use for them, and leaving them in lets a caller forge line
// structure in the JSONL sink.
func stripControlBytes(s string) string {
	needs := false
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			needs = true
			break
		}
	}
	if !needs {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if r < 0x20 || r == 0x7f {
			b.WriteRune(utf8.RuneError)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// truncate cuts s to at most n bytes without splitting a UTF-8 rune, so the
// result still marshals as valid JSON rather than as replacement characters.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func (l *Logger) LogFromEcho(c *echo.Context, e Event) error {
	if l == nil {
		return nil
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
		return l.Log(c.Request().Context(), e)
	}
	return l.Log(context.Background(), e)
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

	uid := userID
	sid := svcID
	err := l.LogFromEcho(c, Event{
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
	// Armed only after the database sink accepted the row. Storing it first meant
	// one request whose record the database rejected both failed to persist and
	// suppressed the whole next window, so a single poisoned request per five
	// minutes erased that user's proxy-access trail entirely.
	if err == nil {
		l.debounce.Store(key, now)
	}
}

// LogProxyDenied records a proxy denial, debounced per (client, service, reason)
// the way LogProxyAccess is per (user, service). The deny path is reachable
// without authentication, so it was the cheapest way to drive synchronous writes
// to both sinks and dilute the trail with noise.
func (l *Logger) LogProxyDenied(c *echo.Context, e Event, reason string) {
	if l == nil {
		return
	}
	svc := ""
	if e.TargetID != nil {
		svc = e.TargetID.String()
	}
	// Keyed on the /64-folded client address, matching the rate limiter. Keying on
	// the raw IP let one v6 client cycle addresses within its own prefix and get a
	// fresh debounce bucket per request, which is the write amplification the
	// debounce exists to stop.
	key := "denied|" + debounceIPKey(c.RealIP()) + "|" + svc + "|" + reason
	now := time.Now()
	if v, ok := l.debounce.Load(key); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < deniedDebounce {
			return
		}
	}
	if err := l.LogFromEcho(c, e); err == nil {
		l.debounce.Store(key, now)
	}
}

// debounceIPKey folds an IPv6 address to its /64 so the debounce bucket matches
// the rate limiter's. IPv4 and unparseable values are returned as-is.
func debounceIPKey(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	masked := parsed.Mask(net.CIDRMask(64, 128))
	if masked == nil {
		return ip
	}
	return masked.String() + "/64"
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
