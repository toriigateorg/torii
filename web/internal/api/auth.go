package api

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/labstack/echo/v5"

	"torii/internal/audit"
	"torii/internal/auth"
	"torii/internal/config"
	"torii/internal/db"
	"torii/internal/proxy"
)

type authHandlers struct {
	pool    *pgxpool.Pool
	q       *db.Queries
	cfg     *config.Config
	cache   *proxy.ServiceCache
	auditor *audit.Logger
}

type roleSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type userDTO struct {
	ID          string        `json:"id"`
	Username    string        `json:"username"`
	Email       string        `json:"email"`
	FirstName   string        `json:"first_name"`
	LastName    string        `json:"last_name"`
	Roles       []roleSummary `json:"roles"`
	Permissions []string      `json:"permissions"`
	// SsoOnly is true when the account has no password hash and can therefore
	// only authenticate through an SSO provider.
	SsoOnly bool `json:"sso_only"`
	// LockedUntil is set only while a failed-login lockout is in effect, so the
	// admin UI can show which accounts need unlocking.
	LockedUntil *time.Time `json:"locked_until,omitempty"`
}

func toDTO(u db.User, roles []roleSummary, perms []string) userDTO {
	if roles == nil {
		roles = []roleSummary{}
	}
	if perms == nil {
		perms = []string{}
	}
	var lockedUntil *time.Time
	if u.LockedUntil.Valid && time.Now().Before(u.LockedUntil.Time) {
		t := u.LockedUntil.Time
		lockedUntil = &t
	}
	return userDTO{
		LockedUntil: lockedUntil,
		ID:          u.ID.String(),
		Username:    u.Username,
		Email:       u.Email,
		FirstName:   u.FirstName,
		LastName:    u.LastName,
		Roles:       roles,
		Permissions: perms,
		SsoOnly:     !u.PasswordHash.Valid,
	}
}

type tokenResp struct {
	AccessToken string   `json:"access_token,omitempty"`
	ExpiresIn   int      `json:"expires_in"`
	User        *userDTO `json:"user,omitempty"`
	// HandoffURL is present when the caller signed in on the control plane after
	// being redirected there from a proxied service host. The SPA navigates to it
	// to materialise the session on that host. See handoffURLFor.
	HandoffURL string `json:"handoff_url,omitempty"`
}

type signupReq struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	// BootstrapToken is required only while the users table is empty, to claim the
	// first-user administrator grant. See config.Config.BootstrapToken.
	BootstrapToken string `json:"bootstrap_token"`
}

type signinReq struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
	// ReturnToHost names the proxied service host the user was sent here from, so
	// a successful sign-in on the control plane can hand them a session back on
	// that host. Honoured only on the torii host, only for a registered service
	// domain, and only together with HandoffCnf. See handoffURLFor.
	ReturnToHost string `json:"return_to_host"`
	// ReturnTo is the path on ReturnToHost to land on afterwards. Relative only.
	ReturnTo string `json:"return_to"`
	// HandoffCnf is the correlator digest minted by the service host when it
	// redirected the user here. It binds the resulting handoff token to the browser
	// that started on that host, so a caller cannot mint one for a host it never
	// visited.
	HandoffCnf string `json:"handoff_cnf"`
}

var (
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,64}$`)
	// Printable ASCII only, excluding '@' outside the single separator. The
	// previous `[^\s@]+` classes admitted every non-space byte — control
	// characters, newlines, and the '|' that the HMAC payload used to join on.
	// The email is forwarded upstream as X-Torii-Email and covered by the
	// signature, so a control character in it produced an unsettable header and
	// bricked the account with 502s on every proxied request.
	emailRe = regexp.MustCompile(`^[!-?A-~]+@[!-?A-~]+\.[!-?A-~]+$`)
)

// isPrintableSingleLine reports whether s contains only printable characters —
// no control bytes, no newlines. Applied to any operator-supplied string torii
// forwards to an upstream in a header.
func isPrintableSingleLine(s string) bool {
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// hashIdentifier returns a stable hex digest of an email/username for use in
// failed-signin/signup audit events. Logging the raw value would leak PII to
// anyone with shell access (audit.jsonl is on-disk), and to any operator
// with audit.read for accounts they don't own. Hashing preserves the
// "same identifier was attempted N times" signal while removing the PII.
func hashIdentifier(s string) string {
	if s == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(s))))
	return hex.EncodeToString(sum[:])
}

func (h *authHandlers) signup(c *echo.Context) error {
	var req signupReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	// Usernames are lowercased for the same reason emails are: signin folds case
	// on both, so storing mixed case would let 'Admin' and 'admin' be different
	// rows that answer to the same credential. Migration 0016 enforces this in
	// the schema too — a mixed-case insert now fails the CHECK.
	req.Username = strings.ToLower(strings.TrimSpace(req.Username))
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)

	// Failure reasons are recorded, not written, and the write happens in the
	// deferred block below. An audit insert is a pool acquisition, and three of
	// these calls sat inside the open transaction while the signup advisory lock
	// was held — a second acquisition made while holding the first connection,
	// which is a circular wait once the pool is saturated. The deferred write runs
	// after tx.Rollback (defers are LIFO and the rollback is registered later), so
	// the connection is always back in the pool first.
	var failReason string
	signupFail := func(reason string) { failReason = reason }
	defer func() {
		if failReason == "" {
			return
		}
		h.auditor.LogFromEcho(c, audit.Event{
			EventType: audit.EventSignupFailed,
			Metadata: map[string]any{
				"username_hash": hashIdentifier(req.Username),
				"email_hash":    hashIdentifier(req.Email),
				"reason":        failReason,
			},
		})
	}()

	if !usernameRe.MatchString(req.Username) {
		signupFail("invalid_username")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "username must be 3-64 chars: letters, digits, _ . -"})
	}
	if !emailRe.MatchString(req.Email) {
		signupFail("invalid_email")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid email"})
	}
	if h.cfg.IsProd() {
		if err := auth.ValidatePasswordStrength(req.Password); err != nil {
			signupFail("weak_password")
			return c.JSON(http.StatusBadRequest, map[string]string{"error": err.Error()})
		}
	} else if req.Password == "" {
		signupFail("missing_password")
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "password required"})
	}

	ctx := c.Request().Context()

	// Bail out on a closed signup endpoint *before* the argon2 derivation, not
	// after. Hashing first hands an anonymous caller a 64 MiB allocation per
	// request on a route that is meant to be shut. The authoritative check is
	// the one below, inside the transaction that serializes against first-user
	// signup; this is only an early-out, so a stale read here costs nothing.
	//
	// It runs before the api_users lookup, not after. The other way round, a
	// closed endpoint still answered 409 for a name held by a service credential
	// and 403 for every other name, so anonymous callers could enumerate the
	// machine-identity namespace on a route that is supposed to be shut.
	if !h.getBoolSetting(ctx, settingSignupEnabled, true) {
		if count, err := h.q.CountUsers(ctx); err == nil && count > 0 {
			signupFail("signup_disabled")
			return c.JSON(http.StatusForbidden, map[string]string{"error": "new account signups are disabled"})
		}
	}

	// Both directions of the machine/human namespace have to be closed, or the
	// api_users check is just a race: create the service credential first, then
	// register the human account that shadows it. The response is identical to
	// the human-collision one below so it does not say which namespace matched.
	if _, err := h.q.GetAPIUserByName(ctx, req.Username); err == nil {
		signupFail("conflict_api_user")
		return c.JSON(http.StatusConflict, map[string]string{"error": "username already taken"})
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	tx, err := h.pool.Begin(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	defer tx.Rollback(ctx)

	// Serialize signup transactions so two concurrent first-user signups
	// can't both observe count == 0 and both be granted admin. The lock
	// is released automatically at commit/rollback. The integer is
	// arbitrary — picked once and never reused for any other purpose.
	//
	// lock_timeout bounds the wait. Without it a signup that blocks on the lock
	// pins its pooled connection for as long as the holder takes, so one stuck
	// transaction becomes a queue the whole pool drains into.
	if _, err := tx.Exec(ctx, "SET LOCAL lock_timeout = '5s'"); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if _, err := tx.Exec(ctx, "SELECT pg_advisory_xact_lock($1)", int64(74331)); err != nil {
		return c.JSON(http.StatusServiceUnavailable, map[string]string{"error": "signup is busy, please retry"})
	}

	qtx := h.q.WithTx(tx)

	count, err := qtx.CountUsers(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	// Read through qtx, not h.q. h.q issues on the pool, so this was a second
	// connection acquisition taken while this transaction held the first *and* the
	// advisory lock — and because the lock serialises, exactly one request reached
	// this line while the rest blocked in Postgres still holding their own
	// connections. The winner then waited on a connection only it could free.
	if count > 0 && !getBoolSettingWith(ctx, qtx, settingSignupEnabled, true) {
		signupFail("signup_disabled")
		return c.JSON(http.StatusForbidden, map[string]string{"error": "new account signups are disabled"})
	}

	// The zero-user administrator grant needs out-of-band proof, and needs to
	// happen on the control plane. signup_enabled does not gate it — the check
	// above short-circuits at count zero — so before this an unauthenticated
	// caller who reached the port during initial setup became the administrator,
	// on any Host value including a bare IP.
	if count == 0 {
		if !h.cfg.IsToriiHost(c.Request().Host) {
			signupFail("bootstrap_wrong_host")
			return c.JSON(http.StatusForbidden, map[string]string{"error": "the first account must be created on the torii host"})
		}
		if h.cfg.BootstrapToken == "" ||
			subtle.ConstantTimeCompare([]byte(h.cfg.BootstrapToken), []byte(req.BootstrapToken)) != 1 {
			signupFail("bootstrap_token_invalid")
			return c.JSON(http.StatusForbidden, map[string]string{
				"error": "a bootstrap token is required to create the first account; it is printed to the server log at startup",
			})
		}
	}

	user, err := qtx.CreateUser(ctx, db.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		PasswordHash: pgtype.Text{String: hash, Valid: true},
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			signupFail("conflict")
			return c.JSON(http.StatusConflict, map[string]string{"error": "username or email already taken"})
		}
		signupFail("server_error")
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create user"})
	}

	allRole, err := qtx.GetRoleByName(ctx, "all")
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if err := qtx.AssignUserRole(ctx, db.AssignUserRoleParams{UserID: user.ID, RoleID: allRole.ID}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	if count == 0 {
		adminRole, err := qtx.GetRoleByName(ctx, "admin")
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
		if err := qtx.AssignUserRole(ctx, db.AssignUserRoleParams{UserID: user.ID, RoleID: adminRole.ID}); err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	uid := user.ID
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:     audit.EventSignupSuccess,
		ActorUserID:   &uid,
		ActorUsername: user.Username,
		TargetType:    audit.TargetUser,
		TargetID:      &uid,
		TargetName:    user.Username,
		Metadata: map[string]any{
			"first_user_admin": count == 0,
			"after":            audit.SnapshotUser(user),
		},
	})

	return h.issueAndRespond(c, user)
}

func (h *authHandlers) signin(c *echo.Context) error {
	var req signinReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Identifier = strings.TrimSpace(req.Identifier)
	if req.Identifier == "" || req.Password == "" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "identifier and password required"})
	}
	// Per-account fail-safe, checked before the argon2 derivation. authLimiter is
	// per-IP and therefore worth nothing when torii's view of the client address
	// is a single upstream hop, which is the default under any reverse proxy that
	// is not in TRUSTED_PROXY_CIDRS.
	if !allowIdentifierAttempt(req.Identifier) {
		return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
	}

	signinFail := func(reason string, uid *uuid.UUID, username string) {
		h.auditor.LogFromEcho(c, audit.Event{
			EventType:     audit.EventSigninFailed,
			ActorUserID:   uid,
			ActorUsername: username,
			Metadata: map[string]any{
				"identifier_hash": hashIdentifier(req.Identifier),
				"reason":          reason,
			},
		})
	}

	user, err := h.q.GetUserByUsernameOrEmail(c.Request().Context(), req.Identifier)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Run argon2 against a constant dummy hash so the unknown-user
			// path takes the same wall-clock time as a real
			// known-user-wrong-password path. Without this, response timing
			// reveals which identifiers exist.
			auth.VerifyDummyPassword(req.Password)
			signinFail("unknown_user", nil, "")
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	uid := user.ID
	ctx := c.Request().Context()
	// Every failure exit below pays the same argon2 cost as a real
	// wrong-password verify. The unknown-user path above already did; these two
	// short-circuited before reaching VerifyPassword, which handed back a
	// distinguishable fast response and so reintroduced exactly the oracle the
	// dummy hash exists to close. The SSO-only case is the more useful leak: it
	// answers "does this address authenticate by password" pre-authentication.
	if user.LockedUntil.Valid && time.Now().Before(user.LockedUntil.Time) {
		auth.VerifyDummyPassword(req.Password)
		signinFail("account_locked", &uid, user.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}
	if !user.PasswordHash.Valid {
		auth.VerifyDummyPassword(req.Password)
		signinFail("no_password", &uid, user.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}
	if !auth.VerifyPassword(user.PasswordHash.String, req.Password) {
		row, _ := h.q.IncrementFailedLogin(ctx, uid)
		reason := "bad_password"
		if row.LockedUntil.Valid && time.Now().Before(row.LockedUntil.Time) {
			reason = "account_locked_after_failures"
		}
		signinFail(reason, &uid, user.Username)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}
	if user.FailedLoginCount > 0 || user.LockedUntil.Valid {
		_ = h.q.ResetFailedLogin(ctx, uid)
	}
	h.auditor.LogFromEcho(c, audit.Event{
		EventType:     audit.EventSigninSuccess,
		ActorUserID:   &uid,
		ActorUsername: user.Username,
		TargetType:    audit.TargetUser,
		TargetID:      &uid,
		TargetName:    user.Username,
	})
	return h.issueAndRespondWithHandoff(c, user, req.ReturnToHost, req.HandoffCnf, req.ReturnTo)
}

// handoffURLFor mints the cross-host return leg for a session just established on
// the control plane, or returns "" when there is nothing to hand off.
//
// This is the leg that makes confining the sign-in form to TORII_URL workable:
// dispatch sends an unauthenticated navigation on a service host here, and this
// sends the browser back with a 30-second single-use token instead of ever putting
// a password form on the upstream's origin.
//
// correlatorDigest is mandatory and comes from the service host's own redirect, so
// a caller cannot manufacture a handoff for a host it never visited.
func (h *authHandlers) handoffURLFor(c *echo.Context, user db.User, returnToHost, correlatorDigest, returnTo string) string {
	if returnToHost == "" || correlatorDigest == "" {
		return ""
	}
	// Only ever minted on the control plane. On a service host there is nothing to
	// hand off — the session was just set there.
	if !h.cfg.IsToriiHost(c.Request().Host) {
		return ""
	}
	ctx := c.Request().Context()
	if !h.isKnownServiceHost(ctx, returnToHost) {
		return ""
	}
	tok, err := auth.IssueHandoffToken(user.ID, returnToHost, correlatorDigest, h.cfg.JWTSecret)
	if err != nil {
		return ""
	}
	scheme := "https"
	if !h.cfg.IsProd() {
		scheme = "http"
	}
	u := scheme + "://" + returnToHost + "/_torii/handoff"
	if to := safeRelativeRedirect(returnTo); to != "/" {
		u += "?to=" + url.QueryEscape(to)
	}
	// Fragment, not query: the token mints a session, and a fragment is never sent
	// to a server, never logged, and never appears in a Referer.
	return u + "#token=" + tok
}

func (h *authHandlers) tokenRefresh(c *echo.Context) error {
	secure := h.cfg.IsProd()
	ctx := c.Request().Context()

	refreshFail := func(reason string, uid *uuid.UUID) {
		h.auditor.LogFromEcho(c, audit.Event{
			EventType:   audit.EventTokenRefreshFailed,
			ActorUserID: uid,
			Metadata:    map[string]any{"reason": reason},
		})
	}

	cookie, err := c.Cookie(auth.RefreshCookie)
	if err != nil || cookie.Value == "" {
		refreshFail("missing_cookie", nil)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "no refresh token"})
	}
	hash := auth.HashRefreshToken(cookie.Value)

	// Consume the presented token in one statement. The old shape read the row,
	// validated it, issued a new session, and only then deleted the old row —
	// four separate statements with no transaction, so two simultaneous
	// presentations of the same token both passed the read and both got a
	// session, forking one stolen token into two independent chains.
	row, err := h.q.ConsumeRefreshTokenByHash(ctx, hash)
	if err != nil {
		auth.ClearAuthCookies(c, secure)
		refreshFail("invalid_token", nil)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
	}
	if !row.ExpiresAt.Valid || time.Now().After(row.ExpiresAt.Time) || row.RevokedAt.Valid {
		auth.ClearAuthCookies(c, secure)
		uid := row.UserID
		refreshFail("expired_or_revoked", &uid)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "refresh token expired"})
	}
	// The token is only valid on the host it was issued for. This is what defeats
	// cookie tossing server-side: a token the attacker minted for themselves and
	// planted in the victim's jar with Domain=example.com no longer rotates on a
	// sibling host. Rows predating migration 0017 carry '' and never match, so they
	// fail closed and their owners sign in once more.
	if row.Host != config.CanonicalHost(c.Request().Host) {
		auth.ClearAuthCookies(c, secure)
		uid := row.UserID
		refreshFail("host_mismatch", &uid)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "refresh token was not issued for this host"})
	}

	user, err := h.q.GetUserByID(ctx, row.UserID)
	if err != nil {
		auth.ClearAuthCookies(c, secure)
		uid := row.UserID
		refreshFail("user_not_found", &uid)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "user not found"})
	}
	// A lockout has to bite here too. Refresh mints a fresh access token with
	// re-read roles and permissions, so honouring the lock only on the password
	// path meant an attacker holding a live refresh token rode straight through
	// the lockout that was supposed to have shut them out.
	if user.LockedUntil.Valid && time.Now().Before(user.LockedUntil.Time) {
		auth.ClearAuthCookies(c, secure)
		uid := user.ID
		refreshFail("account_locked", &uid)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "account locked"})
	}

	return h.issueAndRespond(c, user)
}

func (h *authHandlers) logout(c *echo.Context) error {
	secure := h.cfg.IsProd()
	// Same-origin only. This endpoint is unauthenticated and answered on every
	// proxied host, and it is deliberately exempt from the cookie CSRF gate
	// (isCookieAllowedPath), so a cross-site auto-submitting form POST could delete
	// any visitor's host-only session cookies. On its own that is a nuisance
	// logout; combined with a domain-scoped cookie planted from a sibling host it
	// was the primitive that decided *which* cookie won, by removing the victim's
	// real one and leaving the attacker's in place.
	if !auth.IsSameOrigin(c.Request()) {
		return c.JSON(http.StatusForbidden, map[string]string{"error": "forbidden: cross-origin logout"})
	}
	terminated := false
	if cookie, err := c.Cookie(auth.RefreshCookie); err == nil && cookie.Value != "" {
		_ = h.q.DeleteRefreshTokenByHash(c.Request().Context(), auth.HashRefreshToken(cookie.Value))
		terminated = true
	}
	h.auditor.LogFromEcho(c, audit.Event{EventType: audit.EventLogout})
	auth.ClearAuthCookies(c, secure)
	// Tell the browser to flush its HTTP cache for this origin so the next
	// navigation can't serve a stale upstream HTML payload that still has
	// the user "signed in" visually.
	//
	// "cache" only. "storage" and "executionContexts" wipe localStorage,
	// IndexedDB, Cache Storage and service-worker registrations belonging to
	// the *upstream application*, not to torii — and this route is
	// unauthenticated and allowlisted on every proxied host, so an attacker's
	// page could destroy that state with a top-level auto-submitting form POST
	// to https://<service-host>/_torii/api/v1/logout. Emitted only when a
	// session was actually terminated and the caller is same-origin, so the
	// cross-site navigation gets no header at all — which the same-origin gate at
	// the top of this handler now guarantees anyway.
	if terminated {
		c.Response().Header().Set("Clear-Site-Data", `"cache"`)
	}
	c.Response().Header().Set("Cache-Control", "no-store")
	return c.NoContent(http.StatusNoContent)
}

func (h *authHandlers) me(c *echo.Context) error {
	claims := auth.ClaimsFrom(c)
	if claims == nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
	}
	id, err := uuid.Parse(claims.Subject)
	if err != nil {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid subject"})
	}
	ctx := c.Request().Context()
	user, err := h.q.GetUserByID(ctx, id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	roles, perms, _, err := h.loadUserAuthz(ctx, id)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	return c.JSON(http.StatusOK, toDTO(user, roles, perms))
}

func (h *authHandlers) loadUserAuthz(ctx context.Context, userID uuid.UUID) ([]roleSummary, []string, []uuid.UUID, error) {
	roleRows, err := h.q.ListUserRoles(ctx, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	roles := make([]roleSummary, 0, len(roleRows))
	roleIDs := make([]uuid.UUID, 0, len(roleRows))
	for _, r := range roleRows {
		roles = append(roles, roleSummary{ID: r.ID.String(), Name: r.Name})
		roleIDs = append(roleIDs, r.ID)
	}
	perms, err := h.q.GetUserPermissions(ctx, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	if perms == nil {
		perms = []string{}
	}
	return roles, perms, roleIDs, nil
}

func (h *authHandlers) issueSession(ctx context.Context, c *echo.Context, user db.User) (string, []roleSummary, []string, error) {
	secure := h.cfg.IsProd()

	roles, perms, roleIDs, err := h.loadUserAuthz(ctx, user.ID)
	if err != nil {
		return "", nil, nil, err
	}

	access, _, err := auth.IssueAccessToken(user.ID, user.Username, user.Email, perms, roleIDs, c.Request().Host, h.cfg.JWTSecret, h.cfg.AccessTokenTTL)
	if err != nil {
		return "", nil, nil, err
	}
	raw, hash, err := auth.NewRefreshToken()
	if err != nil {
		return "", nil, nil, err
	}
	// Bind the token to the host this session was established on. Without it one
	// refresh token minted sessions on every host, which is what made a cookie
	// planted from a sibling host redeemable — see migration 0017.
	if _, err := h.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(h.cfg.RefreshTokenTTL), Valid: true},
		Host:      config.CanonicalHost(c.Request().Host),
	}); err != nil {
		return "", nil, nil, err
	}

	auth.SetAccessCookie(c, access, h.cfg.AccessTokenTTL, secure)
	auth.SetRefreshCookie(c, raw, h.cfg.RefreshTokenTTL, secure)
	return access, roles, perms, nil
}

// refreshAndRedirect rotates the session using the refresh cookie and 302s
// back to the caller-supplied `to` path. Lives at
// /_torii/api/v1/refresh_and_redirect so the path-scoped refresh cookie
// actually rides along on the request — the proxy dispatch redirects the
// browser here whenever an access token expires on a proxied service domain.
func (h *authHandlers) refreshAndRedirect(c *echo.Context) error {
	to := safeRelativeRedirect(c.QueryParam("to"))
	if _, err := h.AttemptCookieRefresh(c); err != nil {
		// Absolute, to the control plane: this endpoint answers on service hosts,
		// and a relative /_torii/signin would land the user on a sign-in page
		// served from the upstream's origin. That page no longer exists off-host,
		// so a relative redirect would also simply 404.
		return c.Redirect(http.StatusFound, h.controlPlaneSigninURL(c))
	}
	return c.Redirect(http.StatusFound, to)
}

// handoffStart bridges an existing control-plane session onto a proxied service
// host. dispatch sends an unauthenticated navigation on a service host here
// rather than straight to the sign-in form, because the common case is a user who
// is *already* signed in on TORII_URL: cookies are host-scoped, so holding a
// session on the control plane says nothing about holding one on the service
// host, and no credential prompt is needed to bridge the gap.
//
// Redirecting to /signin instead was a dead end — that page carries the `guest`
// middleware, which bounces an authenticated visitor to /dashboard, so the handoff
// never ran and the service was unreachable.
//
// Control-plane only: absent from crossHostEndpoints, so it 404s on a service host.
func (h *authHandlers) handoffStart(c *echo.Context) error {
	// The only legitimate way to arrive here is dispatch's 302 from a service
	// host, i.e. a top-level document navigation. Script on a service host can
	// otherwise drive the whole flow itself — mint a correlator it controls, call
	// this, and harvest the resulting handoff token out of the fragment — turning
	// ephemeral XSS into a durable session for that host that survives outside
	// the browser. Requiring a navigation does not stop a determined attacker
	// from opening a window, but it does close the silent fetch()/XHR path, and
	// browsers that do not send Sec-Fetch-* are not the ones running the script.
	if dest := c.Request().Header.Get("Sec-Fetch-Dest"); dest != "" && dest != "document" {
		return c.NoContent(http.StatusForbidden)
	}
	if mode := c.Request().Header.Get("Sec-Fetch-Mode"); mode != "" && mode != "navigate" {
		return c.NoContent(http.StatusForbidden)
	}

	rh := c.QueryParam("return_to_host")
	cnf := c.QueryParam("handoff_cnf")
	to := safeRelativeRedirect(c.QueryParam("to"))

	// No session (or nothing to hand off): fall through to the credential form,
	// carrying the correlator so signin can complete the same handoff afterwards.
	toSignin := func() error {
		q := url.Values{}
		if rh != "" && cnf != "" {
			q.Set("return_to_host", rh)
			q.Set("handoff_cnf", cnf)
		}
		if to != "/" {
			q.Set("to", to)
		}
		target := "/_torii/signin"
		if len(q) > 0 {
			target += "?" + q.Encode()
		}
		return c.Redirect(http.StatusFound, target)
	}

	claims, err := auth.ClaimsFromRequest(c, h.cfg.JWTSecret)
	if err != nil {
		// An expired access token is the norm here, not the exception: the default
		// TTL is one minute. The refresh cookie is scoped to /_torii/api/v1/, which
		// this endpoint lives under, so it rides along on this very request.
		claims, err = h.AttemptCookieRefresh(c)
		if err != nil {
			return toSignin()
		}
	}
	uid, err := uuid.Parse(claims.Subject)
	if err != nil {
		return toSignin()
	}
	user, err := h.q.GetUserByID(c.Request().Context(), uid)
	if err != nil {
		return toSignin()
	}
	if u := h.handoffURLFor(c, user, rh, cnf, to); u != "" {
		return c.Redirect(http.StatusFound, u)
	}
	// Authenticated but the handoff was refused — an unregistered service host, or
	// a correlator that never made it through the bounce. The sign-in form would
	// just bounce back off the guest middleware, so land them somewhere real.
	return c.Redirect(http.StatusFound, "/_torii/dashboard")
}

// controlPlaneSigninURL is the absolute sign-in URL on TORII_URL. Kept here
// rather than reusing cmd's helper because this path has no correlator to mint:
// the refresh already failed, so there is no session to hand back.
func (h *authHandlers) controlPlaneSigninURL(c *echo.Context) string {
	if h.cfg.IsToriiHost(c.Request().Host) {
		return "/_torii/signin"
	}
	scheme := "https"
	if !h.cfg.IsProd() {
		scheme = "http"
	}
	return scheme + "://" + h.cfg.ToriiURL + "/_torii/signin"
}

// safeRelativeRedirect returns target if and only if it is a same-origin
// relative URL with a single leading "/". Anything else (absolute URLs,
// protocol-relative "//host/..." forms, paths beginning with a backslash that
// browsers normalize to "//", embedded CR/LF) collapses to "/". This is the
// /api/v1/refresh_and_redirect open-redirect guard.
func safeRelativeRedirect(target string) string {
	if target == "" {
		return "/"
	}
	if strings.ContainsAny(target, "\\\r\n") {
		return "/"
	}
	u, err := url.Parse(target)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	if !strings.HasPrefix(u.Path, "/") || strings.HasPrefix(u.Path, "//") {
		return "/"
	}
	return u.RequestURI()
}

// AttemptCookieRefresh validates the refresh cookie on the request, rotates
// the refresh token, mints a new access token, sets fresh cookies on the
// response, and returns the new claims. On failure it returns nil and clears
// auth cookies. Used by the proxy dispatch so that an expired access token on
// a proxied service domain doesn't fall through to the SPA.
//
// This is the second refresh path, and every hardening tokenRefresh received had
// to be mirrored here or the weaker one is simply the one an attacker uses. It
// previously diverged in three ways: it used the non-atomic
// GetRefreshTokenByHash + delete that ConsumeRefreshTokenByHash was introduced to
// replace, so two simultaneous presentations of one stolen token both succeeded
// and forked it into two chains; it omitted the locked_until check, so a live
// refresh token rode straight through a lockout that had shut the password path;
// and it emitted no audit event at all, so failures on it were invisible.
func (h *authHandlers) AttemptCookieRefresh(c *echo.Context) (*auth.Claims, error) {
	secure := h.cfg.IsProd()
	ctx := c.Request().Context()

	refreshFail := func(reason string, uid *uuid.UUID) {
		h.auditor.LogFromEcho(c, audit.Event{
			EventType:   audit.EventTokenRefreshFailed,
			ActorUserID: uid,
			Metadata:    map[string]any{"reason": reason, "path": "refresh_and_redirect"},
		})
	}

	cookie, err := c.Cookie(auth.RefreshCookie)
	if err != nil || cookie.Value == "" {
		refreshFail("missing_cookie", nil)
		return nil, errors.New("no refresh cookie")
	}
	hash := auth.HashRefreshToken(cookie.Value)

	// Consume in one statement, for the same reason tokenRefresh does.
	row, err := h.q.ConsumeRefreshTokenByHash(ctx, hash)
	if err != nil {
		auth.ClearAuthCookies(c, secure)
		refreshFail("invalid_token", nil)
		return nil, err
	}
	if !row.ExpiresAt.Valid || time.Now().After(row.ExpiresAt.Time) || row.RevokedAt.Valid {
		auth.ClearAuthCookies(c, secure)
		uid := row.UserID
		refreshFail("expired_or_revoked", &uid)
		return nil, errors.New("refresh token expired or revoked")
	}
	// Mirrors tokenRefresh. This is the path dispatch bounces a planted
	// torii_session marker into, so it is the one the cookie-tossing attack
	// actually drove — checking the binding only on the other path would have left
	// the exploited half open.
	if row.Host != config.CanonicalHost(c.Request().Host) {
		auth.ClearAuthCookies(c, secure)
		uid := row.UserID
		refreshFail("host_mismatch", &uid)
		return nil, errors.New("refresh token was not issued for this host")
	}
	user, err := h.q.GetUserByID(ctx, row.UserID)
	if err != nil {
		auth.ClearAuthCookies(c, secure)
		uid := row.UserID
		refreshFail("user_not_found", &uid)
		return nil, err
	}
	if user.LockedUntil.Valid && time.Now().Before(user.LockedUntil.Time) {
		auth.ClearAuthCookies(c, secure)
		uid := user.ID
		refreshFail("account_locked", &uid)
		return nil, errors.New("account locked")
	}
	accessTok, _, _, err := h.issueSession(ctx, c, user)
	if err != nil {
		return nil, err
	}
	return auth.ParseAccessToken(accessTok, h.cfg.JWTSecret, c.Request().Host)
}

func (h *authHandlers) issueAndRespond(c *echo.Context, user db.User) error {
	return h.issueAndRespondWithHandoff(c, user, "", "", "")
}

func (h *authHandlers) issueAndRespondWithHandoff(c *echo.Context, user db.User, returnToHost, correlatorDigest, returnTo string) error {
	access, roles, perms, err := h.issueSession(c.Request().Context(), c, user)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	// The bearer token is only ever echoed into the body on the control plane.
	// signin, signup and token_refresh all answer on proxied service hosts too
	// (cookies are host-scoped, so the flow reruns per domain), and a token in a
	// same-origin response body is readable by any script on that upstream's
	// origin. The session cookie is already set, and the SPA on a service host
	// authenticates its GETs with it, so the body copy buys nothing there.
	dto := toDTO(user, roles, perms)
	resp := tokenResp{
		ExpiresIn: int(h.cfg.AccessTokenTTL.Seconds()),
		User:      &dto,
	}
	if h.cfg.IsToriiHost(c.Request().Host) {
		resp.AccessToken = access
	}
	resp.HandoffURL = h.handoffURLFor(c, user, returnToHost, correlatorDigest, returnTo)
	return c.JSON(http.StatusOK, resp)
}
