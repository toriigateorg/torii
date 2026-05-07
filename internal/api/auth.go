package api

import (
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/labstack/echo/v5"

	"sanmon/internal/auth"
	"sanmon/internal/config"
	"sanmon/internal/db"
	"sanmon/internal/proxy"
)

type authHandlers struct {
	q     *db.Queries
	cfg   *config.Config
	cache *proxy.ServiceCache
}

type userDTO struct {
	ID        string `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	UserType  string `json:"user_type"`
}

func toDTO(u db.User) userDTO {
	return userDTO{
		ID:        u.ID.String(),
		Username:  u.Username,
		Email:     u.Email,
		FirstName: u.FirstName,
		LastName:  u.LastName,
		UserType:  u.UserType,
	}
}

type tokenResp struct {
	AccessToken string   `json:"access_token"`
	ExpiresIn   int      `json:"expires_in"`
	User        *userDTO `json:"user,omitempty"`
}

type signupReq struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type signinReq struct {
	Identifier string `json:"identifier"`
	Password   string `json:"password"`
}

var (
	usernameRe = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,64}$`)
	emailRe    = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

func (h *authHandlers) signup(c *echo.Context) error {
	var req signupReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)

	if !usernameRe.MatchString(req.Username) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "username must be 3-64 chars: letters, digits, _ . -"})
	}
	if !emailRe.MatchString(req.Email) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid email"})
	}
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

	ctx := c.Request().Context()
	userType := "user"
	if count, err := h.q.CountUsers(ctx); err == nil && count == 0 {
		userType = "admin"
	}

	user, err := h.q.CreateUser(ctx, db.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		PasswordHash: hash,
		UserType:     userType,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "username or email already taken"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create user"})
	}
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

	user, err := h.q.GetUserByUsernameOrEmail(c.Request().Context(), req.Identifier)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if !auth.VerifyPassword(user.PasswordHash, req.Password) {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
	}
	return h.issueAndRespond(c, user)
}

func (h *authHandlers) tokenRefresh(c *echo.Context) error {
	secure := h.cfg.IsProd()
	ctx := c.Request().Context()

	cookie, err := c.Cookie(auth.RefreshCookie)
	if err != nil || cookie.Value == "" {
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "no refresh token"})
	}
	hash := auth.HashRefreshToken(cookie.Value)

	row, err := h.q.GetRefreshTokenByHash(ctx, hash)
	if err != nil {
		auth.ClearAuthCookies(c, secure)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "invalid refresh token"})
	}
	if !row.ExpiresAt.Valid || time.Now().After(row.ExpiresAt.Time) || row.RevokedAt.Valid {
		_ = h.q.DeleteRefreshTokenByHash(ctx, hash)
		auth.ClearAuthCookies(c, secure)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "refresh token expired"})
	}

	user, err := h.q.GetUserByID(ctx, row.UserID)
	if err != nil {
		auth.ClearAuthCookies(c, secure)
		return c.JSON(http.StatusUnauthorized, map[string]string{"error": "user not found"})
	}

	if err := h.q.DeleteRefreshTokenByHash(ctx, hash); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	return h.issueAndRespond(c, user)
}

func (h *authHandlers) logout(c *echo.Context) error {
	secure := h.cfg.IsProd()
	if cookie, err := c.Cookie(auth.RefreshCookie); err == nil && cookie.Value != "" {
		_ = h.q.DeleteRefreshTokenByHash(c.Request().Context(), auth.HashRefreshToken(cookie.Value))
	}
	auth.ClearAuthCookies(c, secure)
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
	user, err := h.q.GetUserByID(c.Request().Context(), id)
	if err != nil {
		return c.JSON(http.StatusNotFound, map[string]string{"error": "user not found"})
	}
	dto := toDTO(user)
	return c.JSON(http.StatusOK, dto)
}

func (h *authHandlers) issueAndRespond(c *echo.Context, user db.User) error {
	ctx := c.Request().Context()
	secure := h.cfg.IsProd()

	access, _, err := auth.IssueAccessToken(user.ID, user.Username, user.UserType, h.cfg.JWTSecret, h.cfg.AccessTokenTTL)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	raw, hash, err := auth.NewRefreshToken()
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}
	if _, err := h.q.CreateRefreshToken(ctx, db.CreateRefreshTokenParams{
		UserID:    user.ID,
		TokenHash: hash,
		ExpiresAt: pgtype.Timestamptz{Time: time.Now().Add(h.cfg.RefreshTokenTTL), Valid: true},
	}); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "server error"})
	}

	auth.SetAccessCookie(c, access, h.cfg.AccessTokenTTL, secure)
	auth.SetRefreshCookie(c, raw, h.cfg.RefreshTokenTTL, secure)

	dto := toDTO(user)
	return c.JSON(http.StatusOK, tokenResp{
		AccessToken: access,
		ExpiresIn:   int(h.cfg.AccessTokenTTL.Seconds()),
		User:        &dto,
	})
}
