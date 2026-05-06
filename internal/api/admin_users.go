package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/labstack/echo/v5"

	"sanmon/internal/auth"
	"sanmon/internal/db"
)

type adminUserListResp struct {
	pageMeta
	Items []userDTO `json:"items"`
}

type adminCreateUserReq struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	UserType  string `json:"user_type"`
}

func (h *authHandlers) adminListUsers(c *echo.Context) error {
	ctx := c.Request().Context()
	limit, offset, page, pageSize := parsePagination(c)

	rows, err := h.q.ListUsers(ctx, db.ListUsersParams{Lim: limit, Off: offset})
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not list users"})
	}
	total, err := h.q.CountUsers(ctx)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not count users"})
	}

	items := make([]userDTO, 0, len(rows))
	for _, u := range rows {
		items = append(items, toDTO(u))
	}
	return c.JSON(http.StatusOK, adminUserListResp{
		pageMeta: pageMeta{Page: page, PageSize: pageSize, Total: total},
		Items:    items,
	})
}

func (h *authHandlers) adminCreateUser(c *echo.Context) error {
	var req adminCreateUserReq
	if err := c.Bind(&req); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid body"})
	}
	req.Username = strings.TrimSpace(req.Username)
	req.Email = strings.ToLower(strings.TrimSpace(req.Email))
	req.FirstName = strings.TrimSpace(req.FirstName)
	req.LastName = strings.TrimSpace(req.LastName)
	req.UserType = strings.TrimSpace(req.UserType)

	if !usernameRe.MatchString(req.Username) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "username must be 3-64 chars: letters, digits, _ . -"})
	}
	if !emailRe.MatchString(req.Email) {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid email"})
	}
	if req.UserType != "admin" && req.UserType != "user" {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "user_type must be 'admin' or 'user'"})
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

	user, err := h.q.CreateUser(c.Request().Context(), db.CreateUserParams{
		Username:     req.Username,
		Email:        req.Email,
		FirstName:    req.FirstName,
		LastName:     req.LastName,
		PasswordHash: hash,
		UserType:     req.UserType,
	})
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return c.JSON(http.StatusConflict, map[string]string{"error": "username or email already taken"})
		}
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not create user"})
	}
	dto := toDTO(user)
	return c.JSON(http.StatusCreated, dto)
}

func (h *authHandlers) adminDeleteUser(c *echo.Context) error {
	id, err := uuid.Parse(c.Param("id"))
	if err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid id"})
	}
	claims := auth.ClaimsFrom(c)
	if claims != nil && claims.Subject == id.String() {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "cannot delete your own account"})
	}
	if err := h.q.DeleteUser(c.Request().Context(), id); err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "could not delete user"})
	}
	return c.NoContent(http.StatusNoContent)
}
