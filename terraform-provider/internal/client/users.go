package client

import (
	"context"
	"fmt"
	"net/url"
)

type RoleSummary struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type User struct {
	ID          string        `json:"id"`
	Username    string        `json:"username"`
	Email       string        `json:"email"`
	FirstName   string        `json:"first_name"`
	LastName    string        `json:"last_name"`
	Roles       []RoleSummary `json:"roles"`
	Permissions []string      `json:"permissions"`
}

type UserCreate struct {
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type userListResp struct {
	Items    []User `json:"items"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Total    int64  `json:"total"`
}

// ListUsers returns one page of users, optionally filtered by the server-side
// search term (matches username/email).
func (c *Client) ListUsers(ctx context.Context, search string, page, pageSize int) ([]User, int64, error) {
	q := url.Values{}
	q.Set("page", fmt.Sprintf("%d", page))
	q.Set("page_size", fmt.Sprintf("%d", pageSize))
	if search != "" {
		q.Set("search", search)
	}
	var resp userListResp
	if err := c.do(ctx, "GET", "/api/v1/admin/users?"+q.Encode(), nil, &resp); err != nil {
		return nil, 0, err
	}
	return resp.Items, resp.Total, nil
}

// GetUser fetches a single user by id. The torii API has no GET-by-id endpoint,
// so we paginate the list and match.
func (c *Client) GetUser(ctx context.Context, id string) (*User, error) {
	page := 1
	const pageSize = 100
	for {
		items, total, err := c.ListUsers(ctx, "", page, pageSize)
		if err != nil {
			return nil, err
		}
		for i := range items {
			if items[i].ID == id {
				return &items[i], nil
			}
		}
		if int64(page*pageSize) >= total || len(items) == 0 {
			return nil, ErrNotFound
		}
		page++
	}
}

// FindUserByUsername resolves a user by exact username via the search filter.
func (c *Client) FindUserByUsername(ctx context.Context, username string) (*User, error) {
	page := 1
	const pageSize = 100
	for {
		items, total, err := c.ListUsers(ctx, username, page, pageSize)
		if err != nil {
			return nil, err
		}
		for i := range items {
			if items[i].Username == username {
				return &items[i], nil
			}
		}
		if int64(page*pageSize) >= total || len(items) == 0 {
			return nil, ErrNotFound
		}
		page++
	}
}

func (c *Client) CreateUser(ctx context.Context, in UserCreate) (*User, error) {
	var out User
	if err := c.do(ctx, "POST", "/api/v1/admin/users", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

type setPasswordReq struct {
	New string `json:"new"`
}

func (c *Client) SetUserPassword(ctx context.Context, id, password string) error {
	return c.do(ctx, "POST", "/api/v1/admin/users/"+url.PathEscape(id)+"/password",
		setPasswordReq{New: password}, nil)
}

func (c *Client) DeleteUser(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/api/v1/admin/users/"+url.PathEscape(id), nil, nil)
}
