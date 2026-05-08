package client

import (
	"context"
	"net/url"
)

type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	IsSystem    bool     `json:"is_system"`
	Permissions []string `json:"permissions"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
}

type RoleCreate struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
}

type RoleUpdate struct {
	Name        *string `json:"name,omitempty"`
	Description *string `json:"description,omitempty"`
}

type rolePermsResp struct {
	Permissions []string `json:"permissions"`
}

func (c *Client) GetRole(ctx context.Context, id string) (*Role, error) {
	var out Role
	if err := c.do(ctx, "GET", "/api/v1/admin/roles/"+url.PathEscape(id), nil, &out); err != nil {
		return nil, err
	}
	if out.Permissions == nil {
		out.Permissions = []string{}
	}
	return &out, nil
}

func (c *Client) CreateRole(ctx context.Context, in RoleCreate) (*Role, error) {
	var out Role
	if err := c.do(ctx, "POST", "/api/v1/admin/roles", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateRole(ctx context.Context, id string, in RoleUpdate) (*Role, error) {
	var out Role
	if err := c.do(ctx, "PATCH", "/api/v1/admin/roles/"+url.PathEscape(id), in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteRole(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/api/v1/admin/roles/"+url.PathEscape(id), nil, nil)
}

func (c *Client) GetRolePermissions(ctx context.Context, id string) ([]string, error) {
	var out rolePermsResp
	if err := c.do(ctx, "GET", "/api/v1/admin/roles/"+url.PathEscape(id)+"/permissions", nil, &out); err != nil {
		return nil, err
	}
	if out.Permissions == nil {
		return []string{}, nil
	}
	return out.Permissions, nil
}

func (c *Client) SetRolePermissions(ctx context.Context, id string, perms []string) ([]string, error) {
	if perms == nil {
		perms = []string{}
	}
	body := rolePermsResp{Permissions: perms}
	var out rolePermsResp
	if err := c.do(ctx, "PUT", "/api/v1/admin/roles/"+url.PathEscape(id)+"/permissions", body, &out); err != nil {
		return nil, err
	}
	if out.Permissions == nil {
		return []string{}, nil
	}
	return out.Permissions, nil
}

// ListAvailablePermissions returns the catalog of permission strings the
// server recognizes; used to validate `torii_role.permissions` client-side
// so users get a fast, clear error instead of a generic 400.
func (c *Client) ListAvailablePermissions(ctx context.Context) ([]string, error) {
	var out struct {
		Items []string `json:"items"`
	}
	if err := c.do(ctx, "GET", "/api/v1/admin/permissions", nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}
