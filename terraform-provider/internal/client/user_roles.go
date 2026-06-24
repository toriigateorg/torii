package client

import (
	"context"
	"net/url"
)

type userRolesResp struct {
	Items []Role `json:"items"`
}

type userRoleAssignReq struct {
	RoleID string `json:"role_id"`
}

func (c *Client) ListUserRoles(ctx context.Context, userID string) ([]Role, error) {
	var out userRolesResp
	if err := c.do(ctx, "GET", "/api/v1/admin/users/"+url.PathEscape(userID)+"/roles", nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) AssignUserRole(ctx context.Context, userID, roleID string) error {
	return c.do(ctx, "POST", "/api/v1/admin/users/"+url.PathEscape(userID)+"/roles",
		userRoleAssignReq{RoleID: roleID}, nil)
}

func (c *Client) RevokeUserRole(ctx context.Context, userID, roleID string) error {
	return c.do(ctx, "DELETE",
		"/api/v1/admin/users/"+url.PathEscape(userID)+"/roles/"+url.PathEscape(roleID),
		nil, nil)
}
