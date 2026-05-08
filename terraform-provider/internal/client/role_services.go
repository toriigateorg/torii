package client

import (
	"context"
	"net/url"
)

type roleServicesResp struct {
	Items []Service `json:"items"`
}

type roleServiceCreateReq struct {
	ServiceID string `json:"service_id"`
}

func (c *Client) ListRoleServices(ctx context.Context, roleID string) ([]Service, error) {
	var out roleServicesResp
	if err := c.do(ctx, "GET", "/api/v1/admin/roles/"+url.PathEscape(roleID)+"/services", nil, &out); err != nil {
		return nil, err
	}
	return out.Items, nil
}

func (c *Client) AssignRoleService(ctx context.Context, roleID, serviceID string) error {
	return c.do(ctx, "POST", "/api/v1/admin/roles/"+url.PathEscape(roleID)+"/services",
		roleServiceCreateReq{ServiceID: serviceID}, nil)
}

func (c *Client) RevokeRoleService(ctx context.Context, roleID, serviceID string) error {
	return c.do(ctx, "DELETE",
		"/api/v1/admin/roles/"+url.PathEscape(roleID)+"/services/"+url.PathEscape(serviceID),
		nil, nil)
}
