package client

import (
	"context"
	"fmt"
	"net/url"
)

type SSOProvider struct {
	ID          string `json:"id"`
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	IssuerURL   string `json:"issuer_url"`
	ClientID    string `json:"client_id"`
	HasSecret   bool   `json:"has_secret"`
	Scopes      string `json:"scopes"`
	Enabled     bool   `json:"enabled"`
	AllowSignup bool   `json:"allow_signup"`
	LinkByEmail bool   `json:"link_by_email"`
	CreatedAt   string `json:"created_at"`
	UpdatedAt   string `json:"updated_at"`
}

// SSOWrite mirrors the admin API request. The pointer fields are optional
// server-side: a nil ClientSecret leaves the stored secret untouched, and the
// nil bools fall back to the server defaults on create.
type SSOWrite struct {
	Slug         string  `json:"slug"`
	Name         string  `json:"name"`
	IssuerURL    string  `json:"issuer_url"`
	ClientID     string  `json:"client_id"`
	ClientSecret *string `json:"client_secret,omitempty"`
	Scopes       string  `json:"scopes"`
	Enabled      *bool   `json:"enabled,omitempty"`
	AllowSignup  *bool   `json:"allow_signup,omitempty"`
	LinkByEmail  *bool   `json:"link_by_email,omitempty"`
}

type ssoListResp struct {
	Items    []SSOProvider `json:"items"`
	Page     int           `json:"page"`
	PageSize int           `json:"page_size"`
	Total    int64         `json:"total"`
}

// GetSSO fetches a single SSO provider by id. The torii API has no GET-by-id
// endpoint, so we paginate the list and match.
func (c *Client) GetSSO(ctx context.Context, id string) (*SSOProvider, error) {
	page := 1
	const pageSize = 100
	for {
		var resp ssoListResp
		path := fmt.Sprintf("/api/v1/admin/sso?page=%d&page_size=%d", page, pageSize)
		if err := c.do(ctx, "GET", path, nil, &resp); err != nil {
			return nil, err
		}
		for i := range resp.Items {
			if resp.Items[i].ID == id {
				return &resp.Items[i], nil
			}
		}
		if int64(page*pageSize) >= resp.Total || len(resp.Items) == 0 {
			return nil, ErrNotFound
		}
		page++
	}
}

func (c *Client) CreateSSO(ctx context.Context, in SSOWrite) (*SSOProvider, error) {
	var out SSOProvider
	if err := c.do(ctx, "POST", "/api/v1/admin/sso", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateSSO(ctx context.Context, id string, in SSOWrite) (*SSOProvider, error) {
	var out SSOProvider
	if err := c.do(ctx, "PATCH", "/api/v1/admin/sso/"+url.PathEscape(id), in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteSSO(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/api/v1/admin/sso/"+url.PathEscape(id), nil, nil)
}
