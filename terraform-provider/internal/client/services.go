package client

import (
	"context"
	"fmt"
	"net/url"
)

type Service struct {
	ID                string            `json:"id"`
	Title             string            `json:"title"`
	Description       string            `json:"description"`
	ServiceURL        string            `json:"service_url"`
	Domain            string            `json:"domain"`
	Headers           map[string]string `json:"headers"`
	PreserveHost      bool              `json:"preserve_host"`
	PassthroughErrors bool              `json:"passthrough_errors"`
	MaxBodySize       int64             `json:"max_body_size"`
	ReadTimeoutSecs   int32             `json:"read_timeout_secs"`
	WriteTimeoutSecs  int32             `json:"write_timeout_secs"`
	DialTimeoutSecs   int32             `json:"dial_timeout_secs"`
	CreatedAt         string            `json:"created_at"`
	UpdatedAt         string            `json:"updated_at"`
}

// ServiceWrite mirrors the admin API's request shape. The four pointer fields
// are optional server-side (nil keeps the server default); preserve_host is a
// plain bool the server reads unconditionally.
type ServiceWrite struct {
	Title             string            `json:"title"`
	Description       string            `json:"description"`
	ServiceURL        string            `json:"service_url"`
	Domain            string            `json:"domain"`
	Headers           map[string]string `json:"headers"`
	PreserveHost      bool              `json:"preserve_host"`
	PassthroughErrors *bool             `json:"passthrough_errors,omitempty"`
	MaxBodySize       *int64            `json:"max_body_size,omitempty"`
	ReadTimeoutSecs   *int32            `json:"read_timeout_secs,omitempty"`
	WriteTimeoutSecs  *int32            `json:"write_timeout_secs,omitempty"`
	DialTimeoutSecs   *int32            `json:"dial_timeout_secs,omitempty"`
}

type serviceListResp struct {
	Items    []Service `json:"items"`
	Page     int       `json:"page"`
	PageSize int       `json:"page_size"`
	Total    int64     `json:"total"`
}

// GetService fetches a single service by id. The torii API has no GET-by-id
// endpoint, so we paginate the list and match. Acceptable for the provider's
// expected scale (tens-to-hundreds of services).
func (c *Client) GetService(ctx context.Context, id string) (*Service, error) {
	page := 1
	const pageSize = 100
	for {
		var resp serviceListResp
		path := fmt.Sprintf("/api/v1/admin/services?page=%d&page_size=%d", page, pageSize)
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

// FindServiceByDomain resolves a service by its exact domain using the
// server-side search filter.
func (c *Client) FindServiceByDomain(ctx context.Context, domain string) (*Service, error) {
	page := 1
	const pageSize = 100
	for {
		var resp serviceListResp
		path := fmt.Sprintf("/api/v1/admin/services?page=%d&page_size=%d&search=%s",
			page, pageSize, url.QueryEscape(domain))
		if err := c.do(ctx, "GET", path, nil, &resp); err != nil {
			return nil, err
		}
		for i := range resp.Items {
			if resp.Items[i].Domain == domain {
				return &resp.Items[i], nil
			}
		}
		if int64(page*pageSize) >= resp.Total || len(resp.Items) == 0 {
			return nil, ErrNotFound
		}
		page++
	}
}

func (c *Client) CreateService(ctx context.Context, in ServiceWrite) (*Service, error) {
	var out Service
	if err := c.do(ctx, "POST", "/api/v1/admin/services", in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateService(ctx context.Context, id string, in ServiceWrite) (*Service, error) {
	var out Service
	if err := c.do(ctx, "PATCH", "/api/v1/admin/services/"+url.PathEscape(id), in, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) DeleteService(ctx context.Context, id string) error {
	return c.do(ctx, "DELETE", "/api/v1/admin/services/"+url.PathEscape(id), nil, nil)
}
