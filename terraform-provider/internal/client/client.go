package client

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	endpoint   string
	apiToken   string
	httpClient *http.Client
	userAgent  string
}

type Option func(*Client)

func WithHTTPClient(c *http.Client) Option { return func(cl *Client) { cl.httpClient = c } }
func WithUserAgent(s string) Option        { return func(cl *Client) { cl.userAgent = s } }

func New(endpoint, apiToken string, opts ...Option) (*Client, error) {
	endpoint = strings.TrimRight(endpoint, "/")
	if endpoint == "" {
		return nil, errors.New("torii: endpoint is required")
	}
	if _, err := url.Parse(endpoint); err != nil {
		return nil, fmt.Errorf("torii: invalid endpoint: %w", err)
	}
	if apiToken == "" {
		return nil, errors.New("torii: api_token is required")
	}
	c := &Client{
		endpoint:   endpoint,
		apiToken:   apiToken,
		httpClient: &http.Client{Timeout: 30 * time.Second},
		userAgent:  "terraform-provider-torii/dev",
	}
	for _, o := range opts {
		o(c)
	}
	return c, nil
}

type errBody struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

func (c *Client) do(ctx context.Context, method, path string, body any, out any) error {
	var reader io.Reader
	if body != nil {
		buf, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("torii: marshal body: %w", err)
		}
		reader = bytes.NewReader(buf)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint+path, reader)
	if err != nil {
		return err
	}
	if reader != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiToken)
	req.Header.Set("User-Agent", c.userAgent)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return ErrNotFound
	}
	if resp.StatusCode >= 400 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		var eb errBody
		_ = json.Unmarshal(bodyBytes, &eb)
		msg := eb.Error
		if msg == "" {
			msg = eb.Message
		}
		if msg == "" {
			msg = strings.TrimSpace(string(bodyBytes))
		}
		return &APIError{Status: resp.StatusCode, Message: msg}
	}
	if out == nil || resp.StatusCode == http.StatusNoContent {
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}
