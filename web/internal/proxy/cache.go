package proxy

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/google/uuid"

	"torii/internal/db"
)

type CachedService struct {
	ID            uuid.UUID
	Title         string
	Domain        string
	Target        *url.URL
	Headers       map[string]string
	SigningSecret     []byte
	PreserveHost      bool
	PassthroughErrors bool
	// MaxBodySize caps the request body torii will forward to this upstream,
	// in bytes. 0 means no torii-imposed limit.
	MaxBodySize int64
	// ReadTimeout / WriteTimeout are per-request deadlines applied to the
	// client<->torii connection while proxying to this service (0 = no
	// deadline). Transport carries the upstream dial timeout. See
	// refreshLocked for how they're derived from the *_secs columns.
	ReadTimeout  time.Duration
	WriteTimeout time.Duration
	Transport    *http.Transport
	RoleIDs      map[uuid.UUID]struct{}
}

func (s *CachedService) AllowsAnyRole(roleIDs []uuid.UUID) bool {
	if len(s.RoleIDs) == 0 || len(roleIDs) == 0 {
		return false
	}
	for _, r := range roleIDs {
		if _, ok := s.RoleIDs[r]; ok {
			return true
		}
	}
	return false
}

type ServiceCache struct {
	mu       sync.RWMutex
	byDomain map[string]*CachedService
	loadedAt time.Time
	ttl      time.Duration
	q        *db.Queries
}

func NewServiceCache(q *db.Queries, ttl time.Duration) *ServiceCache {
	return &ServiceCache{
		byDomain: map[string]*CachedService{},
		ttl:      ttl,
		q:        q,
	}
}

func (c *ServiceCache) fresh() bool {
	return !c.loadedAt.IsZero() && time.Since(c.loadedAt) < c.ttl
}

func (c *ServiceCache) Lookup(ctx context.Context, host string) (*CachedService, bool) {
	c.mu.RLock()
	if c.fresh() {
		svc, ok := c.byDomain[host]
		c.mu.RUnlock()
		return svc, ok
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.fresh() {
		c.refreshLocked(ctx)
	}
	svc, ok := c.byDomain[host]
	return svc, ok
}

func (c *ServiceCache) Invalidate() {
	c.mu.Lock()
	c.loadedAt = time.Time{}
	c.mu.Unlock()
}

func (c *ServiceCache) refreshLocked(ctx context.Context) {
	rows, err := c.q.ListAllServicesWithRolesForCache(ctx)
	if err != nil {
		// Don't update loadedAt on failure: existing cache continues to
		// serve stale-but-functional data; next Lookup will retry. Log so
		// the operator notices DB issues instead of debugging "why aren't
		// my service config changes showing up" silently.
		fmt.Fprintln(os.Stderr, "[proxy] service cache refresh failed:", err)
		// Bump loadedAt to "stale ttl ago" so we don't re-hammer a broken
		// DB on every request — back off for one TTL.
		c.loadedAt = time.Now().Add(-c.ttl + 5*time.Second)
		return
	}
	next := make(map[string]*CachedService, len(rows))
	for _, r := range rows {
		target, err := url.Parse(r.ServiceUrl)
		if err != nil {
			continue
		}
		headers := map[string]string{}
		if len(r.Headers) > 0 {
			_ = json.Unmarshal(r.Headers, &headers)
		}
		roleSet := make(map[uuid.UUID]struct{}, len(r.RoleIds))
		for _, id := range r.RoleIds {
			roleSet[id] = struct{}{}
		}
		// Build the transport once per refresh so connections to this upstream
		// are pooled across requests. DialContext Timeout of 0 means no dial
		// timeout.
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.DialContext = (&net.Dialer{
			Timeout:   time.Duration(r.DialTimeoutSecs) * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext
		next[r.Domain] = &CachedService{
			ID:                r.ID,
			Title:             r.Title,
			Domain:            r.Domain,
			Target:            target,
			Headers:           headers,
			SigningSecret:     r.SigningSecret,
			PreserveHost:      r.PreserveHost,
			PassthroughErrors: r.PassthroughErrors,
			MaxBodySize:       r.MaxBodySize,
			ReadTimeout:       time.Duration(r.ReadTimeoutSecs) * time.Second,
			WriteTimeout:      time.Duration(r.WriteTimeoutSecs) * time.Second,
			Transport:         tr,
			RoleIDs:           roleSet,
		}
	}
	c.byDomain = next
	c.loadedAt = time.Now()
}
