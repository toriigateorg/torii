package proxy

import (
	"context"
	"encoding/json"
	"fmt"
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
	SigningSecret []byte
	RoleIDs       map[uuid.UUID]struct{}
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
		next[r.Domain] = &CachedService{
			ID:            r.ID,
			Title:         r.Title,
			Domain:        r.Domain,
			Target:        target,
			Headers:       headers,
			SigningSecret: r.SigningSecret,
			RoleIDs:       roleSet,
		}
	}
	c.byDomain = next
	c.loadedAt = time.Now()
}
