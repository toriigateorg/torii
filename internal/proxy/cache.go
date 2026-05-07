package proxy

import (
	"context"
	"encoding/json"
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"

	"sanmon/internal/db"
)

type CachedService struct {
	ID      uuid.UUID
	Domain  string
	Target  *url.URL
	Headers map[string]string
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
	rows, err := c.q.ListAllServicesForCache(ctx)
	if err != nil {
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
		next[r.Domain] = &CachedService{
			ID:      r.ID,
			Domain:  r.Domain,
			Target:  target,
			Headers: headers,
		}
	}
	c.byDomain = next
	c.loadedAt = time.Now()
}
