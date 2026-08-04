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
	"syscall"
	"time"

	"github.com/google/uuid"

	"torii/internal/db"
	"torii/internal/netutil"
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

// refreshBackoff is how long a failed refresh keeps serving the previous map
// before another Lookup is allowed to retry, so a broken database is not
// re-queried once per request.
//
// refreshTimeout bounds a single refresh query. It has to exist because the
// refresh no longer runs on a request context (see refreshLocked), so nothing
// else would ever cancel it — and it runs under the cache write lock, which
// every proxied request queues behind.
const (
	refreshBackoff = 5 * time.Second
	refreshTimeout = 10 * time.Second
)

type ServiceCache struct {
	mu       sync.RWMutex
	byDomain map[string]*CachedService
	loadedAt time.Time
	// retryAfter is set when a refresh fails, and is what keeps the stale map in
	// service for refreshBackoff. It used to be expressed by backdating loadedAt,
	// which made fresh() report a successful load that had not happened and put
	// the backoff window at odds with the comment describing it.
	retryAfter time.Time
	ttl        time.Duration
	q          *db.Queries
	// blockLoopback mirrors cfg.BlockLoopbackUpstreams and is applied by the
	// dial-time SSRF guard installed on each service transport.
	blockLoopback bool
}

func NewServiceCache(q *db.Queries, ttl time.Duration, blockLoopback bool) *ServiceCache {
	return &ServiceCache{
		byDomain:      map[string]*CachedService{},
		ttl:           ttl,
		q:             q,
		blockLoopback: blockLoopback,
	}
}

func (c *ServiceCache) fresh() bool {
	if !c.loadedAt.IsZero() && time.Since(c.loadedAt) < c.ttl {
		return true
	}
	return !c.retryAfter.IsZero() && time.Now().Before(c.retryAfter)
}

// Lookup resolves a host to its service, refreshing the cache when stale.
//
// ctx is deliberately not threaded into the refresh. Lookup is called from
// dispatch on the client's request context, before authentication, so a client
// that cancels mid-refresh used to abort a load of *shared* routing state: the
// stale map survived and freshness was re-armed, meaning a deleted service kept
// being proxied with its credential overlay, a revoked role_services binding kept
// granting access, and a rotated signing secret kept signing. The refresh serves
// every caller, so it gets its own lifetime.
func (c *ServiceCache) Lookup(_ context.Context, host string) (*CachedService, bool) {
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
		refreshCtx, cancel := context.WithTimeout(context.Background(), refreshTimeout)
		c.refreshLocked(refreshCtx)
		cancel()
	}
	svc, ok := c.byDomain[host]
	return svc, ok
}

func (c *ServiceCache) Invalidate() {
	c.mu.Lock()
	c.loadedAt = time.Time{}
	// Cleared too, or an Invalidate landing inside a post-failure backoff window
	// would be silently ignored for the rest of it.
	c.retryAfter = time.Time{}
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
		c.retryAfter = time.Now().Add(refreshBackoff)
		return
	}
	c.retryAfter = time.Time{}
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
		//
		// Control runs after DNS resolution with the concrete socket address,
		// so the SSRF deny set is enforced against the IP actually being dialed
		// rather than whatever the hostname resolved to when an operator saved
		// the service. That closes the DNS-rebinding window left open by the
		// write-time check in validateServiceReq.
		blockLoopback := c.blockLoopback
		tr := http.DefaultTransport.(*http.Transport).Clone()
		// The clone inherits ProxyFromEnvironment. With a proxy configured the
		// dialer connects to the proxy, so the Control hook above would be
		// inspecting the proxy's address and the SSRF deny set would be applied to
		// the wrong host entirely — the real target travels as a CONNECT/absolute
		// URI the hook never sees.
		tr.Proxy = nil
		tr.DialContext = (&net.Dialer{
			Timeout:   time.Duration(r.DialTimeoutSecs) * time.Second,
			KeepAlive: 30 * time.Second,
			Control: func(network, address string, _ syscall.RawConn) error {
				return netutil.IsSafeUpstreamAddr(address, blockLoopback)
			},
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
