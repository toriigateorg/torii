package api

import (
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/labstack/echo/v5"
	"golang.org/x/time/rate"
)

// ipRateLimiter is an in-memory token-bucket per remote IP. torii is a
// single-binary deployment per CLAUDE.md so per-process state is fine; if
// horizontal scaling is added later this needs to move to a shared store.
type ipRateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipBucket
	r        rate.Limit
	burst    int
	idle     time.Duration
}

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

func newIPRateLimiter(rps rate.Limit, burst int) *ipRateLimiter {
	rl := &ipRateLimiter{
		limiters: map[string]*ipBucket{},
		r:        rps,
		burst:    burst,
		idle:     10 * time.Minute,
	}
	go rl.janitor()
	return rl
}

func (rl *ipRateLimiter) get(ip string) *rate.Limiter {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	b, ok := rl.limiters[ip]
	if !ok {
		b = &ipBucket{limiter: rate.NewLimiter(rl.r, rl.burst)}
		rl.limiters[ip] = b
	}
	b.lastSeen = time.Now()
	return b.limiter
}

func (rl *ipRateLimiter) janitor() {
	t := time.NewTicker(rl.idle)
	defer t.Stop()
	for range t.C {
		cutoff := time.Now().Add(-rl.idle)
		rl.mu.Lock()
		for ip, b := range rl.limiters {
			if b.lastSeen.Before(cutoff) {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// limiterKey folds an IP into the bucket it should share with its neighbours.
// IPv4 keys on the exact address; IPv6 keys on the /64, because a single host
// is routinely handed one and keying on the full 128 bits would give an
// attacker 2^64 fresh buckets — a per-IP limit that never triggers.
func limiterKey(ip string) string {
	addr, err := netip.ParseAddr(ip)
	if err != nil || !addr.Is6() || addr.Is4In6() {
		return ip
	}
	prefix, err := addr.Prefix(64)
	if err != nil {
		return ip
	}
	return prefix.String()
}

// rateLimit returns echo middleware that allows up to `burst` requests
// immediately and refills at `rps` requests per second per RemoteIP (per /64
// for IPv6). On rejection it returns 429 Too Many Requests.
func rateLimit(rps rate.Limit, burst int) echo.MiddlewareFunc {
	rl := newIPRateLimiter(rps, burst)
	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c *echo.Context) error {
			if !rl.get(limiterKey(c.RealIP())).Allow() {
				return c.JSON(http.StatusTooManyRequests, map[string]string{"error": "rate limit exceeded"})
			}
			return next(c)
		}
	}
}
