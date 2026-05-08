package api

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"torii/internal/db"
)

// PAT last-used updates are best-effort: high-volume API callers shouldn't
// each trigger a goroutine + DB write per request. We coalesce updates per
// token to at most once a minute and bound the total in-flight work via a
// fixed-size worker pool. Drops on overflow are intentional — the existing
// row's last_used_at just remains the previous value briefly.

const (
	apiTokenTouchInterval = 60 * time.Second
	apiTokenTouchWorkers  = 4
	apiTokenTouchQueueLen = 256
)

var (
	apiTouchOnce      sync.Once
	apiTouchQueue     chan uuid.UUID
	apiTouchLastSeen  sync.Map // map[uuid.UUID]time.Time
	apiTouchQueriesFn func(ctx context.Context, id uuid.UUID) error
)

func startAPITokenTouchWorkers(q *db.Queries) {
	apiTouchOnce.Do(func() {
		apiTouchQueue = make(chan uuid.UUID, apiTokenTouchQueueLen)
		apiTouchQueriesFn = func(ctx context.Context, id uuid.UUID) error {
			return q.TouchAPITokenLastUsed(ctx, id)
		}
		for i := 0; i < apiTokenTouchWorkers; i++ {
			go apiTokenTouchWorker()
		}
	})
}

func apiTokenTouchWorker() {
	for id := range apiTouchQueue {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = apiTouchQueriesFn(ctx, id)
		cancel()
	}
}

// scheduleTouchAPIToken records that token id was just used. Coalesced to at
// most one DB write per token per apiTokenTouchInterval; drops silently if
// the worker queue is full.
func scheduleTouchAPIToken(q *db.Queries, id uuid.UUID) {
	startAPITokenTouchWorkers(q)
	now := time.Now()
	if v, ok := apiTouchLastSeen.Load(id); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < apiTokenTouchInterval {
			return
		}
	}
	apiTouchLastSeen.Store(id, now)
	select {
	case apiTouchQueue <- id:
	default:
		// Queue full: drop. Worst case last_used_at is stale by a minute,
		// which is fine — this is observability, not correctness.
	}
}
