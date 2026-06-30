package api

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	"torii/internal/db"
)

// Service API user last-used updates mirror the PAT touch machinery in
// api_token_touch.go: coalesced per id to at most once a minute, bounded by a
// fixed worker pool, dropped on overflow. Kept as a separate pool rather than
// generalizing the PAT one — two callers don't justify the indirection.

const (
	apiUserTouchInterval = 60 * time.Second
	apiUserTouchWorkers  = 4
	apiUserTouchQueueLen = 256
)

var (
	apiUserTouchOnce      sync.Once
	apiUserTouchQueue     chan uuid.UUID
	apiUserTouchLastSeen  sync.Map // map[uuid.UUID]time.Time
	apiUserTouchQueriesFn func(ctx context.Context, id uuid.UUID) error
)

func startAPIUserTouchWorkers(q *db.Queries) {
	apiUserTouchOnce.Do(func() {
		apiUserTouchQueue = make(chan uuid.UUID, apiUserTouchQueueLen)
		apiUserTouchQueriesFn = func(ctx context.Context, id uuid.UUID) error {
			return q.TouchAPIUserLastUsed(ctx, id)
		}
		for i := 0; i < apiUserTouchWorkers; i++ {
			go apiUserTouchWorker()
		}
	})
}

func apiUserTouchWorker() {
	for id := range apiUserTouchQueue {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = apiUserTouchQueriesFn(ctx, id)
		cancel()
	}
}

func scheduleTouchAPIUser(q *db.Queries, id uuid.UUID) {
	startAPIUserTouchWorkers(q)
	now := time.Now()
	if v, ok := apiUserTouchLastSeen.Load(id); ok {
		if last, ok := v.(time.Time); ok && now.Sub(last) < apiUserTouchInterval {
			return
		}
	}
	apiUserTouchLastSeen.Store(id, now)
	select {
	case apiUserTouchQueue <- id:
	default:
	}
}
