package host

import (
	"context"
	"time"
)

const gapRetryInterval = time.Second

func (s *Server) startGapRetries(ctx context.Context) <-chan struct{} {
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.runGapRetries(ctx)
	}()
	return done
}

// runGapRetries owns a single bounded retry loop, independent of guest traffic
// and inventory refreshes. Existing publication claims coordinate it with live
// sessions; retryPendingGaps releases every claim before returning.
func (s *Server) runGapRetries(ctx context.Context) {
	ticker := time.NewTicker(gapRetryInterval)
	defer ticker.Stop()
	s.gapRetryLoop(ctx, ticker.C)
}

func (s *Server) gapRetryLoop(ctx context.Context, ticks <-chan time.Time) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticks:
			s.retryPendingGaps(ctx)
		}
	}
}
