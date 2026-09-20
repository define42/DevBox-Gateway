package session

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/audit"
	"github.com/define42/devbox-gateway/internal/identity"

	"github.com/alexedwards/scs/v2"
)

// sessionExpiryStore decorates the in-memory SCS store so an authenticated
// session's absolute expiry remains attributable after SCS has made the record
// indistinguishable from a missing token. SCS intentionally exposes no expiry
// callback, so successful commits are the last reliable point at which the
// identity and deadline are available together.
type sessionExpiryStore struct {
	inner    scs.Store
	iterable scs.IterableStore
	codec    scs.Codec

	mu      sync.Mutex
	tracked map[string]*trackedSessionExpiry
	closed  bool
	active  sync.WaitGroup
}

type trackedSessionExpiry struct {
	user     identity.User
	sourceIP string
	expires  time.Time
	timer    *time.Timer
}

func newSessionExpiryStore(inner scs.Store, codec scs.Codec) (*sessionExpiryStore, error) {
	iterable, ok := inner.(scs.IterableStore)
	if !ok {
		return nil, fmt.Errorf("session store does not support iteration")
	}
	return &sessionExpiryStore{
		inner:    inner,
		iterable: iterable,
		codec:    codec,
		tracked:  make(map[string]*trackedSessionExpiry),
	}, nil
}

func (s *sessionExpiryStore) Delete(token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.inner.Delete(token); err != nil {
		return err
	}
	s.cancelLocked(token)
	return nil
}

func (s *sessionExpiryStore) Find(token string) ([]byte, bool, error) {
	return s.inner.Find(token)
}

func (s *sessionExpiryStore) Commit(token string, data []byte, expiry time.Time) error {
	tracked, decodeErr := s.decodeTrackedSession(data, expiry)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("session store is closed")
	}
	// A request can load an authenticated session immediately before its
	// absolute deadline and try to save a grant immediately afterwards. Never
	// let that stale save resurrect a token which the timeout callback has
	// already deleted (and audited), or replace its pending timer with a second
	// immediate callback.
	if !expiry.After(time.Now()) {
		current := s.removeLocked(token)
		err := s.inner.Delete(token)
		if current != nil {
			s.active.Add(1)
		}
		s.mu.Unlock()
		if current != nil {
			defer s.active.Done()
			s.auditTimeout(current, err)
		}
		if err != nil {
			return fmt.Errorf("session has expired and cleanup failed: %w", err)
		}
		return errors.New("session has expired")
	}
	if err := s.inner.Commit(token, data, expiry); err != nil {
		s.mu.Unlock()
		return err
	}
	s.cancelLocked(token)
	if decodeErr != nil {
		// Preserve the SCS Store contract for non-SCS callers: persistence
		// succeeded, but malformed data cannot safely be attributed for expiry.
		log.Printf("decode committed session for expiry audit: %v", decodeErr)
		s.mu.Unlock()
		return nil
	}
	if tracked == nil {
		s.mu.Unlock()
		return nil
	}

	s.tracked[token] = tracked
	s.scheduleLocked(token, tracked)
	s.mu.Unlock()
	return nil
}

func (s *sessionExpiryStore) scheduleLocked(token string, tracked *trackedSessionExpiry) {
	delay := time.Until(tracked.expires)
	if delay < 0 {
		delay = 0
	}
	tracked.timer = time.AfterFunc(delay, func() {
		s.expire(token, tracked)
	})
}

func (s *sessionExpiryStore) All() (map[string][]byte, error) {
	return s.iterable.All()
}

func (s *sessionExpiryStore) decodeTrackedSession(data []byte, expiry time.Time) (*trackedSessionExpiry, error) {
	_, values, err := s.codec.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decode session for expiry audit: %w", err)
	}
	sess, ok := values[sessionKey].(sessionData)
	if !ok || sess.User == nil {
		return nil, nil
	}
	return &trackedSessionExpiry{
		user:     *sess.User,
		sourceIP: sess.ClientIP,
		expires:  expiry,
	}, nil
}

func (s *sessionExpiryStore) expire(token string, expected *trackedSessionExpiry) {
	s.mu.Lock()
	current, ok := s.tracked[token]
	if !ok || current != expected || s.closed {
		s.mu.Unlock()
		return
	}
	if delay := time.Until(current.expires); delay > 0 {
		current.timer.Reset(delay)
		s.mu.Unlock()
		return
	}
	s.removeLocked(token)
	err := s.inner.Delete(token)
	s.active.Add(1)
	s.mu.Unlock()
	defer s.active.Done()
	s.auditTimeout(current, err)
}

func (s *sessionExpiryStore) auditTimeout(current *trackedSessionExpiry, err error) {
	result := audit.ResultSuccess
	if err != nil {
		result = audit.ResultFailure
		log.Printf("delete expired session for user %q: %v", current.user.Name, err)
	}
	audit.Log(context.Background(), audit.Event{
		Action:        audit.ActionUserLogout,
		User:          current.user.Name,
		Result:        result,
		SourceIP:      current.sourceIP,
		Operation:     audit.OperationLogoutTimeout,
		Administrator: current.user.IsAdmin,
	})
}

// claim removes token from timeout tracking and returns its immutable identity
// snapshot. Higher-level invalidation paths use this as their exact-once
// linearization point before deleting the SCS session.
func (s *sessionExpiryStore) claim(token string) *trackedSessionExpiry {
	s.mu.Lock()
	defer s.mu.Unlock()

	tracked, ok := s.tracked[token]
	if !ok {
		return nil
	}
	delete(s.tracked, token)
	tracked.timer.Stop()
	return tracked
}

// restore reinstates a claimed timeout when the higher-level invalidation did
// not manage to delete the session. A concurrent successful commit or shutdown
// wins over the stale claim and leaves it canceled.
func (s *sessionExpiryStore) restore(token string, tracked *trackedSessionExpiry) {
	if tracked == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	if _, exists := s.tracked[token]; exists {
		return
	}
	s.tracked[token] = tracked
	s.scheduleLocked(token, tracked)
}

func (s *sessionExpiryStore) cancelLocked(token string) {
	s.removeLocked(token)
}

func (s *sessionExpiryStore) removeLocked(token string) *trackedSessionExpiry {
	tracked := s.tracked[token]
	if tracked != nil {
		delete(s.tracked, token)
		tracked.timer.Stop()
	}
	return tracked
}

// Close prevents any pending session timeout from emitting after the gateway's
// audit sink has begun shutting down. The SCS Store interface has no lifecycle
// method, so the underlying store retains its existing process lifetime.
func (s *sessionExpiryStore) Close() {
	s.mu.Lock()
	if !s.closed {
		s.closed = true
		for token := range s.tracked {
			s.cancelLocked(token)
		}
	}
	s.mu.Unlock()
	s.active.Wait()
}
