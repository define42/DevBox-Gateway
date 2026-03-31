// Package session manages authenticated browser sessions for the gateway.
package session

import (
	"context"
	"encoding/gob"
	"net"
	"net/http"
	"net/netip"
	"rdptlsgateway/internal/types"
	"strings"
	"sync"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

type sessionData struct {
	User      *types.User
	CreatedAt time.Time
	ClientIP  string
}

const sessionKey = "session"

const sessionTTL = 30 * time.Minute

var registerSessionTypesOnce sync.Once //nolint:gochecknoglobals // package-level singleton needed for one-time registration

type Manager struct {
	*scs.SessionManager
}

func NewManager() *Manager {
	registerSessionTypes()
	return &Manager{SessionManager: newSessionManager()}
}

func registerSessionTypes() {
	registerSessionTypesOnce.Do(func() {
		gob.Register(sessionData{})
	})
}

func newSessionManager() *scs.SessionManager {
	manager := scs.New()
	manager.Store = memstore.New()
	manager.Lifetime = sessionTTL
	manager.Cookie.Name = "cv_session"
	manager.Cookie.Path = "/"
	manager.Cookie.HttpOnly = true
	manager.Cookie.SameSite = http.SameSiteLaxMode
	manager.Cookie.Secure = true
	return manager
}

func CanonicalClientIP(remoteAddr string) (string, bool) {
	remoteAddr = strings.TrimSpace(remoteAddr)
	if remoteAddr == "" {
		return "", false
	}

	if addrPort, err := netip.ParseAddrPort(remoteAddr); err == nil {
		return addrPort.Addr().Unmap().String(), true
	}

	host, _, err := net.SplitHostPort(remoteAddr)
	if err == nil {
		remoteAddr = host
	}

	addr, err := netip.ParseAddr(remoteAddr)
	if err != nil {
		return "", false
	}

	return addr.Unmap().String(), true
}

func (m *Manager) CreateSession(ctx context.Context, u *types.User, clientIP string) error {
	if err := m.RenewToken(ctx); err != nil {
		return err
	}
	canonicalIP, _ := CanonicalClientIP(clientIP)
	m.Put(ctx, sessionKey, sessionData{
		User:      u,
		CreatedAt: time.Now(),
		ClientIP:  canonicalIP,
	})
	return nil
}

func (m *Manager) getSession(r *http.Request) (sessionData, bool) {
	sess, ok := m.Get(r.Context(), sessionKey).(sessionData)
	if !ok || sess.User == nil {
		return sessionData{}, false
	}
	return sess, true
}

func (m *Manager) UserFromContext(ctx context.Context) (*types.User, bool) {
	if ctx == nil {
		return nil, false
	}
	if sess, ok := m.Get(ctx, sessionKey).(sessionData); ok && sess.User != nil {
		return sess.User, true
	}
	if sess, ok := ctx.Value(sessionContextKey{}).(sessionData); ok && sess.User != nil {
		return sess.User, true
	}
	return nil, false
}

func (m *Manager) GetSessionFromUserName(username string) (sessionData, bool) {
	username = strings.TrimSpace(username)
	if username == "" {
		return sessionData{}, false
	}

	for _, sess := range m.allSessions() {
		if sess.User != nil && sess.User.GetName() == username {
			return sess, true
		}
	}
	return sessionData{}, false
}

func (m *Manager) UserHasActiveSessionFromIP(username, clientIP string) bool {
	username = strings.TrimSpace(username)
	if username == "" {
		return false
	}

	canonicalIP, ok := CanonicalClientIP(clientIP)
	if !ok {
		return false
	}

	for _, sess := range m.allSessions() {
		if sess.User == nil {
			continue
		}
		if sess.User.GetName() == username && sess.ClientIP == canonicalIP {
			return true
		}
	}
	return false
}

func (m *Manager) allSessions() []sessionData {
	store, ok := m.Store.(scs.IterableStore)
	if !ok {
		return nil
	}
	sessions, err := store.All()
	if err != nil {
		return nil
	}

	decoded := make([]sessionData, 0, len(sessions))
	for _, raw := range sessions {
		_, values, err := m.Codec.Decode(raw)
		if err != nil {
			continue
		}
		if sess, ok := values[sessionKey].(sessionData); ok {
			decoded = append(decoded, sess)
		}
	}

	return decoded
}

func (m *Manager) DestroySession(ctx context.Context) error {
	return m.Destroy(ctx)
}

type sessionContextKey struct{}

func (m *Manager) SessionMiddleware() func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		req, w := humachi.Unwrap(ctx)

		sess, ok := m.getSession(req)
		if !ok || sess.User == nil {
			http.Redirect(w, req, "/login", http.StatusSeeOther)
			return
		}

		next(huma.WithValue(ctx, sessionContextKey{}, sess))
	}
}
