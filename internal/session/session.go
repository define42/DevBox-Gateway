// Package session manages authenticated browser sessions for the gateway.
package session

import (
	"context"
	"devboxgateway/internal/types"
	"encoding/gob"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
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
	// RDPConnectGrants records, per VM name, the instant until which an RDP
	// connection for that VM is authorized from this session's client IP. A
	// grant is created when the user clicks "Connect" (downloads the .rdp),
	// expires after rdpConnectWindow, and is single-use, so a standing dashboard
	// session no longer implicitly authorizes RDP — see ConsumeRDPConnectGrant
	// and the RDP front handler's authorizeRDPAccess.
	RDPConnectGrants map[string]time.Time
}

const sessionKey = "session"

// sessionTTL is the absolute lifetime of an authenticated browser session.
// Credentials are verified once at login and not re-checked against the
// directory afterwards, so this bound caps how long a revoked directory account
// can start new dashboard, RDP, or console access. Existing long-lived RDP and
// WebSocket connections are not re-checked against LDAP while open; explicit
// gateway logout closes tracked user connections via CloseUserConnections.
const sessionTTL = 30 * time.Minute

// rdpConnectWindow bounds how long an explicit "Connect" action authorizes RDP
// for a VM from the session's client IP. It must cover a user downloading the
// .rdp file and launching their RDP client (so the initial connection
// establishes), while staying short enough that a logged-in dashboard session
// does not leave a standing, always-open RDP authorization. The grant is also
// single-use (see ConsumeRDPConnectGrant), so a reconnect or any second
// connection requires clicking Connect again even within this window.
const rdpConnectWindow = 2 * time.Minute

var registerSessionTypesOnce sync.Once //nolint:gochecknoglobals // package-level singleton needed for one-time registration

// Manager wraps the session store used by HTTP handlers and middleware.
type Manager struct {
	*scs.SessionManager

	connectionsMu    sync.Mutex
	nextConnectionID uint64
	userConnections  map[string]map[uint64]func()
}

// NewManager constructs the gateway session manager.
func NewManager() *Manager {
	registerSessionTypes()
	return &Manager{
		SessionManager:  newSessionManager(),
		userConnections: make(map[string]map[uint64]func()),
	}
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

// CanonicalClientIP normalizes a remote address down to a comparable client IP string.
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

// CreateSession stores the authenticated user and canonical client IP in the
// session. The caller verifies credentials at login time; the session is then
// trusted until it expires (see sessionTTL), so no password is retained.
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

// GrantRDPConnect opens a short-lived RDP authorization window for vmName on the
// caller's own session, recording that the user explicitly clicked "Connect".
// The grant is checked by ConsumeRDPConnectGrant when an RDP connection arrives. It
// must be called within an authenticated request so the session is loaded; the
// grant is persisted when the session is committed (via the LoadAndSave
// middleware) before the response — and therefore before the RDP client dials.
func (m *Manager) GrantRDPConnect(ctx context.Context, vmName string) error {
	vmName = strings.TrimSpace(vmName)
	if vmName == "" {
		return errors.New("vm name is required")
	}

	sess, ok := m.Get(ctx, sessionKey).(sessionData)
	if !ok || sess.User == nil {
		return errors.New("no authenticated session")
	}

	now := time.Now()
	grants := make(map[string]time.Time, len(sess.RDPConnectGrants)+1)
	// Carry over only still-valid grants so the map cannot grow unbounded with
	// expired entries for VMs the user connected to earlier.
	for name, expiry := range sess.RDPConnectGrants {
		if now.Before(expiry) {
			grants[name] = expiry
		}
	}
	grants[vmName] = now.Add(rdpConnectWindow)

	sess.RDPConnectGrants = grants
	m.Put(ctx, sessionKey, sess)
	return nil
}

func (m *Manager) getSession(r *http.Request) (sessionData, bool) {
	sess, ok := m.Get(r.Context(), sessionKey).(sessionData)
	if !ok || sess.User == nil {
		return sessionData{}, false
	}
	return sess, true
}

// UserFromContext returns the authenticated user stored in the request context.
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

func (m *Manager) getSessionFromUserName(username string) (sessionData, bool) {
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

// UserHasActiveSessionFromIP reports whether the user has an active session from the given IP.
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

// ConsumeRDPConnectGrant reports whether username has an unexpired RDP connect
// grant for vmName from clientIP — i.e. the user clicked "Connect" for that VM
// from that address within the last rdpConnectWindow — and, on a match, removes
// the grant so it authorizes exactly one RDP connection. This is the gate the RDP
// front handler uses: it narrows authorization from "any active dashboard session
// on this IP" to "one explicit, recent Connect action for this specific VM".
//
// Single-use: a reconnect (or any second TCP connection) needs a fresh Connect
// click. Consumption happens at authorization time, so even a connection that
// later fails (e.g. the backend is unreachable) spends the grant.
//
// Consumption is best-effort under concurrency: the store commits each session
// under its own lock, but the check-and-delete is not globally atomic, so two
// simultaneous connections could in a rare race both be admitted. The VM's own
// RDP login still applies in every case.
func (m *Manager) ConsumeRDPConnectGrant(username, clientIP, vmName string) bool {
	username = strings.TrimSpace(username)
	vmName = strings.TrimSpace(vmName)
	if username == "" || vmName == "" {
		return false
	}

	canonicalIP, ok := CanonicalClientIP(clientIP)
	if !ok {
		return false
	}

	store, ok := m.Store.(scs.IterableStore)
	if !ok {
		return false
	}
	sessions, err := store.All()
	if err != nil {
		return false
	}

	now := time.Now()
	for token, raw := range sessions {
		if m.consumeStoredGrant(token, raw, username, canonicalIP, vmName, now) {
			return true
		}
	}
	return false
}

// consumeStoredGrant removes and persists an unexpired RDP connect grant for
// (username, canonicalIP, vmName) held by the stored session at token, returning
// true when it consumed one. It is the per-session step of ConsumeRDPConnectGrant.
func (m *Manager) consumeStoredGrant(token string, raw []byte, username, canonicalIP, vmName string, now time.Time) bool {
	deadline, values, err := m.Codec.Decode(raw)
	if err != nil {
		return false
	}
	sess, ok := values[sessionKey].(sessionData)
	if !ok || sess.User == nil {
		return false
	}
	if sess.User.GetName() != username || sess.ClientIP != canonicalIP {
		return false
	}
	expiry, ok := sess.RDPConnectGrants[vmName]
	if !ok || !now.Before(expiry) {
		return false
	}

	// Consume the grant: drop it and persist, so it authorizes one connection.
	delete(sess.RDPConnectGrants, vmName)
	values[sessionKey] = sess
	if encoded, encErr := m.Codec.Encode(deadline, values); encErr == nil {
		_ = m.Store.Commit(token, encoded, deadline)
	}
	return true
}

// allSessions decodes every stored (non-expired) session. It is a read-only
// enumeration: sessions are trusted for their lifetime, so it performs no
// credential revalidation and never contacts the identity source.
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

// DestroySession removes the current browser session and expires its cookie in
// the response handled by LoadAndSave.
func (m *Manager) DestroySession(ctx context.Context) error {
	return m.Destroy(ctx)
}

// DestroyAllSessionsForUser removes every active browser session belonging to
// username from the backing store. The current request should still call
// DestroySession so LoadAndSave expires that browser's cookie.
func (m *Manager) DestroyAllSessionsForUser(username string) error {
	username = strings.TrimSpace(username)
	if username == "" {
		return nil
	}

	store, ok := m.Store.(scs.IterableStore)
	if !ok {
		return errors.New("session store does not support iteration")
	}
	sessions, err := store.All()
	if err != nil {
		return err
	}

	var firstErr error
	for token, raw := range sessions {
		_, values, err := m.Codec.Decode(raw)
		if err != nil {
			continue
		}
		sess, ok := values[sessionKey].(sessionData)
		if !ok || sess.User == nil || sess.User.GetName() != username {
			continue
		}
		if err := m.Store.Delete(token); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RegisterUserConnection records a live, long-running connection for username
// and returns an idempotent unregister function. closeFn is called by
// CloseUserConnections when the user logs out everywhere.
func (m *Manager) RegisterUserConnection(username string, closeFn func()) func() {
	username = strings.TrimSpace(username)
	if username == "" || closeFn == nil {
		return func() {}
	}

	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()

	if m.userConnections == nil {
		m.userConnections = make(map[string]map[uint64]func())
	}
	m.nextConnectionID++
	id := m.nextConnectionID
	if m.userConnections[username] == nil {
		m.userConnections[username] = make(map[uint64]func())
	}
	m.userConnections[username][id] = closeFn

	var unregisterOnce sync.Once
	return func() {
		unregisterOnce.Do(func() {
			m.connectionsMu.Lock()
			defer m.connectionsMu.Unlock()

			connections := m.userConnections[username]
			delete(connections, id)
			if len(connections) == 0 {
				delete(m.userConnections, username)
			}
		})
	}
}

// CloseUserConnections closes and unregisters every tracked live connection for
// username. Close functions are called after releasing the registry lock.
func (m *Manager) CloseUserConnections(username string) int {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0
	}

	m.connectionsMu.Lock()
	connections := m.userConnections[username]
	closeFns := make([]func(), 0, len(connections))
	for _, closeFn := range connections {
		closeFns = append(closeFns, closeFn)
	}
	delete(m.userConnections, username)
	m.connectionsMu.Unlock()

	for _, closeFn := range closeFns {
		closeFn()
	}
	return len(closeFns)
}

// EnforceClientIP is router middleware that destroys an authenticated session
// whose bound client IP no longer matches the request's source address. The IP
// is bound once at login (see CreateSession); when a user roams to a new network
// and gets a new address, the next request from that address clears the session,
// so downstream handlers see no authenticated user — SessionMiddleware redirects
// the dashboard to /login and the WebSocket handlers reject the connection. The
// forced re-login re-binds ClientIP to the new address, which is also what makes
// a freshly downloaded .rdp file usable: ConsumeRDPConnectGrant requires the RDP
// connection's IP to match the session's bound IP.
//
// This must run after LoadAndSave so the session is loaded into the request
// context (and so Destroy's cookie expiry is committed on the response).
func (m *Manager) EnforceClientIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sess, ok := m.Get(r.Context(), sessionKey).(sessionData)
		if ok && sess.User != nil {
			canonicalIP, ipOK := CanonicalClientIP(r.RemoteAddr)
			if !ipOK || canonicalIP != sess.ClientIP {
				log.Printf("session client IP changed for user %q (bound=%q now=%q): forcing re-login",
					sess.User.GetName(), sess.ClientIP, canonicalIP)
				if err := m.Destroy(r.Context()); err != nil {
					log.Printf("destroy roamed session for user %q failed: %v", sess.User.GetName(), err)
				}
			}
		}
		next.ServeHTTP(w, r)
	})
}

type sessionContextKey struct{}

// SessionMiddleware enforces an authenticated session for Huma handlers.
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
