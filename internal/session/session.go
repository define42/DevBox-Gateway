// Package session manages authenticated browser sessions for the gateway.
package session

import (
	"context"
	"encoding/gob"
	"errors"
	"log"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/define42/devbox-gateway/internal/identity"

	"github.com/alexedwards/scs/v2"
	"github.com/alexedwards/scs/v2/memstore"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
)

type sessionData struct {
	User      *identity.User
	CreatedAt time.Time
	ClientIP  string
	// LoginPasswordHash is the salted sha512_crypt ($6$, /etc/shadow compatible)
	// hash of the password the user logged in with (LDAP or local). It is
	// computed at login and kept only in the in-memory session store so VDI
	// creation can provision the guest account with the user's login password;
	// the cleartext password itself is never retained. The hash format is
	// exactly what cloud-init expects, so the cleartext is never needed again.
	LoginPasswordHash string
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

	// sessionsMu serializes RDP grant updates with session deletion and token
	// renewal. Store methods lock individually, so a read-modify-write needs
	// this additional lock to avoid recreating a token revoked between calls.
	sessionsMu sync.Mutex

	connectionsMu sync.Mutex
	// connectionGenerations changes only on logout, including when no live
	// connection has registered yet. Keep generations across subsequent logins
	// so an older setup attempt can never become valid again.
	connectionGenerations map[string]uint64
	nextConnectionID      uint64
	userConnections       map[string]map[uint64]func()
	connectionsClosing    bool
	activeConnections     int
	connectionsDrained    chan struct{}
	// userConnectionLimit caps concurrently registered connections per user;
	// values <=0 disable the cap. Set once at boot via SetUserConnectionLimit.
	userConnectionLimit int
}

// SetUserConnectionLimit sets how many live connections (dashboard, serial,
// VNC, and RDP) each user may hold at once before
// RegisterUserConnection refuses new ones. Values <=0 disable the cap.
func (m *Manager) SetUserConnectionLimit(limit int) {
	m.connectionsMu.Lock()
	m.userConnectionLimit = limit
	m.connectionsMu.Unlock()
}

// New constructs the gateway session manager.
func New() *Manager {
	registerSessionTypes()
	connectionsDrained := make(chan struct{})
	close(connectionsDrained)
	return &Manager{
		SessionManager:     newSessionManager(),
		userConnections:    make(map[string]map[uint64]func()),
		connectionsDrained: connectionsDrained,
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
// trusted until it expires (see sessionTTL). The cleartext password is not
// retained — loginPasswordHash is its salted sha512_crypt digest, kept in the
// in-memory store so VDI creation can seed the guest account with the user's
// login password (see PasswordHashFromContext).
func (m *Manager) CreateSession(ctx context.Context, u *identity.User, clientIP, loginPasswordHash string) error {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	if err := m.RenewToken(ctx); err != nil {
		return err
	}
	canonicalIP, _ := CanonicalClientIP(clientIP)
	m.Put(ctx, sessionKey, sessionData{
		User:              u,
		CreatedAt:         time.Now(),
		ClientIP:          canonicalIP,
		LoginPasswordHash: loginPasswordHash,
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
func (m *Manager) UserFromContext(ctx context.Context) (*identity.User, bool) {
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

// PasswordHashFromContext returns the salted sha512_crypt hash of the
// authenticated user's login password stored at login time. It never exposes a
// cleartext password — only the /etc/shadow compatible digest that VDI creation
// embeds in the cloud-init seed. ok is false when there is no authenticated
// session or the session predates hash storage (forcing a fresh login).
func (m *Manager) PasswordHashFromContext(ctx context.Context) (string, bool) {
	if ctx == nil {
		return "", false
	}
	if sess, ok := m.Get(ctx, sessionKey).(sessionData); ok && sess.User != nil && sess.LoginPasswordHash != "" {
		return sess.LoginPasswordHash, true
	}
	if sess, ok := ctx.Value(sessionContextKey{}).(sessionData); ok && sess.User != nil && sess.LoginPasswordHash != "" {
		return sess.LoginPasswordHash, true
	}
	return "", false
}

func (m *Manager) getSessionFromUserName(username string) (sessionData, bool) {
	username = strings.TrimSpace(username)
	if username == "" {
		return sessionData{}, false
	}

	for _, sess := range m.allSessions() {
		if sess.User != nil && sess.User.Name == username {
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
		if sess.User.Name == username && sess.ClientIP == canonicalIP {
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
// Candidate tokens are enumerated without holding sessionsMu, then each session
// is reloaded and updated under the same lock used by revocation. An enumeration
// taken before logout can therefore never restore a revoked session, and
// concurrent RDP consumers cannot spend the same stored grant twice.
func (m *Manager) ConsumeRDPConnectGrant(username, clientIP, vmName string) bool {
	_, ok := m.AuthorizeRDPConnection(username, clientIP, vmName)
	return ok
}

// AuthorizeRDPConnection consumes a single-use Connect grant and returns the
// authorization required to register the resulting connection after setup.
func (m *Manager) AuthorizeRDPConnection(username, clientIP, vmName string) (ConnectionAuthorization, bool) {
	username = strings.TrimSpace(username)
	vmName = strings.TrimSpace(vmName)
	if username == "" || vmName == "" {
		return ConnectionAuthorization{}, false
	}

	canonicalIP, ok := CanonicalClientIP(clientIP)
	if !ok {
		return ConnectionAuthorization{}, false
	}
	// Capture before consuming the stored grant: logout during either grant
	// validation or backend setup must make registration reject this ticket.
	authorization := m.connectionAuthorization(username)

	store, ok := m.Store.(scs.IterableStore)
	if !ok {
		return ConnectionAuthorization{}, false
	}
	sessions, err := store.All()
	if err != nil {
		return ConnectionAuthorization{}, false
	}

	for token := range sessions {
		if deadline, consumed := m.consumeStoredGrant(token, username, canonicalIP, vmName); consumed {
			authorization.deadline = deadline
			return authorization, true
		}
	}
	return ConnectionAuthorization{}, false
}

// consumeStoredGrant removes and persists an unexpired RDP connect grant for
// (username, canonicalIP, vmName) held by the stored session at token, returning
// its session deadline when it consumed one.
func (m *Manager) consumeStoredGrant(token, username, canonicalIP, vmName string) (time.Time, bool) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	// All returns a snapshot that may already have been revoked or consumed.
	// Reload under the mutation lock and keep it until the update is committed.
	raw, found, err := m.Store.Find(token)
	if err != nil || !found {
		return time.Time{}, false
	}
	deadline, values, err := m.Codec.Decode(raw)
	if err != nil || !time.Now().Before(deadline) {
		return time.Time{}, false
	}
	sess, ok := values[sessionKey].(sessionData)
	if !ok || sess.User == nil {
		return time.Time{}, false
	}
	if sess.User.Name != username || sess.ClientIP != canonicalIP {
		return time.Time{}, false
	}
	expiry, ok := sess.RDPConnectGrants[vmName]
	if !ok || !time.Now().Before(expiry) {
		return time.Time{}, false
	}

	// Consume the grant: drop it and persist, so it authorizes one connection.
	delete(sess.RDPConnectGrants, vmName)
	values[sessionKey] = sess
	encoded, err := m.Codec.Encode(deadline, values)
	if err != nil {
		return time.Time{}, false
	}
	return deadline, m.Store.Commit(token, encoded, deadline) == nil
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
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

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

	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

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
		if !ok || sess.User == nil || sess.User.Name != username {
			continue
		}
		if err := m.Store.Delete(token); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// RegisterUserConnection records a live, long-running authorized connection
// and returns an idempotent unregister function. closeFn is called by
// CloseUserConnections when the user logs out everywhere and by
// CloseAllConnections during gateway shutdown. When registration is refused,
// ok is false, the returned unregister is a no-op, and the caller must close
// the connection. Refusal happens at the per-user limit and once terminal
// shutdown begins, or when logout revoked the authorization during setup.
func (m *Manager) RegisterUserConnection(authorization ConnectionAuthorization, closeFn func()) (unregister func(), ok bool) {
	username := authorization.username
	if authorization.manager != m || strings.TrimSpace(username) == "" || closeFn == nil {
		return func() {}, false
	}

	m.connectionsMu.Lock()
	defer m.connectionsMu.Unlock()

	if m.connectionsClosing || m.connectionGenerations[username] != authorization.generation ||
		!time.Now().Before(authorization.deadline) {
		return func() {}, false
	}
	if m.userConnectionLimit > 0 && len(m.userConnections[username]) >= m.userConnectionLimit {
		return func() {}, false
	}

	if m.userConnections == nil {
		m.userConnections = make(map[string]map[uint64]func())
	}
	m.nextConnectionID++
	id := m.nextConnectionID
	if m.userConnections[username] == nil {
		m.userConnections[username] = make(map[uint64]func())
	}
	if m.activeConnections == 0 {
		m.connectionsDrained = make(chan struct{})
	}
	m.activeConnections++
	m.userConnections[username][id] = closeFn

	var unregisterOnce sync.Once
	return func() {
		unregisterOnce.Do(func() {
			m.connectionsMu.Lock()
			connections := m.userConnections[username]
			delete(connections, id)
			if len(connections) == 0 {
				delete(m.userConnections, username)
			}
			m.activeConnections--
			if m.activeConnections == 0 {
				close(m.connectionsDrained)
			}
			m.connectionsMu.Unlock()
		})
	}, true
}

// CloseUserConnections invalidates pending authorizations and closes every
// tracked live connection for username. Close functions run after releasing the
// registry lock, and handlers remain responsible for calling unregister.
func (m *Manager) CloseUserConnections(username string) int {
	username = strings.TrimSpace(username)
	if username == "" {
		return 0
	}

	m.connectionsMu.Lock()
	if m.connectionGenerations == nil {
		m.connectionGenerations = make(map[string]uint64)
	}
	m.connectionGenerations[username]++
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

// CloseAllConnections begins the terminal connection drain used during gateway
// shutdown. It atomically refuses future registrations, closes every currently
// registered connection after releasing the registry lock, and waits for their
// handlers to call the idempotent unregister functions returned by
// RegisterUserConnection. The caller bounds the wait with ctx. Explicit user
// logout continues to use the non-blocking CloseUserConnections method.
func (m *Manager) CloseAllConnections(ctx context.Context) (int, error) {
	m.connectionsMu.Lock()
	m.connectionsClosing = true
	closeFns := make([]func(), 0, m.activeConnections)
	for _, connections := range m.userConnections {
		for _, closeFn := range connections {
			closeFns = append(closeFns, closeFn)
		}
	}
	clear(m.userConnections)
	drained := m.connectionsDrained
	if drained == nil {
		drained = make(chan struct{})
		close(drained)
		m.connectionsDrained = drained
	}
	m.connectionsMu.Unlock()

	// A transport close may block (for example, while TLS tries to send a
	// close-notify alert). Dispatch all closes independently so one stalled
	// transport cannot prevent the others from unwinding and so ctx still bounds
	// the overall drain.
	for _, closeFn := range closeFns {
		go closeFn()
	}

	select {
	case <-drained:
		return len(closeFns), nil
	case <-ctx.Done():
		return len(closeFns), ctx.Err()
	}
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
				log.Printf("session client IP changed for user %s (bound=%s now=%s): forcing re-login",
					strconv.Quote(sess.User.Name), strconv.Quote(sess.ClientIP), strconv.Quote(canonicalIP))
				if err := m.DestroySession(r.Context()); err != nil {
					log.Printf("destroy roamed session for user %q failed: %v", sess.User.Name, err)
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
