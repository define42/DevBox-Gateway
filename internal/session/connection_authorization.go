package session

import (
	"context"
	"time"
)

// ConnectionAuthorization carries an authenticated session's permission through
// connection setup. RegisterUserConnection rejects it after that user's logout.
// Its zero value does not authorize a connection.
type ConnectionAuthorization struct {
	manager    *Manager
	username   string
	generation uint64
	deadline   time.Time
}

// Username returns the authenticated owner of this connection authorization.
func (a ConnectionAuthorization) Username() string {
	return a.username
}

// connectionAuthorization snapshots revocation before authentication. Callers
// must validate a stored session or consume its grant before returning the ticket.
func (m *Manager) connectionAuthorization(username string) ConnectionAuthorization {
	m.connectionsMu.Lock()
	generation := m.connectionGenerations[username]
	m.connectionsMu.Unlock()
	return ConnectionAuthorization{
		manager:    m,
		username:   username,
		generation: generation,
		deadline:   time.Now().Add(sessionTTL),
	}
}

// AuthorizeConnection validates an HTTP session before backend setup. The
// request-local SCS snapshot may predate logout, so authenticate against the
// current store after capturing the user's revocation generation.
func (m *Manager) AuthorizeConnection(ctx context.Context) (ConnectionAuthorization, bool) {
	user, ok := m.UserFromContext(ctx)
	if !ok {
		return ConnectionAuthorization{}, false
	}
	authorization := m.connectionAuthorization(user.Name)

	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	raw, found, err := m.Store.Find(m.Token(ctx))
	if err != nil || !found {
		return ConnectionAuthorization{}, false
	}
	deadline, values, err := m.Codec.Decode(raw)
	if err != nil || !time.Now().Before(deadline) {
		return ConnectionAuthorization{}, false
	}
	sess, ok := values[sessionKey].(sessionData)
	if !ok || sess.User == nil || sess.User.Name != user.Name {
		return ConnectionAuthorization{}, false
	}
	authorization.deadline = deadline
	return authorization, true
}
