package session

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/define42/devbox-gateway/internal/identity"
)

// rdpConnectGrant persists only the verifier of an opaque, single-use token.
// It is scoped to its owning session and the VM key in RDPConnectGrants.
type rdpConnectGrant struct {
	Verifier  [sha256.Size]byte
	ExpiresAt time.Time
}

// rdpTokenReference binds the direct lookup to the issuing session's identity.
// It is never sufficient for authorization without reloading the stored grant.
type rdpTokenReference struct {
	sessionToken string
	vmName       string
	user         identity.User
	clientIP     string
	createdAt    time.Time
	expiresAt    time.Time
}

// GrantRDPConnect returns a fresh, random token for one RDP connection to vmName.
// It expires after two minutes (or earlier when the browser session expires).
// A new grant supersedes an earlier token for this session and VM. The grant is
// committed before returning and the HTTP snapshot is deliberately untouched,
// so a pending response cannot restore a consumed token or a logged-out session.
func (m *Manager) GrantRDPConnect(ctx context.Context, vmName string) (string, error) {
	vmName = strings.TrimSpace(vmName)
	if vmName == "" {
		return "", errors.New("vm name is required")
	}
	caller, ok := m.Get(ctx, sessionKey).(sessionData)
	if !ok || caller.User == nil {
		return "", errors.New("no authenticated session")
	}
	sessionToken := m.Token(ctx)
	if sessionToken == "" {
		return "", errors.New("no persisted session")
	}
	return m.grantStoredRDPConnect(sessionToken, caller, vmName)
}

func (m *Manager) grantStoredRDPConnect(sessionToken string, caller sessionData, vmName string) (string, error) {
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	raw, found, err := m.Store.Find(sessionToken)
	if err != nil {
		return "", fmt.Errorf("load session for RDP grant: %w", err)
	}
	if !found {
		return "", errors.New("session is no longer active")
	}
	deadline, values, err := m.Codec.Decode(raw)
	if err != nil {
		return "", fmt.Errorf("decode session for RDP grant: %w", err)
	}
	now := time.Now()
	if !now.Before(deadline) {
		return "", errors.New("session has expired")
	}
	sess, ok := values[sessionKey].(sessionData)
	if !ok || !sameRDPSession(sess, *caller.User, caller.ClientIP, caller.CreatedAt) {
		return "", errors.New("authenticated session has changed")
	}
	if _, validIP := CanonicalClientIP(sess.ClientIP); !validIP {
		return "", errors.New("session client IP is invalid")
	}

	token, grant, err := m.newRDPConnectGrant(now, deadline)
	if err != nil {
		return "", err
	}
	grants := make(map[string]rdpConnectGrant, len(sess.RDPConnectGrants)+1)
	for name, existing := range sess.RDPConnectGrants {
		if now.Before(existing.ExpiresAt) {
			grants[name] = existing
		}
	}
	grants[vmName] = grant
	sess.RDPConnectGrants = grants
	values[sessionKey] = sess
	encoded, err := m.Codec.Encode(deadline, values)
	if err != nil {
		return "", fmt.Errorf("encode RDP grant: %w", err)
	}
	if err := m.Store.Commit(sessionToken, encoded, deadline); err != nil {
		return "", fmt.Errorf("persist RDP grant: %w", err)
	}
	m.indexRDPConnectGrant(sessionToken, sess, vmName, grant, now)
	return token, nil
}

// newRDPConnectGrant is called with sessionsMu held to check the index for a
// collision before persisting. crypto/rand supplies 128 bits of token entropy.
func (m *Manager) newRDPConnectGrant(now, deadline time.Time) (string, rdpConnectGrant, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", rdpConnectGrant{}, fmt.Errorf("generate RDP token: %w", err)
	}
	token := hex.EncodeToString(random[:])
	verifier := sha256.Sum256([]byte(token))
	if _, exists := m.rdpTokens[verifier]; exists {
		return "", rdpConnectGrant{}, errors.New("RDP token collision")
	}
	expiresAt := now.Add(rdpConnectWindow)
	if deadline.Before(expiresAt) {
		expiresAt = deadline
	}
	return token, rdpConnectGrant{Verifier: verifier, ExpiresAt: expiresAt}, nil
}

func (m *Manager) indexRDPConnectGrant(sessionToken string, sess sessionData, vmName string, grant rdpConnectGrant, now time.Time) {
	if m.rdpTokens == nil {
		m.rdpTokens = make(map[[sha256.Size]byte]rdpTokenReference)
	}
	for verifier, ref := range m.rdpTokens {
		if !now.Before(ref.expiresAt) || (ref.sessionToken == sessionToken && ref.vmName == vmName) {
			delete(m.rdpTokens, verifier)
		}
	}
	m.rdpTokens[grant.Verifier] = rdpTokenReference{
		sessionToken: sessionToken,
		vmName:       vmName,
		user:         *sess.User,
		clientIP:     sess.ClientIP,
		createdAt:    sess.CreatedAt,
		expiresAt:    grant.ExpiresAt,
	}
}

// RDPConnectTarget resolves a still-valid token without consuming it. TLS and
// the live VM owner check must complete before AuthorizeRDPConnection spends it.
func (m *Manager) RDPConnectTarget(token, clientIP string) (string, bool) {
	verifier, canonicalIP, ok := rdpTokenLookup(token, clientIP)
	if !ok {
		return "", false
	}
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()
	ref, _, _, ok := m.loadRDPConnectGrant(verifier, canonicalIP)
	return ref.vmName, ok
}

// ConsumeRDPConnectGrant consumes the exact token only when its session, owner,
// client IP and VM still match. A reconnect requires a fresh downloaded file.
func (m *Manager) ConsumeRDPConnectGrant(token, username, clientIP, vmName string) bool {
	_, ok := m.AuthorizeRDPConnection(token, username, clientIP, vmName)
	return ok
}

// AuthorizeRDPConnection atomically revalidates and consumes the supplied token,
// returning the ticket required to register its resulting connection. The caller
// must have completed TLS and checked current VM ownership. Backend setup
// failure still spends the token; its expiry never limits an established session.
func (m *Manager) AuthorizeRDPConnection(token, username, clientIP, vmName string) (ConnectionAuthorization, bool) {
	username = strings.TrimSpace(username)
	vmName = strings.TrimSpace(vmName)
	verifier, canonicalIP, ok := rdpTokenLookup(token, clientIP)
	if !ok || username == "" || vmName == "" {
		return ConnectionAuthorization{}, false
	}
	// Capture before any store validation: a logout during validation or backend
	// setup must invalidate the ticket even if consumption finishes successfully.
	authorization := m.connectionAuthorization(username)
	m.sessionsMu.Lock()
	defer m.sessionsMu.Unlock()

	ref, deadline, values, ok := m.loadRDPConnectGrant(verifier, canonicalIP)
	if !ok || ref.user.Name != username || ref.vmName != vmName {
		return ConnectionAuthorization{}, false
	}
	sess := values[sessionKey].(sessionData)
	delete(sess.RDPConnectGrants, vmName)
	values[sessionKey] = sess
	encoded, err := m.Codec.Encode(deadline, values)
	if err != nil || m.Store.Commit(ref.sessionToken, encoded, deadline) != nil {
		return ConnectionAuthorization{}, false
	}
	delete(m.rdpTokens, verifier)
	authorization.deadline = deadline
	return authorization, true
}

func rdpTokenLookup(token, clientIP string) ([sha256.Size]byte, string, bool) {
	if len(token) != 32 {
		return [sha256.Size]byte{}, "", false
	}
	for _, c := range token {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return [sha256.Size]byte{}, "", false
		}
	}
	canonicalIP, ok := CanonicalClientIP(clientIP)
	return sha256.Sum256([]byte(token)), canonicalIP, ok
}

// loadRDPConnectGrant must hold sessionsMu. The in-memory index never restores
// itself from stored grants, so restart and stale HTTP snapshot saves cannot
// reactivate old tokens. Store errors fail closed while allowing a later retry.
func (m *Manager) loadRDPConnectGrant(verifier [sha256.Size]byte, canonicalIP string) (
	rdpTokenReference, time.Time, map[string]interface{}, bool,
) {
	ref, exists := m.rdpTokens[verifier]
	if !exists {
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	now := time.Now()
	if !now.Before(ref.expiresAt) {
		delete(m.rdpTokens, verifier)
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	if ref.clientIP != canonicalIP {
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	raw, found, err := m.Store.Find(ref.sessionToken)
	if err != nil {
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	if !found {
		m.removeSessionRDPTokenIndex(ref.sessionToken)
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	deadline, values, err := m.Codec.Decode(raw)
	if err != nil {
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	// A slow store read or decode must not preserve a token that expired while
	// validation was in progress.
	now = time.Now()
	if !now.Before(deadline) {
		m.removeSessionRDPTokenIndex(ref.sessionToken)
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	if !now.Before(ref.expiresAt) {
		delete(m.rdpTokens, verifier)
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	sess, ok := values[sessionKey].(sessionData)
	if !ok || !sameRDPSession(sess, ref.user, canonicalIP, ref.createdAt) {
		m.removeSessionRDPTokenIndex(ref.sessionToken)
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	grant, exists := sess.RDPConnectGrants[ref.vmName]
	if !exists || !now.Before(grant.ExpiresAt) || subtle.ConstantTimeCompare(grant.Verifier[:], verifier[:]) != 1 {
		delete(m.rdpTokens, verifier)
		return rdpTokenReference{}, time.Time{}, nil, false
	}
	return ref, deadline, values, true
}

// removeSessionRDPTokenIndex is called under sessionsMu after revocation.
func (m *Manager) removeSessionRDPTokenIndex(sessionToken string) {
	for verifier, ref := range m.rdpTokens {
		if ref.sessionToken == sessionToken {
			delete(m.rdpTokens, verifier)
		}
	}
}

func sameRDPSession(sess sessionData, user identity.User, clientIP string, createdAt time.Time) bool {
	return sess.User != nil && *sess.User == user && sess.ClientIP == clientIP && sess.CreatedAt.Equal(createdAt)
}
