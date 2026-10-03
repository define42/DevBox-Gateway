package session

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/alexedwards/scs/v2"
	"github.com/define42/devbox-gateway/internal/identity"
)

func grantCookieRDPToken(t *testing.T, m *Manager, cookie *http.Cookie, vmName string) string {
	t.Helper()
	ctx, err := m.Load(t.Context(), cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	token, err := m.GrantRDPConnect(ctx, vmName)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func updateStoredRDPGrant(t *testing.T, m *Manager, sessionToken, vmName string, update func(*rdpConnectGrant)) {
	t.Helper()
	deadline, values := storedSessionValues(t, m, sessionToken)
	sess := values[sessionKey].(sessionData)
	grant := sess.RDPConnectGrants[vmName]
	update(&grant)
	sess.RDPConnectGrants[vmName] = grant
	values[sessionKey] = sess
	encoded, err := m.Codec.Encode(deadline, values)
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Store.Commit(sessionToken, encoded, deadline); err != nil {
		t.Fatal(err)
	}
}

func TestRDPTokenRandomFormatStoredVerifierAndSupersession(t *testing.T) {
	m := New()
	cookie := issueSession(t, m, &identity.User{Name: "alice"}, testSessionRemoteAddr)
	tokens := make(map[string]struct{})
	var previous string
	for range 16 {
		token := grantCookieRDPToken(t, m, cookie, "vm1")
		if _, found := tokens[token]; found {
			t.Fatal("fresh token repeated")
		}
		tokens[token] = struct{}{}
		if previous != "" {
			if _, ok := m.RDPConnectTarget(previous, "192.0.2.10"); ok {
				t.Fatal("superseded token routed")
			}
			if m.ConsumeRDPConnectGrant(previous, "alice", "192.0.2.10", "vm1") {
				t.Fatal("superseded token authorized")
			}
		}
		assertStoredRDPToken(t, m, cookie.Value, token)
		if len(m.rdpTokens) != 1 {
			t.Fatal("superseded index entry retained")
		}
		previous = token
	}
	if !m.ConsumeRDPConnectGrant(previous, "alice", "192.0.2.10", "vm1") {
		t.Fatal("latest token was consumed by old-token attempt")
	}
}

func assertStoredRDPToken(t *testing.T, m *Manager, sessionToken, token string) {
	t.Helper()
	if len(token) != 32 || token != strings.ToLower(token) {
		t.Fatal("token must contain exactly 32 lowercase hex characters")
	}
	if _, err := hex.DecodeString(token); err != nil {
		t.Fatal(err)
	}
	raw, found, err := m.Store.Find(sessionToken)
	if err != nil || !found {
		t.Fatal("session missing")
	}
	if bytes.Contains(raw, []byte(token)) {
		t.Fatal("raw token persisted")
	}
	_, values := storedSessionValues(t, m, sessionToken)
	grant := values[sessionKey].(sessionData).RDPConnectGrants["vm1"]
	if grant.Verifier != sha256.Sum256([]byte(token)) {
		t.Fatal("incorrect token verifier")
	}
	if until := time.Until(grant.ExpiresAt); until <= 0 || until > 2*time.Minute {
		t.Fatalf("wrong grant expiry: %v", until)
	}
}

func TestRDPTokenRoutingDoesNotConsumeAndRejectsInvalidInput(t *testing.T) {
	m := New()
	grant := commitTestRDPGrant(t, m, "alice")
	for _, token := range []string{"", "x", strings.Repeat("a", 31), strings.Repeat("f", 33), strings.Repeat("A", 32), strings.Repeat("g", 32), strings.Repeat("0", 32)} {
		if _, ok := m.RDPConnectTarget(token, "192.0.2.10"); ok {
			t.Fatal("invalid token routed")
		}
		if m.ConsumeRDPConnectGrant(token, "alice", "192.0.2.10", "alice.desktop") {
			t.Fatal("invalid token authorized")
		}
	}
	for _, ip := range []string{"", "invalid", "192.0.2.11"} {
		if _, ok := m.RDPConnectTarget(grant.token, ip); ok {
			t.Fatal("invalid clientIP routed")
		}
	}
	for range 2 {
		vm, ok := m.RDPConnectTarget(grant.token, "[::ffff:192.0.2.10]:3389")
		if !ok || vm != "alice.desktop" {
			t.Fatal("valid repeated lookup failed")
		}
	}
	if !m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("lookup consumed token")
	}
	if _, ok := m.RDPConnectTarget(grant.token, "192.0.2.10"); ok {
		t.Fatal("consumed token still routed")
	}
}

func TestRDPTokenIndependentBrowserSessionsAndVMs(t *testing.T) {
	m := New()
	first := issueSession(t, m, &identity.User{Name: "alice"}, testSessionRemoteAddr)
	second := issueSession(t, m, &identity.User{Name: "alice"}, testSessionRemoteAddr)
	firstToken := grantCookieRDPToken(t, m, first, "vm1")
	secondToken := grantCookieRDPToken(t, m, second, "vm1")
	otherVM := grantCookieRDPToken(t, m, first, "vm2")
	replacement := grantCookieRDPToken(t, m, first, "vm1")
	if m.ConsumeRDPConnectGrant(firstToken, "alice", "192.0.2.10", "vm1") {
		t.Fatal("old token authorized a new Connect grant")
	}
	if !m.ConsumeRDPConnectGrant(secondToken, "alice", "192.0.2.10", "vm1") {
		t.Fatal("new Connect invalidated another browser token")
	}
	if !m.ConsumeRDPConnectGrant(otherVM, "alice", "192.0.2.10", "vm2") {
		t.Fatal("new Connect invalidated another VM token")
	}
	if !m.ConsumeRDPConnectGrant(replacement, "alice", "192.0.2.10", "vm1") {
		t.Fatal("replacement token unavailable")
	}
}

func TestRDPTokenExpiresAtSessionDeadline(t *testing.T) {
	m := New()
	synctest.Test(t, func(t *testing.T) {
		defer m.sessionExpiryStore.Close()
		m.Lifetime = 30 * time.Second
		cookie := issueSession(t, m, &identity.User{Name: "alice"}, testSessionRemoteAddr)
		token := grantCookieRDPToken(t, m, cookie, "vm1")
		deadline, values := storedSessionValues(t, m, cookie.Value)
		if !values[sessionKey].(sessionData).RDPConnectGrants["vm1"].ExpiresAt.Equal(deadline) {
			t.Fatal("token outlives session")
		}
		time.Sleep(30 * time.Second)
		if _, ok := m.RDPConnectTarget(token, "192.0.2.10"); ok {
			t.Fatal("expired session token routed")
		}
		if m.ConsumeRDPConnectGrant(token, "alice", "192.0.2.10", "vm1") {
			t.Fatal("expired session token authorized")
		}
	})
}

func TestRDPTokenExpiresAfterTwoMinutes(t *testing.T) {
	m := New()
	synctest.Test(t, func(t *testing.T) {
		defer m.sessionExpiryStore.Close()
		grant := commitTestRDPGrant(t, m, "alice")
		time.Sleep(2 * time.Minute)
		if _, ok := m.RDPConnectTarget(grant.token, "192.0.2.10"); ok {
			t.Fatal("token routed at expiry boundary")
		}
		if m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
			t.Fatal("expired token authorized")
		}
		if len(m.rdpTokens) != 0 {
			t.Fatal("expired lookup index retained")
		}
	})
}

func TestRDPTokenRestartCannotReactivateStoredGrant(t *testing.T) {
	original := New()
	grant := commitTestRDPGrant(t, original, "alice")
	restarted := New()
	restarted.Store = original.Store
	if _, ok := restarted.RDPConnectTarget(grant.token, "192.0.2.10"); ok {
		t.Fatal("restart restored token")
	}
	if restarted.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("restart authorized token")
	}
}

func TestRDPTokenStaleSessionSnapshotCannotRestoreConsumedOrSupersededToken(t *testing.T) {
	for _, consume := range []bool{false, true} {
		checkRDPTokenStaleSnapshot(t, consume)
	}
}

func checkRDPTokenStaleSnapshot(t *testing.T, consume bool) {
	t.Helper()
	m := New()
	grant := commitTestRDPGrant(t, m, "alice")
	raw, found, err := m.Store.Find(grant.sessionToken)
	if err != nil || !found {
		t.Fatal("missing initial session")
	}
	invalidateTestRDPToken(t, m, grant, consume)
	if err := m.Store.Commit(grant.sessionToken, raw, time.Now().Add(sessionTTL)); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.RDPConnectTarget(grant.token, "192.0.2.10"); ok {
		t.Fatal("stale snapshot restored token routing")
	}
	if m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("stale snapshot restored authorization")
	}
}

func invalidateTestRDPToken(t *testing.T, m *Manager, grant testRDPGrant, consume bool) {
	t.Helper()
	if consume {
		if !m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
			t.Fatal("consume failed")
		}
		return
	}
	ctx, err := m.Load(t.Context(), grant.sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.GrantRDPConnect(ctx, "alice.desktop"); err != nil {
		t.Fatal(err)
	}
}

type rdpFindErrorStore struct{ scs.Store }

func (rdpFindErrorStore) Find(string) ([]byte, bool, error) {
	return nil, false, errors.New("store unavailable")
}

func TestRDPTokenFindFailureRetainsTokenForRetry(t *testing.T) {
	m := New()
	grant := commitTestRDPGrant(t, m, "alice")
	store := m.Store
	m.Store = rdpFindErrorStore{Store: store}
	if _, ok := m.RDPConnectTarget(grant.token, "192.0.2.10"); ok {
		t.Fatal("store failure routed")
	}
	if m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("store failure authorized")
	}
	m.Store = store
	if !m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("store failure lost token")
	}
}

type rdpDelayedFindStore struct {
	scs.Store

	delay time.Duration
}

func (s rdpDelayedFindStore) Find(token string) ([]byte, bool, error) {
	data, found, err := s.Store.Find(token)
	time.Sleep(s.delay)
	return data, found, err
}

func TestRDPTokenExpiresDuringStoreReadPreservesOtherVMGrant(t *testing.T) {
	m := New()
	synctest.Test(t, func(t *testing.T) {
		defer m.sessionExpiryStore.Close()
		cookie := issueSession(t, m, &identity.User{Name: "alice"}, testSessionRemoteAddr)
		first := grantCookieRDPToken(t, m, cookie, "vm1")
		time.Sleep(time.Minute)
		second := grantCookieRDPToken(t, m, cookie, "vm2")
		store := m.Store
		m.Store = rdpDelayedFindStore{Store: store, delay: time.Minute}
		if m.ConsumeRDPConnectGrant(first, "alice", "192.0.2.10", "vm1") {
			t.Fatal("token expired during validation but authorized")
		}
		m.Store = store
		if !m.ConsumeRDPConnectGrant(second, "alice", "192.0.2.10", "vm2") {
			t.Fatal("expired token invalidated newer VM token")
		}
	})
}

func TestRDPTokenRejectsChangedIssuingSession(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*sessionData)
	}{
		{"owner", func(sess *sessionData) { sess.User.Name = "bob" }},
		{"privileges", func(sess *sessionData) { sess.User.IsAdmin = true }},
		{"IP", func(sess *sessionData) { sess.ClientIP = "192.0.2.11" }},
		{"login", func(sess *sessionData) { sess.CreatedAt = sess.CreatedAt.Add(time.Second) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := New()
			grant := commitTestRDPGrant(t, m, "alice")
			deadline, values := storedSessionValues(t, m, grant.sessionToken)
			sess := values[sessionKey].(sessionData)
			tc.mutate(&sess)
			values[sessionKey] = sess
			encoded, err := m.Codec.Encode(deadline, values)
			if err != nil {
				t.Fatal(err)
			}
			if err := m.Store.Commit(grant.sessionToken, encoded, deadline); err != nil {
				t.Fatal(err)
			}
			if _, ok := m.RDPConnectTarget(grant.token, "192.0.2.10"); ok {
				t.Fatal("changed session routed old token")
			}
			if m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
				t.Fatal("changed session authorized old token")
			}
		})
	}
}

func TestRDPTokenFailedSupersessionPreservesOriginalGrant(t *testing.T) {
	m := New()
	grant := commitTestRDPGrant(t, m, "alice")
	ctx, err := m.Load(t.Context(), grant.sessionToken)
	if err != nil {
		t.Fatal(err)
	}
	store := m.Store
	m.Store = grantCommitFailingStore{Store: store, IterableStore: store.(scs.IterableStore)}
	token, err := m.GrantRDPConnect(ctx, "alice.desktop")
	if err == nil || token != "" {
		t.Fatal("failed persistence returned a usable token")
	}
	m.Store = store
	if !m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("failed replacement invalidated original token")
	}
}

type rdpNonIterableStore struct{ scs.Store }

func TestRDPTokenLookupDoesNotEnumerateSessions(t *testing.T) {
	m := New()
	grant := commitTestRDPGrant(t, m, "alice")
	m.Store = rdpNonIterableStore{Store: m.Store}
	if vm, ok := m.RDPConnectTarget(grant.token, "192.0.2.10"); !ok || vm != "alice.desktop" {
		t.Fatal("direct token lookup required session enumeration")
	}
	if !m.ConsumeRDPConnectGrant(grant.token, "alice", "192.0.2.10", "alice.desktop") {
		t.Fatal("token consumption required session enumeration")
	}
}
