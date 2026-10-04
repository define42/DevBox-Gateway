package host

import (
	"errors"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/output"
	"github.com/define42/devbox-gateway/SauronAgent/internal/protocol"
)

// requireResolvedIdentity asks an incompletely attributed session to reconnect
// once fresh inventory can identify its CID. Source remains pinned throughout
// a session: updating it in place could relabel an old connection after CID reuse.
// The caller must return the error before acknowledging or writing this frame;
// the agent reconnects and replays any event that has not been acknowledged.
func (s *session) requireResolvedIdentity() error {
	if !s.srv.monitor.identityAvailable(s.peer, s.src, s.srv.now()) {
		return nil
	}
	const reason = "trusted VM identity is now available; reconnect to refresh attribution"
	// Fatal ends this connection, not the agent. Its sender retries host errors
	// with backoff. A bounded best-effort notification is enough: EOF also
	// causes a reconnect if the error frame cannot reach the guest.
	_ = s.conn.Send(protocol.MsgError, 0, &protocol.ErrorMessage{
		Code: protocol.ErrCodeInternal, Message: reason, Fatal: true,
	}, s.writeTimeout)
	return errors.New(reason)
}

func (m *monitor) identityAvailable(p peer, src output.Source, now time.Time) bool {
	if !m.enabled || m.expected == nil || !p.vsock {
		return false
	}
	if src.Known && src.VM != "" && src.UUID != "" {
		// Fully resolved sessions keep their original identity even if this
		// CID now belongs to a different VM in the current inventory.
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.refreshErr != nil || m.lastRefresh.IsZero() || now.Sub(m.lastRefresh) > 3*m.interval {
		return false
	}
	h := m.vms[p.cid]
	return h != nil && h.mapping.Name != "" && h.mapping.UUID != ""
}
