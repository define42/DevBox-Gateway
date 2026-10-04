package host

import (
	"errors"
	"fmt"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/internal/config"
)

// Readiness reports stream-monitor health and unpublished audit gaps without
// performing I/O. It includes stalled expectation refreshes so a blocked
// hypervisor query cannot leave collection readiness green indefinitely.
func (s *Server) Readiness() error {
	select {
	case <-s.servingDone:
		if s.servingErr != nil {
			return fmt.Errorf("collector stopped accepting: %w", s.servingErr)
		}
		return errors.New("collector stopped accepting")
	default:
	}
	return errors.Join(s.monitor.readiness(s.now()), s.dedup.readiness())
}

// ServingDone closes as soon as the accept loop stops, before potentially slow
// session, inventory callback, or output cleanup. Run still waits for cleanup.
func (s *Server) ServingDone() <-chan struct{} { return s.servingDone }

// ServingErr returns the accept-loop error after ServingDone closes, or nil
// while serving or after an orderly stop. It does not wait for cleanup.
func (s *Server) ServingErr() error {
	select {
	case <-s.servingDone:
		return s.servingErr
	default:
		return nil
	}
}

func (m *monitor) readiness(now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.enabled {
		return nil
	}
	if m.expected != nil {
		if m.refreshErr != nil {
			return fmt.Errorf("refresh expected agents: %w", m.refreshErr)
		}
		if m.lastRefresh.IsZero() || now.Sub(m.lastRefresh) > 3*m.interval {
			return errors.New("expected agent inventory is stale")
		}
	}
	if m.overflow {
		return errors.New("stream alert backlog overflowed; operator recovery required")
	}
	if len(m.pending) != 0 {
		return fmt.Errorf("%d stream alerts await output acceptance", len(m.pending))
	}
	missing := 0
	for _, h := range m.vms {
		if now.Sub(h.lastSeen) > m.allowedSilence(h) {
			missing++
		}
	}
	if missing > 0 {
		return fmt.Errorf("%d expected agents are silent", missing)
	}
	return nil
}

// refresh leaves previous expectations intact on error. A successful empty
// snapshot means no managed guests are running; it is not an inventory failure.
func (m *monitor) refresh(now time.Time) {
	if m.expected == nil {
		return
	}
	vms, err := m.expected()
	if err == nil {
		err = validateExpectedVMs(vms)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastRefresh = m.now()
	if err != nil {
		if m.refreshErr == nil {
			m.log.Error("refresh expected audit streams failed", "error", err)
		}
		m.refreshErr = err
		return
	}
	m.refreshErr = nil
	next := make(map[uint32]*vmHealth, len(vms))
	for _, vm := range vms {
		h := m.newVMHealth(vm, now)
		if previous := m.vms[vm.CID]; previous != nil && previous.mapping.Name == vm.Name && previous.mapping.UUID == vm.UUID {
			h.lastSeen, h.observed, h.lost = previous.lastSeen, previous.observed, previous.lost
		}
		next[vm.CID] = h
	}
	m.vms = next
}

func validateExpectedVMs(vms []config.VMMapping) error {
	seen := make(map[uint32]bool, len(vms))
	for _, vm := range vms {
		if vm.CID < 3 || vm.CID == config.VMADDR_CID_ANY || vm.Name == "" {
			return errors.New("expected agent inventory contains an invalid VM mapping")
		}
		if seen[vm.CID] {
			return errors.New("expected agent inventory contains duplicate CIDs")
		}
		seen[vm.CID] = true
	}
	return nil
}
