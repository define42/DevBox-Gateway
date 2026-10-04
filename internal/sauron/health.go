package sauron

import (
	"errors"
	"fmt"
	"time"

	"github.com/define42/devbox-gateway/SauronAgent/collector"
)

// Done closes when the accept loop stops, before session and output cleanup.
// Supervisors should terminate the gateway on an unexpected exit; Close waits
// for cleanup within its timeout.
func (c *Collector) Done() <-chan struct{} { return c.server.ServingDone() }

// Err returns the accept-loop error as soon as Done closes and includes cleanup
// errors once cleanup finishes. It returns nil while running or after a clean
// shutdown and never waits for a blocked inventory callback.
func (c *Collector) Err() error {
	select {
	case <-c.done:
		return c.runErr
	default:
		return c.server.ServingErr()
	}
}

// Readiness reports a stopped collector, stale expectations, overdue agents or
// stream alerts waiting for a successful output write. It performs no I/O.
func (c *Collector) Readiness() error {
	select {
	case <-c.done:
		if c.runErr != nil {
			return fmt.Errorf("collector stopped: %w", c.runErr)
		}
		return errors.New("collector stopped")
	default:
		return errors.Join(c.server.Readiness(), c.output.readiness())
	}
}

func expectedVMs(list func() ([]VM, error)) func() ([]collector.VM, error) {
	if list == nil {
		return nil
	}
	return func() ([]collector.VM, error) {
		vms, err := list()
		if err != nil {
			return nil, err
		}
		mappings := make([]collector.VM, 0, len(vms))
		for _, vm := range vms {
			mappings = append(mappings, collector.VM{
				CID: vm.CID, Name: vm.Name, UUID: vm.UUID, Expected: true,
				Labels: map[string]string{"owner": vm.Owner},
			})
		}
		return mappings, nil
	}
}

func defaultDuration(value, fallback time.Duration) time.Duration {
	if value > 0 {
		return value
	}
	return fallback
}
