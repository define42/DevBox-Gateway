package gateway

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"

	"github.com/define42/devbox-gateway/internal/sauron"
	"github.com/define42/devbox-gateway/internal/virt"
)

type readinessProvider interface {
	Readiness() error
}

type collectorSupervisor interface {
	Done() <-chan struct{}
	Err() error
}

// wait treats mandatory collector termination like loss of the front listener:
// exit nonzero so the service manager can replace the failed process.
func (g *gatewayRuntime) wait(ctx context.Context) int {
	var collectorDone <-chan struct{}
	collector, supervised := g.sauron.(collectorSupervisor)
	if supervised {
		collectorDone = collector.Done()
	}
	select {
	case <-ctx.Done():
		return 0
	case <-g.done:
		if ctx.Err() != nil {
			return 0
		}
		log.Printf("gateway stopped serving: %v", g.serveErr)
	case <-collectorDone:
		if ctx.Err() != nil {
			return 0
		}
		log.Printf("mandatory sauron collector stopped; exiting for service recovery: %v", collector.Err())
	}
	return 1
}

func (g *gatewayRuntime) readiness() error {
	var failures []error
	for _, component := range []struct {
		name  string
		value any
	}{
		{name: "application audit", value: g.auditSink},
		{name: "guest audit collector", value: g.sauron},
	} {
		provider, ok := component.value.(readinessProvider)
		if !ok {
			failures = append(failures, fmt.Errorf("%s readiness unavailable", component.name))
			continue
		}
		if err := provider.Readiness(); err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", component.name, err))
		}
	}
	return errors.Join(failures...)
}

func readinessHandler(check func() error) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Connection", "close")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		status, body := http.StatusOK, "ready\n"
		if check == nil || check() != nil {
			status, body = http.StatusServiceUnavailable, "not ready\n"
		}
		// No VM identities, storage paths or backend errors on this public probe.
		w.WriteHeader(status)
		if _, err := w.Write([]byte(body)); err != nil {
			log.Printf("write readiness response: %v", err)
		}
	}
}

func expectedSauronGuests() ([]sauron.VM, error) {
	guests, err := virt.ListExpectedVSockGuests()
	if err != nil {
		return nil, err
	}
	expected := make([]sauron.VM, 0, len(guests))
	for _, guest := range guests {
		expected = append(expected, sauron.VM{CID: guest.CID, Name: guest.Name, UUID: guest.UUID, Owner: guest.Owner})
	}
	return expected, nil
}
