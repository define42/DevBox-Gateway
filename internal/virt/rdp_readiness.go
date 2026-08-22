package virt

import (
	"context"
	"net"
	"sync"
	"time"
)

const (
	rdpPort                  = "3389"
	rdpReadinessProbeTimeout = 500 * time.Millisecond
)

type rdpReadinessProbe func(context.Context, string) bool

// rdpReadinessJob always carries PrimaryIP from the trusted DHCP-derived
// routing cache. Dashboard clients never provide probe targets.
type rdpReadinessJob struct {
	name       string
	owner      string
	primaryIP  string
	generation uint64
}

type rdpReadinessResult struct {
	job         rdpReadinessJob
	ready       bool
	observation uint64
}

// RefreshRDPReadiness checks every running VM owned by username. Dashboard
// WebSocket publishers call this synchronously, so each connection owns its
// polling lifecycle and cancellation. All of that user's probes start together;
// there is deliberately no process-wide concurrency limit.
func (s *Inventory) RefreshRDPReadiness(ctx context.Context, username string) {
	s.refreshRDPReadiness(ctx, username, probeRDPAddress)
}

func (s *Inventory) refreshRDPReadiness(
	ctx context.Context,
	username string,
	probe rdpReadinessProbe,
) {
	if username == "" || ctx.Err() != nil {
		return
	}
	if probe == nil {
		probe = probeRDPAddress
	}

	jobs := s.rdpReadinessJobs(username)
	if len(jobs) == 0 {
		return
	}

	results := s.probeRDPJobs(ctx, jobs, probe)
	s.applyRDPReadinessResults(results)
}

func (s *Inventory) probeRDPJobs(
	ctx context.Context,
	jobs []rdpReadinessJob,
	probe rdpReadinessProbe,
) []rdpReadinessResult {
	results := make(chan rdpReadinessResult, len(jobs))
	var wg sync.WaitGroup
	wg.Add(len(jobs))

	for _, job := range jobs {
		go func() {
			defer wg.Done()
			address := net.JoinHostPort(job.primaryIP, rdpPort)
			ready := probe(ctx, address)
			if ctx.Err() != nil {
				return
			}
			results <- rdpReadinessResult{
				job:         job,
				ready:       ready,
				observation: s.nextRDPObservation.Add(1),
			}
		}()
	}

	wg.Wait()
	close(results)

	completed := make([]rdpReadinessResult, 0, len(results))
	for result := range results {
		completed = append(completed, result)
	}
	return completed
}

func probeRDPAddress(ctx context.Context, address string) bool {
	return tcpEndpointReadyContext(ctx, address, rdpReadinessProbeTimeout)
}

func tcpEndpointReady(address string, timeout time.Duration) bool {
	return tcpEndpointReadyContext(context.Background(), address, timeout)
}

func tcpEndpointReadyContext(ctx context.Context, address string, timeout time.Duration) bool {
	dialer := net.Dialer{Timeout: timeout}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return false
	}
	_ = conn.Close()
	return true
}

func (s *Inventory) rdpReadinessJobs(username string) []rdpReadinessJob {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jobs := make([]rdpReadinessJob, 0, len(s.vms))
	seen := make(map[string]struct{}, len(s.vms))
	for _, vm := range s.vms {
		if vm.Owner != username || !isRDPReadinessTarget(vm) {
			continue
		}
		if _, duplicate := seen[vm.Name]; duplicate {
			continue
		}
		seen[vm.Name] = struct{}{}
		jobs = append(jobs, rdpReadinessJob{
			name:       vm.Name,
			owner:      vm.Owner,
			primaryIP:  vm.PrimaryIP,
			generation: vm.rdpGeneration,
		})
	}
	return jobs
}

func isRDPReadinessTarget(vm VMInfo) bool {
	return vm.State == "running" && vm.PrimaryIP != "" && vm.Owner != ""
}

func (s *Inventory) applyRDPReadinessResults(results []rdpReadinessResult) {
	if len(results) == 0 {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	vmIndexes := make(map[string]int, len(s.vms))
	for i := range s.vms {
		vmIndexes[s.vms[i].Name] = i
	}

	changed := false
	for _, result := range results {
		index, ok := vmIndexes[result.job.name]
		if !ok {
			continue
		}
		vm := &s.vms[index]
		if !rdpResultMatchesTarget(vm, &result) {
			continue
		}
		if result.observation != 0 && result.observation <= vm.rdpObservation {
			continue
		}
		if result.observation != 0 {
			vm.rdpObservation = result.observation
		}
		if vm.RDPReady != result.ready {
			vm.RDPReady = result.ready
			changed = true
		}
	}

	if changed {
		s.notifySubscribersLocked()
	}
}

func rdpResultMatchesTarget(vm *VMInfo, result *rdpReadinessResult) bool {
	return vm.Name == result.job.name &&
		vm.Owner == result.job.owner &&
		vm.PrimaryIP == result.job.primaryIP &&
		vm.rdpGeneration == result.job.generation &&
		vm.State == "running"
}

// mergeRDPReadinessLocked carries RDP readiness state forward onto a fresh VM
// snapshot: an entry whose probe target is unchanged keeps its readiness and
// generation, while a new or changed entry gets a new generation so stale probe
// results can never be applied to it. Callers must hold s.mu.
func (s *Inventory) mergeRDPReadinessLocked(next []VMInfo) {
	previous := make(map[string]VMInfo, len(s.vms))
	for _, vm := range s.vms {
		previous[vm.Name] = vm
	}

	for i := range next {
		old, ok := previous[next[i].Name]
		if ok && sameRDPReadinessTarget(old, next[i]) {
			if next[i].State == "running" {
				next[i].RDPReady = old.RDPReady
			} else {
				next[i].RDPReady = false
			}
			next[i].rdpGeneration = old.rdpGeneration
			next[i].rdpObservation = old.rdpObservation
			continue
		}

		s.nextRDPGeneration++
		next[i].RDPReady = false
		next[i].rdpGeneration = s.nextRDPGeneration
		next[i].rdpObservation = 0
	}
}

func sameRDPReadinessTarget(old, next VMInfo) bool {
	return old.Name == next.Name &&
		old.Owner == next.Owner &&
		old.PrimaryIP == next.PrimaryIP &&
		old.CreatedAt == next.CreatedAt &&
		old.State == next.State
}
