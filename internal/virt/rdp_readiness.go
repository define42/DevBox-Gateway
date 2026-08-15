package virt

import (
	"context"
	"net"
	"sync"
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
func (s *SingletonWorker) RefreshRDPReadiness(ctx context.Context, username string) {
	s.refreshRDPReadiness(ctx, username, probeRDPAddress)
}

func (s *SingletonWorker) refreshRDPReadiness(
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

func (s *SingletonWorker) probeRDPJobs(
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

func (s *SingletonWorker) rdpReadinessJobs(username string) []rdpReadinessJob {
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

func (s *SingletonWorker) applyRDPReadinessResults(results []rdpReadinessResult) {
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
