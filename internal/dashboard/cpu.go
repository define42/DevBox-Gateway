package dashboard

import (
	"bufio"
	"fmt"
	"io"
	"math"
	"os"
	"strconv"
	"strings"
	"sync"
)

const (
	procStatPath           = "/proc/stat"
	minServerCPUTimeFields = 4
	maxServerCPUTimeFields = 8
)

// ServerCPU is the aggregate utilization of all logical CPUs over a sampling
// interval.
type ServerCPU struct {
	UsagePercent float64 `json:"usagePercent"`
}

// ServerCPUSampler keeps the previous aggregate CPU counters needed to derive
// interval utilization. A sampler is safe for concurrent use, although each
// administrator dashboard connection owns its own sampler.
type ServerCPUSampler struct {
	mu          sync.Mutex
	read        func() (serverCPUTimes, error)
	previous    serverCPUTimes
	hasPrevious bool
}

type serverCPUTimes struct {
	total uint64
	idle  uint64
}

// NewServerCPUSampler creates an aggregate host CPU sampler.
func NewServerCPUSampler() *ServerCPUSampler {
	return &ServerCPUSampler{read: readServerCPUTimes}
}

// Sample reads the current aggregate CPU counters and calculates utilization
// since the preceding successful sample. The first call establishes the
// baseline and returns a nil sample without an error.
func (sampler *ServerCPUSampler) Sample() (*ServerCPU, error) {
	if sampler == nil || sampler.read == nil {
		return nil, fmt.Errorf("sample server CPU: sampler is not initialized")
	}

	sampler.mu.Lock()
	defer sampler.mu.Unlock()

	current, err := sampler.read()
	if err != nil {
		sampler.hasPrevious = false
		return nil, fmt.Errorf("sample server CPU: %w", err)
	}
	previous := sampler.previous
	hadPrevious := sampler.hasPrevious
	sampler.previous = current
	sampler.hasPrevious = true
	if !hadPrevious {
		return nil, nil
	}

	usage, err := serverCPUUtilization(previous, current)
	if err != nil {
		return nil, fmt.Errorf("sample server CPU: %w", err)
	}
	return &usage, nil
}

func readServerCPUTimes() (serverCPUTimes, error) {
	file, err := os.Open(procStatPath)
	if err != nil {
		return serverCPUTimes{}, fmt.Errorf("open server CPU information: %w", err)
	}
	defer func() { _ = file.Close() }()

	times, err := parseServerCPUTimes(file)
	if err != nil {
		return serverCPUTimes{}, fmt.Errorf("parse server CPU information: %w", err)
	}
	return times, nil
}

func parseServerCPUTimes(reader io.Reader) (serverCPUTimes, error) {
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 || fields[0] != "cpu" {
			continue
		}
		return parseServerCPUTimeFields(fields[1:])
	}
	if err := scanner.Err(); err != nil {
		return serverCPUTimes{}, fmt.Errorf("scan CPU information: %w", err)
	}
	return serverCPUTimes{}, fmt.Errorf("aggregate CPU counters are missing")
}

func parseServerCPUTimeFields(fields []string) (serverCPUTimes, error) {
	if len(fields) < minServerCPUTimeFields {
		return serverCPUTimes{}, fmt.Errorf("expected at least %d CPU counters", minServerCPUTimeFields)
	}
	if len(fields) > maxServerCPUTimeFields {
		fields = fields[:maxServerCPUTimeFields]
	}

	var times serverCPUTimes
	for index, field := range fields {
		value, err := strconv.ParseUint(field, 10, 64)
		if err != nil {
			return serverCPUTimes{}, fmt.Errorf("parse CPU counter %q: %w", field, err)
		}
		if value > math.MaxUint64-times.total {
			return serverCPUTimes{}, fmt.Errorf("total CPU counter overflows uint64")
		}
		times.total += value
		if index == 3 || index == 4 {
			if value > math.MaxUint64-times.idle {
				return serverCPUTimes{}, fmt.Errorf("idle CPU counter overflows uint64")
			}
			times.idle += value
		}
	}
	if times.total == 0 {
		return serverCPUTimes{}, fmt.Errorf("total CPU counter is zero")
	}
	return times, nil
}

func serverCPUUtilization(previous, current serverCPUTimes) (ServerCPU, error) {
	if current.total < previous.total || current.idle < previous.idle {
		return ServerCPU{}, fmt.Errorf("CPU counters moved backwards")
	}

	totalDelta := current.total - previous.total
	if totalDelta == 0 {
		return ServerCPU{}, fmt.Errorf("total CPU counter did not advance")
	}
	idleDelta := current.idle - previous.idle
	if idleDelta > totalDelta {
		return ServerCPU{}, fmt.Errorf("idle CPU delta exceeds total CPU delta")
	}

	busyDelta := totalDelta - idleDelta
	return ServerCPU{UsagePercent: float64(busyDelta) * 100 / float64(totalDelta)}, nil
}
