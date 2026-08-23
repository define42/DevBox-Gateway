package dashboard

import (
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

// ServerDiskIO is block-device activity measured over a sampling interval.
type ServerDiskIO struct {
	UsagePercent        float64 `json:"usagePercent"`
	ReadBytesPerSecond  float64 `json:"readBytesPerSecond"`
	WriteBytesPerSecond float64 `json:"writeBytesPerSecond"`
}

// ServerDiskIOSampler keeps the preceding counters needed to derive block-
// device utilization and throughput. A sampler is safe for concurrent use.
type ServerDiskIOSampler struct {
	mu          sync.Mutex
	device      string
	read        serverDiskIOCounterReader
	now         func() time.Time
	previous    serverDiskIOSnapshot
	hasPrevious bool
}

type serverDiskIOCounterReader func(...string) (map[string]disk.IOCountersStat, error)

type serverDiskIOSnapshot struct {
	readBytes  uint64
	writeBytes uint64
	ioTime     uint64
	sampledAt  time.Time
}

// NewServerDiskIOSampler creates a sampler for a configured kernel block-
// device name. Both "vda" and a path such as "/dev/vda" select device vda.
func NewServerDiskIOSampler(device string) (*ServerDiskIOSampler, error) {
	return newServerDiskIOSampler(device, disk.IOCounters, time.Now)
}

func newServerDiskIOSampler(
	device string,
	read serverDiskIOCounterReader,
	now func() time.Time,
) (*ServerDiskIOSampler, error) {
	deviceName, err := normalizeServerDiskIODevice(device)
	if err != nil {
		return nil, err
	}
	if read == nil {
		return nil, fmt.Errorf("create server disk I/O sampler: counter reader is nil")
	}
	if now == nil {
		return nil, fmt.Errorf("create server disk I/O sampler: clock is nil")
	}

	return &ServerDiskIOSampler{
		device: deviceName,
		read:   read,
		now:    now,
	}, nil
}

// Sample reads the configured device and calculates activity since the
// preceding successful observation. The first call establishes the baseline
// and returns a nil sample without an error.
func (sampler *ServerDiskIOSampler) Sample() (*ServerDiskIO, error) {
	if sampler == nil || sampler.read == nil || sampler.now == nil {
		return nil, fmt.Errorf("sample server disk I/O: sampler is not initialized")
	}

	sampler.mu.Lock()
	defer sampler.mu.Unlock()

	current, err := sampler.readSnapshot()
	if err != nil {
		sampler.resetLocked()
		return nil, fmt.Errorf("sample server disk I/O: %w", err)
	}
	previous := sampler.previous
	hadPrevious := sampler.hasPrevious
	sampler.previous = current
	sampler.hasPrevious = true
	if !hadPrevious {
		return nil, nil
	}

	usage, err := serverDiskIODelta(previous, current)
	if err != nil {
		return nil, fmt.Errorf("sample server disk I/O: %w", err)
	}
	return &usage, nil
}

// Reset drops the current baseline. The next successful Sample call only
// establishes a fresh baseline.
func (sampler *ServerDiskIOSampler) Reset() {
	if sampler == nil {
		return
	}

	sampler.mu.Lock()
	defer sampler.mu.Unlock()
	sampler.resetLocked()
}

func (sampler *ServerDiskIOSampler) readSnapshot() (serverDiskIOSnapshot, error) {
	counters, err := sampler.read(sampler.device)
	if err != nil {
		return serverDiskIOSnapshot{}, fmt.Errorf("read device %q counters: %w", sampler.device, err)
	}
	counter, ok := counters[sampler.device]
	if !ok {
		return serverDiskIOSnapshot{}, fmt.Errorf("device %q counters are missing", sampler.device)
	}

	return serverDiskIOSnapshot{
		readBytes:  counter.ReadBytes,
		writeBytes: counter.WriteBytes,
		ioTime:     counter.IoTime,
		sampledAt:  sampler.now(),
	}, nil
}

func (sampler *ServerDiskIOSampler) resetLocked() {
	sampler.previous = serverDiskIOSnapshot{}
	sampler.hasPrevious = false
}

func normalizeServerDiskIODevice(device string) (string, error) {
	trimmed := strings.TrimSpace(device)
	if trimmed == "" {
		return "", fmt.Errorf("create server disk I/O sampler: device is empty")
	}

	deviceName := filepath.Base(filepath.Clean(trimmed))
	if deviceName == "." || deviceName == ".." || deviceName == string(filepath.Separator) {
		return "", fmt.Errorf("create server disk I/O sampler: invalid device %q", device)
	}
	return deviceName, nil
}

func serverDiskIODelta(previous, current serverDiskIOSnapshot) (ServerDiskIO, error) {
	elapsed := current.sampledAt.Sub(previous.sampledAt)
	if elapsed <= 0 {
		return ServerDiskIO{}, fmt.Errorf("sampling interval must be positive")
	}
	if current.readBytes < previous.readBytes {
		return ServerDiskIO{}, fmt.Errorf("read byte counter moved backwards")
	}
	if current.writeBytes < previous.writeBytes {
		return ServerDiskIO{}, fmt.Errorf("write byte counter moved backwards")
	}
	if current.ioTime < previous.ioTime {
		return ServerDiskIO{}, fmt.Errorf("I/O time counter moved backwards")
	}

	elapsedSeconds := elapsed.Seconds()
	elapsedMilliseconds := elapsedSeconds * 1000
	utilization := float64(current.ioTime-previous.ioTime) * 100 / elapsedMilliseconds

	return ServerDiskIO{
		UsagePercent:        math.Min(utilization, 100),
		ReadBytesPerSecond:  float64(current.readBytes-previous.readBytes) / elapsedSeconds,
		WriteBytesPerSecond: float64(current.writeBytes-previous.writeBytes) / elapsedSeconds,
	}, nil
}
