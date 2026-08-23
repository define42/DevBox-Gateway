package dashboard

import (
	"errors"
	"testing"
	"time"

	"github.com/shirou/gopsutil/v4/disk"
)

func TestNewServerDiskIOSamplerNormalizesDevice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		device string
		want   string
	}{
		{name: "kernel name", device: "vda", want: "vda"},
		{name: "device path", device: "/dev/vda", want: "vda"},
		{name: "surrounding whitespace", device: "  /dev/nvme0n1  ", want: "nvme0n1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			sampler, err := newServerDiskIOSampler(
				tt.device,
				func(...string) (map[string]disk.IOCountersStat, error) { return nil, nil },
				time.Now,
			)
			if err != nil {
				t.Fatalf("newServerDiskIOSampler() error = %v", err)
			}
			if sampler.device != tt.want {
				t.Fatalf("newServerDiskIOSampler() device = %q, want %q", sampler.device, tt.want)
			}
		})
	}
}

func TestNewServerDiskIOSamplerRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	reader := func(...string) (map[string]disk.IOCountersStat, error) { return nil, nil }
	tests := []struct {
		name   string
		device string
		read   serverDiskIOCounterReader
		now    func() time.Time
	}{
		{name: "empty device", read: reader, now: time.Now},
		{name: "blank device", device: "   ", read: reader, now: time.Now},
		{name: "current directory", device: ".", read: reader, now: time.Now},
		{name: "parent directory", device: "..", read: reader, now: time.Now},
		{name: "root directory", device: "/", read: reader, now: time.Now},
		{name: "nil reader", device: "vda", now: time.Now},
		{name: "nil clock", device: "vda", read: reader},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if sampler, err := newServerDiskIOSampler(tt.device, tt.read, tt.now); err == nil {
				t.Fatalf("newServerDiskIOSampler() = %+v, want error", sampler)
			}
		})
	}
}

func TestServerDiskIOSampler(t *testing.T) {
	t.Parallel()

	counters := []disk.IOCountersStat{
		{ReadBytes: 1_000, WriteBytes: 2_000, IoTime: 100},
		{ReadBytes: 5_000, WriteBytes: 8_000, IoTime: 1_100},
		{ReadBytes: 7_000, WriteBytes: 9_000, IoTime: 1_300},
	}
	times := []time.Time{
		time.Unix(100, 0),
		time.Unix(102, 0),
		time.Unix(103, 0),
	}
	readIndex := 0
	timeIndex := 0
	sampler, err := newServerDiskIOSampler(
		"/dev/vda",
		func(names ...string) (map[string]disk.IOCountersStat, error) {
			if len(names) != 1 || names[0] != "vda" {
				t.Fatalf("counter reader names = %v, want [vda]", names)
			}
			counter := counters[readIndex]
			readIndex++
			return map[string]disk.IOCountersStat{"vda": counter}, nil
		},
		func() time.Time {
			at := times[timeIndex]
			timeIndex++
			return at
		},
	)
	if err != nil {
		t.Fatalf("newServerDiskIOSampler() error = %v", err)
	}

	if got, sampleErr := sampler.Sample(); sampleErr != nil || got != nil {
		t.Fatalf("first Sample() = %+v, %v; want nil sample without error", got, sampleErr)
	}
	assertServerDiskIO(t, sampler, ServerDiskIO{
		UsagePercent:        50,
		ReadBytesPerSecond:  2_000,
		WriteBytesPerSecond: 3_000,
	})
	assertServerDiskIO(t, sampler, ServerDiskIO{
		UsagePercent:        20,
		ReadBytesPerSecond:  2_000,
		WriteBytesPerSecond: 1_000,
	})
}

func TestServerDiskIOSamplerResetsAfterReadFailure(t *testing.T) {
	t.Parallel()

	readFailure := errors.New("disk counters unavailable")
	results := []struct {
		counter disk.IOCountersStat
		err     error
	}{
		{counter: disk.IOCountersStat{ReadBytes: 100, WriteBytes: 200, IoTime: 10}},
		{err: readFailure},
		{counter: disk.IOCountersStat{ReadBytes: 300, WriteBytes: 400, IoTime: 30}},
		{counter: disk.IOCountersStat{ReadBytes: 500, WriteBytes: 800, IoTime: 130}},
	}
	readIndex := 0
	now := time.Unix(100, 0)
	sampler := mustNewServerDiskIOSampler(t, func(...string) (map[string]disk.IOCountersStat, error) {
		result := results[readIndex]
		readIndex++
		if result.err != nil {
			return nil, result.err
		}
		return map[string]disk.IOCountersStat{"vda": result.counter}, nil
	}, func() time.Time {
		now = now.Add(time.Second)
		return now
	})

	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("first Sample() = %+v, %v; want baseline", got, err)
	}
	if got, err := sampler.Sample(); !errors.Is(err, readFailure) || got != nil {
		t.Fatalf("failed Sample() = %+v, %v; want wrapped read error", got, err)
	}
	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("Sample() after failure = %+v, %v; want reset baseline", got, err)
	}
	assertServerDiskIO(t, sampler, ServerDiskIO{
		UsagePercent:        10,
		ReadBytesPerSecond:  200,
		WriteBytesPerSecond: 400,
	})
}

func TestServerDiskIOSamplerReset(t *testing.T) {
	t.Parallel()

	readBytes := uint64(0)
	now := time.Unix(100, 0)
	sampler := mustNewServerDiskIOSampler(t, func(...string) (map[string]disk.IOCountersStat, error) {
		readBytes += 100
		return map[string]disk.IOCountersStat{
			"vda": {ReadBytes: readBytes, WriteBytes: readBytes, IoTime: readBytes},
		}, nil
	}, func() time.Time {
		now = now.Add(time.Second)
		return now
	})

	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("first Sample() = %+v, %v; want baseline", got, err)
	}
	sampler.Reset()
	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("Sample() after Reset() = %+v, %v; want baseline", got, err)
	}
	assertServerDiskIO(t, sampler, ServerDiskIO{
		UsagePercent:        10,
		ReadBytesPerSecond:  100,
		WriteBytesPerSecond: 100,
	})
}

func TestServerDiskIOSamplerRecoversFromInvalidDelta(t *testing.T) {
	t.Parallel()

	baseline := serverDiskIOSnapshot{
		readBytes: 100, writeBytes: 200, ioTime: 30, sampledAt: time.Unix(100, 0),
	}
	tests := []struct {
		name       string
		invalid    serverDiskIOSnapshot
		recoveryAt time.Time
	}{
		{
			name:       "zero elapsed",
			invalid:    serverDiskIOSnapshot{readBytes: 200, writeBytes: 300, ioTime: 40, sampledAt: time.Unix(100, 0)},
			recoveryAt: time.Unix(101, 0),
		},
		{
			name:       "time moved backwards",
			invalid:    serverDiskIOSnapshot{readBytes: 200, writeBytes: 300, ioTime: 40, sampledAt: time.Unix(99, 0)},
			recoveryAt: time.Unix(100, 0),
		},
		{
			name:       "read bytes moved backwards",
			invalid:    serverDiskIOSnapshot{readBytes: 99, writeBytes: 300, ioTime: 40, sampledAt: time.Unix(101, 0)},
			recoveryAt: time.Unix(102, 0),
		},
		{
			name:       "write bytes moved backwards",
			invalid:    serverDiskIOSnapshot{readBytes: 200, writeBytes: 199, ioTime: 40, sampledAt: time.Unix(101, 0)},
			recoveryAt: time.Unix(102, 0),
		},
		{
			name:       "I/O time moved backwards",
			invalid:    serverDiskIOSnapshot{readBytes: 200, writeBytes: 300, ioTime: 29, sampledAt: time.Unix(101, 0)},
			recoveryAt: time.Unix(102, 0),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			assertServerDiskIORecovery(t, baseline, tt.invalid, tt.recoveryAt)
		})
	}
}

func TestServerDiskIODeltaRejectsInvalidSamples(t *testing.T) {
	t.Parallel()

	baseline := serverDiskIOSnapshot{
		readBytes:  100,
		writeBytes: 200,
		ioTime:     30,
		sampledAt:  time.Unix(100, 0),
	}
	tests := []struct {
		name    string
		current serverDiskIOSnapshot
	}{
		{name: "zero elapsed", current: serverDiskIOSnapshot{readBytes: 200, writeBytes: 300, ioTime: 40, sampledAt: time.Unix(100, 0)}},
		{name: "time moved backwards", current: serverDiskIOSnapshot{readBytes: 200, writeBytes: 300, ioTime: 40, sampledAt: time.Unix(99, 0)}},
		{name: "read bytes moved backwards", current: serverDiskIOSnapshot{readBytes: 99, writeBytes: 300, ioTime: 40, sampledAt: time.Unix(101, 0)}},
		{name: "write bytes moved backwards", current: serverDiskIOSnapshot{readBytes: 200, writeBytes: 199, ioTime: 40, sampledAt: time.Unix(101, 0)}},
		{name: "I/O time moved backwards", current: serverDiskIOSnapshot{readBytes: 200, writeBytes: 300, ioTime: 29, sampledAt: time.Unix(101, 0)}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, err := serverDiskIODelta(baseline, tt.current); err == nil {
				t.Fatalf("serverDiskIODelta() = %+v, want error", got)
			}
		})
	}
}

func TestServerDiskIODeltaCapsUtilization(t *testing.T) {
	t.Parallel()

	previous := serverDiskIOSnapshot{sampledAt: time.Unix(100, 0)}
	current := serverDiskIOSnapshot{ioTime: 1_500, sampledAt: time.Unix(101, 0)}
	got, err := serverDiskIODelta(previous, current)
	if err != nil {
		t.Fatalf("serverDiskIODelta() error = %v", err)
	}
	if got.UsagePercent != 100 {
		t.Fatalf("serverDiskIODelta() utilization = %v, want 100", got.UsagePercent)
	}
}

func TestServerDiskIOSamplerRejectsMissingDevice(t *testing.T) {
	t.Parallel()

	sampler := mustNewServerDiskIOSampler(t, func(...string) (map[string]disk.IOCountersStat, error) {
		return map[string]disk.IOCountersStat{"sda": {}}, nil
	}, time.Now)
	if got, err := sampler.Sample(); err == nil || got != nil {
		t.Fatalf("Sample() = %+v, %v; want missing device error", got, err)
	}
}

func assertServerDiskIO(t *testing.T, sampler *ServerDiskIOSampler, want ServerDiskIO) {
	t.Helper()

	got, err := sampler.Sample()
	if err != nil {
		t.Fatalf("Sample() error = %v", err)
	}
	if got == nil || *got != want {
		t.Fatalf("Sample() = %+v, want %+v", got, want)
	}
}

func assertServerDiskIORecovery(
	t *testing.T,
	baseline serverDiskIOSnapshot,
	invalid serverDiskIOSnapshot,
	recoveryAt time.Time,
) {
	t.Helper()

	recovery := serverDiskIOSnapshot{
		readBytes:  invalid.readBytes + 100,
		writeBytes: invalid.writeBytes + 100,
		ioTime:     invalid.ioTime + 100,
		sampledAt:  recoveryAt,
	}
	snapshots := []serverDiskIOSnapshot{baseline, invalid, recovery}
	index := 0
	sampler := mustNewServerDiskIOSampler(t, func(...string) (map[string]disk.IOCountersStat, error) {
		snapshot := snapshots[index]
		return map[string]disk.IOCountersStat{"vda": {
			ReadBytes: snapshot.readBytes, WriteBytes: snapshot.writeBytes, IoTime: snapshot.ioTime,
		}}, nil
	}, func() time.Time {
		at := snapshots[index].sampledAt
		index++
		return at
	})

	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("first Sample() = %+v, %v; want baseline", got, err)
	}
	if got, err := sampler.Sample(); err == nil || got != nil {
		t.Fatalf("invalid Sample() = %+v, %v; want error", got, err)
	}
	assertServerDiskIO(t, sampler, ServerDiskIO{
		UsagePercent:        10,
		ReadBytesPerSecond:  100,
		WriteBytesPerSecond: 100,
	})
}

func mustNewServerDiskIOSampler(
	t *testing.T,
	read serverDiskIOCounterReader,
	now func() time.Time,
) *ServerDiskIOSampler {
	t.Helper()

	sampler, err := newServerDiskIOSampler("vda", read, now)
	if err != nil {
		t.Fatalf("newServerDiskIOSampler() error = %v", err)
	}
	return sampler
}
