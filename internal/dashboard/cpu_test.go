package dashboard

import (
	"errors"
	"strings"
	"testing"
)

func TestParseServerCPUTimes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		want  serverCPUTimes
	}{
		{
			name:  "all counters excluding guest times",
			input: "intr 1 2 3\ncpu 100 10 20 700 30 5 6 7 999 999\ncpu0 50 5 10 350 15 2 3 4\n",
			want:  serverCPUTimes{total: 878, idle: 730},
		},
		{name: "minimum counters", input: "cpu 10 5 15 70\n", want: serverCPUTimes{total: 100, idle: 70}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseServerCPUTimes(strings.NewReader(tt.input))
			if err != nil {
				t.Fatalf("parseServerCPUTimes() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseServerCPUTimes() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestParseServerCPUTimesRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
	}{
		{name: "missing aggregate row", input: "cpu0 1 2 3 4\n"},
		{name: "too few counters", input: "cpu 1 2 3\n"},
		{name: "invalid counter", input: "cpu 1 invalid 3 4\n"},
		{name: "negative counter", input: "cpu 1 -2 3 4\n"},
		{name: "counter overflow", input: "cpu 18446744073709551615 1 0 0\n"},
		{name: "zero total", input: "cpu 0 0 0 0\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, err := parseServerCPUTimes(strings.NewReader(tt.input)); err == nil {
				t.Fatalf("parseServerCPUTimes() = %+v, want error", got)
			}
		})
	}
}

func TestServerCPUUtilization(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		previous serverCPUTimes
		current  serverCPUTimes
		want     float64
	}{
		{name: "partially busy", previous: serverCPUTimes{total: 100, idle: 80}, current: serverCPUTimes{total: 200, idle: 140}, want: 40},
		{name: "fully busy", previous: serverCPUTimes{total: 100, idle: 80}, current: serverCPUTimes{total: 200, idle: 80}, want: 100},
		{name: "fully idle", previous: serverCPUTimes{total: 100, idle: 80}, current: serverCPUTimes{total: 200, idle: 180}, want: 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := serverCPUUtilization(tt.previous, tt.current)
			if err != nil {
				t.Fatalf("serverCPUUtilization() error = %v", err)
			}
			if got.UsagePercent != tt.want {
				t.Fatalf("serverCPUUtilization() = %v%%, want %v%%", got.UsagePercent, tt.want)
			}
		})
	}
}

func TestServerCPUUtilizationRejectsInvalidSamples(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		previous serverCPUTimes
		current  serverCPUTimes
	}{
		{name: "total moved backwards", previous: serverCPUTimes{total: 200, idle: 100}, current: serverCPUTimes{total: 199, idle: 100}},
		{name: "idle moved backwards", previous: serverCPUTimes{total: 100, idle: 80}, current: serverCPUTimes{total: 200, idle: 79}},
		{name: "no elapsed CPU time", previous: serverCPUTimes{total: 100, idle: 80}, current: serverCPUTimes{total: 100, idle: 80}},
		{name: "idle exceeds total delta", previous: serverCPUTimes{total: 100, idle: 20}, current: serverCPUTimes{total: 110, idle: 40}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, err := serverCPUUtilization(tt.previous, tt.current); err == nil {
				t.Fatalf("serverCPUUtilization() = %+v, want error", got)
			}
		})
	}
}

func TestServerCPUSampler(t *testing.T) {
	t.Parallel()

	type readResult struct {
		times serverCPUTimes
		err   error
	}
	results := []readResult{
		{times: serverCPUTimes{total: 100, idle: 80}},
		{err: errors.New("cpu counters unavailable")},
		{times: serverCPUTimes{total: 200, idle: 140}},
		{times: serverCPUTimes{total: 300, idle: 200}},
		{times: serverCPUTimes{total: 400, idle: 220}},
	}
	readCalls := 0
	sampler := &ServerCPUSampler{read: func() (serverCPUTimes, error) {
		result := results[readCalls]
		readCalls++
		return result.times, result.err
	}}

	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("first Sample() = %+v, %v; want nil sample without error", got, err)
	}
	if got, err := sampler.Sample(); err == nil || got != nil {
		t.Fatalf("second Sample() = %+v, want read error", got)
	}
	if got, err := sampler.Sample(); err != nil || got != nil {
		t.Fatalf("third Sample() = %+v, %v; want reset baseline without error", got, err)
	}
	got, err := sampler.Sample()
	if err != nil {
		t.Fatalf("fourth Sample() error = %v", err)
	}
	if got == nil {
		t.Fatal("fourth Sample() returned nil")
	}
	if got.UsagePercent != 40 {
		t.Fatalf("fourth Sample() = %v%%, want 40%%", got.UsagePercent)
	}

	got, err = sampler.Sample()
	if err != nil {
		t.Fatalf("fifth Sample() error = %v", err)
	}
	if got == nil || got.UsagePercent != 80 {
		t.Fatalf("fifth Sample() = %+v, want 80%%", got)
	}
}
