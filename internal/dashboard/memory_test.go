package dashboard

import (
	"strings"
	"testing"
)

func TestParseServerMemory(t *testing.T) {
	t.Parallel()

	const gib = uint64(1024 * 1024 * 1024)
	tests := []struct {
		name    string
		input   string
		want    ServerMemory
		wantErr bool
	}{
		{
			name: "half of 64 GiB used",
			input: "MemTotal:       67108864 kB\n" +
				"MemFree:         1048576 kB\n" +
				"MemAvailable:   33554432 kB\n",
			want: ServerMemory{UsedBytes: 32 * gib, TotalBytes: 64 * gib},
		},
		{
			name: "no memory available",
			input: "MemAvailable:          0 kB\n" +
				"MemTotal:          1048576 kB\n",
			want: ServerMemory{UsedBytes: gib, TotalBytes: gib},
		},
		{name: "missing total", input: "MemAvailable: 1 kB\n", wantErr: true},
		{name: "missing available", input: "MemTotal: 1 kB\n", wantErr: true},
		{name: "zero total", input: "MemTotal: 0 kB\nMemAvailable: 0 kB\n", wantErr: true},
		{name: "available exceeds total", input: "MemTotal: 1 kB\nMemAvailable: 2 kB\n", wantErr: true},
		{name: "invalid value", input: "MemTotal: many kB\nMemAvailable: 1 kB\n", wantErr: true},
		{name: "invalid unit", input: "MemTotal: 1024 MB\nMemAvailable: 1 kB\n", wantErr: true},
		{name: "overflow", input: "MemTotal: 18446744073709551615 kB\nMemAvailable: 1 kB\n", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseServerMemory(strings.NewReader(tt.input))
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseServerMemory() = %+v, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseServerMemory() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("parseServerMemory() = %+v, want %+v", got, tt.want)
			}
		})
	}
}
