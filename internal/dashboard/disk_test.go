package dashboard

import (
	"math"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerDiskFromStatfs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stats unix.Statfs_t
		want  ServerDisk
	}{
		{
			name:  "reserved blocks count as used",
			stats: unix.Statfs_t{Bsize: 4096, Blocks: 100, Bfree: 50, Bavail: 40},
			want:  ServerDisk{UsedBytes: 60 * 4096, TotalBytes: 100 * 4096},
		},
		{
			name:  "full",
			stats: unix.Statfs_t{Bsize: 1024, Blocks: 100, Bavail: 0},
			want:  ServerDisk{UsedBytes: 100 * 1024, TotalBytes: 100 * 1024},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := serverDiskFromStatfs(tt.stats)
			if err != nil {
				t.Fatalf("serverDiskFromStatfs() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("serverDiskFromStatfs() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestServerDiskFromStatfsRejectsInvalidStats(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		stats unix.Statfs_t
	}{
		{name: "zero block size", stats: unix.Statfs_t{Blocks: 100, Bavail: 40}},
		{name: "negative block size", stats: unix.Statfs_t{Bsize: -1, Blocks: 100, Bavail: 40}},
		{name: "zero total blocks", stats: unix.Statfs_t{Bsize: 4096}},
		{name: "available blocks exceed total", stats: unix.Statfs_t{Bsize: 4096, Blocks: 100, Bavail: 101}},
		{name: "total bytes overflow", stats: unix.Statfs_t{Bsize: 2, Blocks: math.MaxUint64, Bavail: 1}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got, err := serverDiskFromStatfs(tt.stats); err == nil {
				t.Fatalf("serverDiskFromStatfs() = %+v, want error", got)
			}
		})
	}
}

func TestReadServerDisk(t *testing.T) {
	t.Parallel()

	usage, err := ReadServerDisk(t.TempDir())
	if err != nil {
		t.Fatalf("ReadServerDisk() error = %v", err)
	}
	if usage.TotalBytes == 0 || usage.UsedBytes > usage.TotalBytes {
		t.Fatalf("ReadServerDisk() returned invalid usage: %+v", usage)
	}
}

func TestReadServerDiskRejectsInvalidPath(t *testing.T) {
	t.Parallel()

	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		if usage, err := ReadServerDisk(path); err == nil {
			t.Errorf("ReadServerDisk(%q) = %+v, want error", path, usage)
		}
	}
}
