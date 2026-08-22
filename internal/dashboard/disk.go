package dashboard

import (
	"fmt"
	"math"
	"strings"

	"golang.org/x/sys/unix"
)

// ServerDisk is a point-in-time view of the filesystem that stores managed VM
// volumes. UsedBytes includes filesystem-reserved blocks that are unavailable
// to the gateway, so it reflects the capacity the gateway can actually use.
type ServerDisk struct {
	UsedBytes  uint64 `json:"usedBytes"`
	TotalBytes uint64 `json:"totalBytes"`
}

// ReadServerDisk reads capacity information for the filesystem containing
// path. The caller supplies the configured VM storage-pool path.
func ReadServerDisk(path string) (ServerDisk, error) {
	if strings.TrimSpace(path) == "" {
		return ServerDisk{}, fmt.Errorf("read server disk information: path is empty")
	}

	var stats unix.Statfs_t
	if err := unix.Statfs(path, &stats); err != nil {
		return ServerDisk{}, fmt.Errorf("read server disk information for %s: %w", path, err)
	}

	usage, err := serverDiskFromStatfs(stats)
	if err != nil {
		return ServerDisk{}, fmt.Errorf("read server disk information for %s: %w", path, err)
	}
	return usage, nil
}

func serverDiskFromStatfs(stats unix.Statfs_t) (ServerDisk, error) {
	if stats.Bsize <= 0 {
		return ServerDisk{}, fmt.Errorf("invalid block size %d", stats.Bsize)
	}
	if stats.Blocks == 0 {
		return ServerDisk{}, fmt.Errorf("total block count is zero")
	}
	if stats.Bavail > stats.Blocks {
		return ServerDisk{}, fmt.Errorf("available blocks exceed total blocks")
	}

	blockSize := uint64(stats.Bsize)
	if stats.Blocks > math.MaxUint64/blockSize {
		return ServerDisk{}, fmt.Errorf("total byte count overflows uint64")
	}
	totalBytes := stats.Blocks * blockSize
	availableBytes := stats.Bavail * blockSize

	return ServerDisk{
		UsedBytes:  totalBytes - availableBytes,
		TotalBytes: totalBytes,
	}, nil
}
