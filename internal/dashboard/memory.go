package dashboard

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

const memInfoPath = "/proc/meminfo"

// ServerMemory is a point-in-time view of the host's usable physical memory.
// UsedBytes excludes memory the kernel considers readily available, including
// reclaimable caches, so the value reflects memory pressure rather than just
// the amount on the free list.
type ServerMemory struct {
	UsedBytes  uint64 `json:"usedBytes"`
	TotalBytes uint64 `json:"totalBytes"`
}

// ReadServerMemory reads the Linux kernel's current host-memory accounting.
func ReadServerMemory() (ServerMemory, error) {
	file, err := os.Open(memInfoPath)
	if err != nil {
		return ServerMemory{}, fmt.Errorf("open server memory information: %w", err)
	}
	defer func() { _ = file.Close() }()

	usage, err := parseServerMemory(file)
	if err != nil {
		return ServerMemory{}, fmt.Errorf("parse server memory information: %w", err)
	}
	return usage, nil
}

func parseServerMemory(reader io.Reader) (ServerMemory, error) {
	values, err := scanServerMemory(reader)
	if err != nil {
		return ServerMemory{}, err
	}
	return values.usage()
}

type serverMemoryValues struct {
	totalBytes     uint64
	availableBytes uint64
	foundTotal     bool
	foundAvailable bool
}

func scanServerMemory(reader io.Reader) (serverMemoryValues, error) {
	var values serverMemoryValues

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) == 0 {
			continue
		}

		key := strings.TrimSuffix(fields[0], ":")
		if key != "MemTotal" && key != "MemAvailable" {
			continue
		}

		value, err := parseMemInfoBytes(fields)
		if err != nil {
			label := "mem available"
			if key == "MemTotal" {
				label = "mem total"
			}
			return serverMemoryValues{}, fmt.Errorf("%s: %w", label, err)
		}
		if key == "MemTotal" {
			values.totalBytes = value
			values.foundTotal = true
		} else {
			values.availableBytes = value
			values.foundAvailable = true
		}
	}
	if err := scanner.Err(); err != nil {
		return serverMemoryValues{}, fmt.Errorf("scan memory information: %w", err)
	}
	return values, nil
}

func (values serverMemoryValues) usage() (ServerMemory, error) {
	if !values.foundTotal {
		return ServerMemory{}, fmt.Errorf("mem total is missing")
	}
	if !values.foundAvailable {
		return ServerMemory{}, fmt.Errorf("mem available is missing")
	}
	if values.totalBytes == 0 {
		return ServerMemory{}, fmt.Errorf("mem total is zero")
	}
	if values.availableBytes > values.totalBytes {
		return ServerMemory{}, fmt.Errorf("mem available exceeds mem total")
	}

	return ServerMemory{
		UsedBytes:  values.totalBytes - values.availableBytes,
		TotalBytes: values.totalBytes,
	}, nil
}

func parseMemInfoBytes(fields []string) (uint64, error) {
	if len(fields) < 3 {
		return 0, fmt.Errorf("expected a value in kB")
	}
	if fields[2] != "kB" {
		return 0, fmt.Errorf("unexpected unit %q", fields[2])
	}

	valueKiB, err := strconv.ParseUint(fields[1], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("parse value %q: %w", fields[1], err)
	}
	const bytesPerKiB = uint64(1024)
	if valueKiB > ^uint64(0)/bytesPerKiB {
		return 0, fmt.Errorf("value %q overflows bytes", fields[1])
	}
	return valueKiB * bytesPerKiB, nil
}
