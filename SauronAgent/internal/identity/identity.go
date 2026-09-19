// Package identity gathers the guest's self-description.
//
// Everything here is informational. The host derives a guest's authoritative
// identity from the VSOCK CID of the connection, because a compromised guest
// controls every value this package can read. The data is still worth sending:
// it makes host-side logs readable, and a mismatch between the CID mapping and
// what the guest claims is itself a signal worth alerting on.
package identity

import (
	"bytes"
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Version is the agent version, overridable at build time with
// -ldflags "-X github.com/define42/SauronAgent/internal/identity.Version=..."
var Version = "0.1.0"

// Identity describes the guest the agent is running in.
type Identity struct {
	Hostname  string
	MachineID string
	BootID    string
	Kernel    string
	Version   string
}

// bootIDPath is the kernel-generated identifier that changes on every boot.
// It scopes event sequence numbers: (boot ID, sequence) is unique per guest.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// machineIDPaths are the standard locations for the persistent machine ID, in
// order of preference.
var machineIDPaths = []string{"/etc/machine-id", "/var/lib/dbus/machine-id"}

// Gather collects the guest's identity. It never fails: a value that cannot be
// read is simply left empty, because an agent that refuses to start over a
// missing /etc/machine-id would be a worse outcome than one that reports
// slightly less context.
func Gather() Identity {
	id := Identity{Version: Version}
	if h, err := os.Hostname(); err == nil {
		id.Hostname = h
	}
	id.BootID = readTrimmed(bootIDPath)
	for _, p := range machineIDPaths {
		if v := readTrimmed(p); v != "" {
			id.MachineID = v
			break
		}
	}
	id.Kernel = kernelRelease()
	return id
}

func readTrimmed(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func kernelRelease() string {
	var uts unix.Utsname
	if err := unix.Uname(&uts); err != nil {
		return ""
	}
	return string(bytes.TrimRight(uts.Release[:], "\x00"))
}

// String implements fmt.Stringer.
func (i Identity) String() string {
	return fmt.Sprintf("hostname=%s machine_id=%s boot_id=%s kernel=%s version=%s",
		i.Hostname, i.MachineID, i.BootID, i.Kernel, i.Version)
}
