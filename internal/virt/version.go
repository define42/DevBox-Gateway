package virt

import (
	"fmt"

	"libvirt.org/go/libvirt"
)

// minLibvirtVersion is the lowest libvirt daemon version the gateway supports.
// It is 6.2.0, the first release that honors <port isolated='yes'/> on a virtual
// network interface (see internal/virt/ubuntu.go). Without it, booted VDIs would
// silently share an L2 bridge with no guest-to-guest isolation, so we refuse to
// start rather than provision VMs that are not isolated.
//
// libvirt encodes versions as major*1000000 + minor*1000 + release, so 6.2.0 is
// 6*1000000 + 2*1000 + 0.
const minLibvirtVersion uint32 = 6*1_000_000 + 2*1_000 + 0

// ensureLibvirtVersion verifies the connected libvirt daemon is new enough to
// enforce VDI network isolation. It returns an error when the daemon is older
// than minLibvirtVersion so the caller can abort startup.
func ensureLibvirtVersion(conn *libvirt.Connect) error {
	version, err := conn.GetLibVersion()
	if err != nil {
		return fmt.Errorf("query libvirt version: %w", err)
	}
	return checkLibvirtVersion(version)
}

// checkLibvirtVersion compares an encoded libvirt version against the minimum
// the gateway requires. It is split out from ensureLibvirtVersion so the policy
// can be unit-tested without a live libvirt connection.
func checkLibvirtVersion(version uint32) error {
	if version < minLibvirtVersion {
		return fmt.Errorf(
			"libvirt %s is too old: VDI network isolation (<port isolated='yes'>) requires libvirt %s or newer",
			formatLibvirtVersion(version),
			formatLibvirtVersion(minLibvirtVersion),
		)
	}
	return nil
}

// formatLibvirtVersion renders an encoded libvirt version as "major.minor.release".
func formatLibvirtVersion(version uint32) string {
	major := version / 1_000_000
	minor := (version / 1_000) % 1_000
	release := version % 1_000
	return fmt.Sprintf("%d.%d.%d", major, minor, release)
}
