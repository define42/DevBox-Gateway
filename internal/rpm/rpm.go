// Package rpm builds RPM packages for the DevBox Gateway executable.
package rpm

import (
	"fmt"
	"math"
	"os"

	"github.com/google/rpmpack"
)

const (
	packageName = "devbox-gateway"
	summary     = "DevBox Gateway for libvirt-backed development desktops"
	description = "DevBox Gateway publishes libvirt-managed development desktops over a single HTTPS port. It terminates TLS from RDP clients, routes each connection to a backend VM by TLS SNI, and re-establishes TLS to that backend. The same port also serves an LDAP-authenticated web dashboard for self-service VM lifecycle management, in-browser serial and noVNC consoles, and downloadable .rdp connection files."
	url         = "https://github.com/define42/devbox-gateway"

	confDestination = "/etc/devbox-gateway/devbox-gateway.conf"
	unitDestination = "/usr/lib/systemd/system/devbox-gateway.service"
	licenseDest     = "/usr/share/licenses/devbox-gateway/LICENSE"
)

// The service runs as root (it binds :443 and talks to libvirt), so no dedicated
// user is created. These scriptlets mirror the systemd rpm macros: reload on
// install, apply preset policy on initial install, disable on final removal, and
// restart on upgrade. $1 is the count of package instances that will remain after
// the transaction (0 = the package is being removed entirely, 1 = initial
// install, >1 = upgrade).
//
// preset (rather than a forced enable) honors the host's systemd preset policy,
// so installing the package enables the unit only where policy allows and never
// starts it; an operator still runs `systemctl start` (or reboots) to launch it.
const postinScript = `if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
    if [ "$1" = 1 ]; then
        systemctl --no-reload preset devbox-gateway.service || :
    fi
fi
`

const preunScript = `if [ "$1" = 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now devbox-gateway.service || :
fi
`

const postunScript = `if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
    if [ "$1" -ge 1 ]; then
        systemctl try-restart devbox-gateway.service || :
    fi
fi
`

// Options describes the inputs and metadata needed to build an RPM package.
type Options struct {
	Version           string
	Release           string
	Arch              string
	License           string
	BinarySource      string
	BinaryDestination string
	UnitSource        string
	ConfigSource      string
	LicenseSource     string
	Output            string
}

// Arch maps a Go GOARCH value to the matching RPM architecture tag.
func Arch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return goarch
	}
}

// Write builds an RPM package from the supplied options.
func Write(o Options) error {
	requires, err := packageRelations()
	if err != nil {
		return err
	}

	packageRPM, err := rpmpack.NewRPM(rpmpack.RPMMetaData{
		Name:        packageName,
		Summary:     summary,
		Description: description,
		Version:     o.Version,
		Release:     o.Release,
		Arch:        o.Arch,
		URL:         url,
		Licence:     o.License,
		Requires:    requires,
	})
	if err != nil {
		return err
	}

	if err := addPackageFiles(packageRPM, o); err != nil {
		return err
	}

	packageRPM.AddPostin(postinScript)
	packageRPM.AddPreun(preunScript)
	packageRPM.AddPostun(postunScript)

	destination, err := os.Create(o.Output)
	if err != nil {
		return err
	}
	if err := packageRPM.Write(destination); err != nil {
		_ = destination.Close()
		return err
	}
	return destination.Close()
}

// packageRelations builds the RPM's hard requires: the libvirt client library
// the binary links against, ca-certificates for outbound TLS, and the local KVM
// stack that hosts the virtual desktops. libvirt-daemon-kvm pulls in the modular
// libvirt daemons (virtqemud/virtnetworkd/virtstoraged) and qemu-kvm, so a fresh
// install can provision VMs out of the box.
func packageRelations() (requires rpmpack.Relations, err error) {
	for _, dependency := range []string{"libvirt-libs", "ca-certificates", "libvirt-daemon-kvm", "qemu-kvm"} {
		if err := requires.Set(dependency); err != nil {
			return nil, fmt.Errorf("add require %q: %w", dependency, err)
		}
	}
	return requires, nil
}

// packageFile describes one file in the RPM: its source path, install
// destination, permission bits, and rpmpack file classification.
type packageFile struct {
	source      string
	destination string
	mode        uint
	typeFlags   rpmpack.FileType
}

// packageFiles returns the install manifest. The config file is installed 0640
// (root read/write, no group or world read) because it can hold secrets such as
// SNI_HASH_SECRET. Combined with the root:root
// owner set in addPackageFiles, that keeps the file readable only by root. The
// remaining files carry no secrets and use the conventional world-readable
// modes. The LICENSE file is bundled when present; packaging tolerates its
// absence (e.g. out-of-tree builds) rather than failing.
func packageFiles(o Options) []packageFile {
	files := []packageFile{
		{o.BinarySource, o.BinaryDestination, 0o755, rpmpack.GenericFile},
		{o.UnitSource, unitDestination, 0o644, rpmpack.GenericFile},
		{o.ConfigSource, confDestination, 0o640, rpmpack.ConfigFile | rpmpack.NoReplaceFile},
	}
	if _, err := os.Stat(o.LicenseSource); err == nil {
		files = append(files, packageFile{o.LicenseSource, licenseDest, 0o644, rpmpack.LicenceFile})
	}
	return files
}

// addPackageFiles adds the binary, systemd unit, sample config file, and (when
// present) the license to the RPM, all stamped with the binary's mtime so the
// package is reproducible for a given build artifact. The config file is marked
// %config(noreplace) so operator edits survive upgrades.
func addPackageFiles(packageRPM *rpmpack.RPM, o Options) error {
	info, err := os.Stat(o.BinarySource)
	if err != nil {
		return err
	}
	// RPM MTime is uint32 epoch seconds; reject mtimes outside that range instead
	// of silently wrapping them into the package metadata.
	unixMTime := info.ModTime().Unix()
	if unixMTime < 0 || unixMTime > math.MaxUint32 {
		return fmt.Errorf("binary mtime %v is outside the rpm uint32 epoch range", info.ModTime())
	}
	mtime := uint32(unixMTime)

	for _, file := range packageFiles(o) {
		body, err := os.ReadFile(file.source)
		if err != nil {
			return err
		}
		packageRPM.AddFile(rpmpack.RPMFile{
			Name:  file.destination,
			Body:  body,
			Mode:  file.mode,
			Owner: "root",
			Group: "root",
			MTime: mtime,
			Type:  file.typeFlags,
		})
	}
	return nil
}
