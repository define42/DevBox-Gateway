// Package deb builds Debian packages. Write builds the DevBox Gateway package
// from Options; WritePackage builds any other package in this repository (such
// as SauronAgent, see cmd/mksauronagent) from a Package description.
package deb

// Maintainer is the Maintainer field of every package built in this repository.
const Maintainer = "define42 <define42@users.noreply.github.com>"

const (
	packageName = "devbox-gateway"
	summary     = "DevBox Gateway for libvirt-backed development desktops"
	description = "DevBox Gateway publishes libvirt-managed development desktops over a single HTTPS port. It terminates TLS from RDP clients, routes each connection to a backend VM by TLS SNI, and re-establishes TLS to that backend. The same port also serves an LDAP-authenticated web dashboard for self-service VM lifecycle management, in-browser serial and noVNC consoles, and downloadable .rdp connection files."
	url         = "https://github.com/define42/devbox-gateway"
	section     = "net"

	confDestination = "/etc/devbox-gateway/devbox-gateway.conf"
	unitDestination = "/lib/systemd/system/devbox-gateway.service"
	licenseDest     = "/usr/share/doc/devbox-gateway/copyright"
)

// The service runs as root (it binds :443 and talks to libvirt), so no dedicated
// user is created. These maintainer scripts mirror the internal/rpm scriptlets
// but follow Debian's argument conventions
// (https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html): reload on
// configure, apply preset policy only on the initial install (postinst's $2 is
// empty when no previous version was configured), restart on upgrade, and disable
// on final removal.
//
// preset (rather than a forced enable) honors the host's systemd preset policy,
// so installing the package enables the unit only where policy allows and never
// starts it; an operator still runs `systemctl start` (or reboots) to launch it.
const postinstScript = `#!/bin/sh
set -e
if [ "$1" = "configure" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
    if [ -z "$2" ]; then
        systemctl --no-reload preset devbox-gateway.service || :
    else
        systemctl try-restart devbox-gateway.service || :
    fi
fi
`

const prermScript = `#!/bin/sh
set -e
if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now devbox-gateway.service || :
fi
`

const postrmScript = `#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi
`

// Options describes the inputs and metadata needed to build a Debian package.
type Options struct {
	Version           string
	Arch              string
	BinarySource      string
	BinaryDestination string
	UnitSource        string
	ConfigSource      string
	LicenseSource     string
	Output            string
}

// Arch maps a Go GOARCH value to the matching Debian architecture tag. Unlike
// RPM, Debian keeps amd64/arm64 as-is and only renames 386 and arm.
func Arch(goarch string) string {
	switch goarch {
	case "386":
		return "i386"
	case "arm":
		return "armhf"
	default:
		return goarch
	}
}

// Package describes a .deb to build: its control metadata, payload, and
// maintainer scripts. Scripts follow Debian's argument conventions
// (https://www.debian.org/doc/debian-policy/ch-maintainerscripts.html) and are
// omitted from the package when empty, as is an empty Depends field.
type Package struct {
	Name        string
	Version     string
	Arch        string
	Maintainer  string
	Section     string
	Homepage    string
	Depends     string
	Summary     string
	Description string
	Files       []File
	Postinst    string
	Prerm       string
	Postrm      string
	Output      string
}

// File is one payload entry: its source path on the build host, absolute
// install destination, and permission bits. Modes are fixed here rather than
// copied from the source files so the package is deterministic regardless of
// the build checkout's umask; every entry is owned root:root. Conffile lists
// the file in the package's conffiles, so dpkg preserves operator edits.
type File struct {
	Source      string
	Destination string
	Mode        int64
	Conffile    bool
}

// Write builds the DevBox Gateway .deb from the supplied options.
func Write(o Options) error {
	files, err := packageFiles(o)
	if err != nil {
		return err
	}
	abiDepends, err := binaryDependencies(o.BinarySource)
	if err != nil {
		return err
	}
	return WritePackage(Package{
		Name:        packageName,
		Version:     o.Version,
		Arch:        o.Arch,
		Maintainer:  Maintainer,
		Section:     section,
		Homepage:    url,
		Depends:     abiDepends + ", " + packageRelations(),
		Summary:     summary,
		Description: description,
		Files:       files,
		Postinst:    postinstScript,
		Prerm:       prermScript,
		Postrm:      postrmScript,
		Output:      o.Output,
	})
}

// WritePackage builds a Debian package from p.
func WritePackage(p Package) error {
	return writeArchive(p)
}

// packageRelations builds the .deb's Depends field. The nwfilter config package
// pulls in the separate driver on newer Debian releases; older releases include
// that driver in libvirt-daemon, already required by libvirt-daemon-system.
// iptables also supplies the ebtables frontend required by the host filter.
func packageRelations() string {
	return "libvirt0, ca-certificates, libvirt-daemon-system, libvirt-daemon-config-nwfilter, iptables, qemu-system-x86"
}
