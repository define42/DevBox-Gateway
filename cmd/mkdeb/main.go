// Command mkdeb packages the prebuilt devbox-gateway binary together with its
// systemd unit, sample config file, and license into a Debian .deb. No dpkg-deb,
// debian/ tree, or Go toolchain is needed in a buildroot, so the package can be
// produced on any build host. It is invoked by the makefile `deb` target after
// `make build` and mirrors the sibling cmd/mkrpm command.
package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"
)

const (
	packageName = "devbox-gateway"
	summary     = "DevBox Gateway for libvirt-backed development desktops"
	description = "DevBox Gateway publishes libvirt-managed development desktops over a single HTTPS port. It terminates TLS from RDP clients, routes each connection to a backend VM by TLS SNI, and re-establishes TLS to that backend. The same port also serves an LDAP-authenticated web dashboard for self-service VM lifecycle management, in-browser serial and noVNC consoles, and downloadable .rdp connection files."
	url         = "https://github.com/define42/devbox-gateway"
	maintainer  = "define42"
	section     = "net"

	confDestination = "/etc/devbox-gateway/devbox-gateway.conf"
	unitDestination = "/lib/systemd/system/devbox-gateway.service"
	licenseDest     = "/usr/share/doc/devbox-gateway/copyright"
)

// The service runs as root (it binds :443 and talks to libvirt), so no dedicated
// user is created. These maintainer scripts mirror the cmd/mkrpm scriptlets but
// follow Debian's argument conventions
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

type options struct {
	version    string
	arch       string
	binarySrc  string
	binaryDest string
	unitSrc    string
	confSrc    string
	licenseSrc string
	out        string
}

func main() {
	o := options{}
	flag.StringVar(&o.version, "version", "0.0.0", "package version")
	flag.StringVar(&o.arch, "arch", debArch(runtime.GOARCH), "package architecture")
	flag.StringVar(&o.binarySrc, "binary", "dist/devbox-gateway", "path to the prebuilt binary")
	flag.StringVar(&o.binaryDest, "binary-dest", "/usr/bin/devbox-gateway", "install path for the binary")
	flag.StringVar(&o.unitSrc, "unit", "devbox-gateway.service", "path to the systemd unit file")
	flag.StringVar(&o.confSrc, "conf", "devbox-gateway.conf", "path to the sample config file")
	flag.StringVar(&o.licenseSrc, "license", "LICENSE", "path to the license file (skipped if it does not exist)")
	flag.StringVar(&o.out, "out", "", "output deb path (default dist/<name>_<version>_<arch>.deb)")
	flag.Parse()

	if o.out == "" {
		o.out = fmt.Sprintf("dist/%s_%s_%s.deb", packageName, o.version, o.arch)
	}

	if err := writeDeb(o); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", o.out)
}

// debArch maps a Go GOARCH value to the matching Debian architecture tag. Unlike
// RPM, Debian keeps amd64/arm64 as-is and only renames 386 and arm.
func debArch(goarch string) string {
	switch goarch {
	case "386":
		return "i386"
	case "arm":
		return "armhf"
	default:
		return goarch
	}
}

func writeDeb(o options) error {
	return writeDebArchive(o)
}

// packageRelations builds the .deb's Depends field: the libvirt client library
// the binary links against, ca-certificates for outbound TLS, and the local KVM
// stack that hosts the virtual desktops. libvirt-daemon-system pulls in the
// modular libvirt daemons and qemu-system-x86 provides qemu-kvm, so a fresh
// install can provision VMs out of the box. These are the Debian-named
// counterparts of the RPM requires in cmd/mkrpm.
func packageRelations() string {
	return "libvirt0, ca-certificates, libvirt-daemon-system, qemu-system-x86"
}
