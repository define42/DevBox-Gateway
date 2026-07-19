// Command mkrpm packages the prebuilt devbox-gateway binary together with its
// systemd unit, sample config file, and license into an RPM using the
// pure-Go github.com/google/rpmpack. No rpmbuild, spec file, or Go toolchain is
// needed in a buildroot, so the package can be produced on any build host. It is
// invoked by the makefile `rpm` target after `make build`.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"

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

type options struct {
	version    string
	release    string
	arch       string
	licence    string
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
	flag.StringVar(&o.release, "release", "1", "package release")
	flag.StringVar(&o.arch, "arch", rpmArch(runtime.GOARCH), "package architecture")
	flag.StringVar(&o.licence, "licence", "Proprietary", "license tag for the RPM metadata")
	flag.StringVar(&o.binarySrc, "binary", "dist/devbox-gateway", "path to the prebuilt binary")
	flag.StringVar(&o.binaryDest, "binary-dest", "/usr/bin/devbox-gateway", "install path for the binary")
	flag.StringVar(&o.unitSrc, "unit", "devbox-gateway.service", "path to the systemd unit file")
	flag.StringVar(&o.confSrc, "conf", "devbox-gateway.conf", "path to the sample config file")
	flag.StringVar(&o.licenseSrc, "license", "LICENSE", "path to the license file (skipped if it does not exist)")
	flag.StringVar(&o.out, "out", "", "output rpm path (default dist/<name>-<version>-<release>.<arch>.rpm)")
	flag.Parse()

	if o.out == "" {
		o.out = fmt.Sprintf("dist/%s-%s-%s.%s.rpm", packageName, o.version, o.release, o.arch)
	}

	if err := writeRPM(o); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", o.out)
}

// rpmArch maps a Go GOARCH value to the matching RPM architecture tag.
func rpmArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	default:
		return goarch
	}
}

func writeRPM(o options) error {
	requires, err := packageRelations()
	if err != nil {
		return err
	}

	rpm, err := rpmpack.NewRPM(rpmpack.RPMMetaData{
		Name:        packageName,
		Summary:     summary,
		Description: description,
		Version:     o.version,
		Release:     o.release,
		Arch:        o.arch,
		URL:         url,
		Licence:     o.licence,
		Requires:    requires,
	})
	if err != nil {
		return err
	}

	if err := addPackageFiles(rpm, o); err != nil {
		return err
	}

	rpm.AddPostin(postinScript)
	rpm.AddPreun(preunScript)
	rpm.AddPostun(postunScript)

	dst, err := os.Create(o.out)
	if err != nil {
		return err
	}
	if err := rpm.Write(dst); err != nil {
		_ = dst.Close()
		return err
	}
	return dst.Close()
}

// packageRelations builds the RPM's hard requires: the libvirt client library
// the binary links against, ca-certificates for outbound TLS, and the local KVM
// stack that hosts the virtual desktops. libvirt-daemon-kvm pulls in the modular
// libvirt daemons (virtqemud/virtnetworkd/virtstoraged) and qemu-kvm, so a fresh
// install can provision VMs out of the box.
func packageRelations() (requires rpmpack.Relations, err error) {
	for _, dep := range []string{"libvirt-libs", "ca-certificates", "libvirt-daemon-kvm", "qemu-kvm"} {
		if err := requires.Set(dep); err != nil {
			return nil, fmt.Errorf("add require %q: %w", dep, err)
		}
	}
	return requires, nil
}

// packageFile describes one file in the RPM: its source path, install
// destination, permission bits, and rpmpack file classification.
type packageFile struct {
	src  string
	dest string
	mode uint
	typ  rpmpack.FileType
}

// packageFiles returns the install manifest. The config file is installed 0640
// (root read/write, no group or world read) because it can hold secrets: a
// LOCAL_USER_SHA256 list of password digests and the SSH tunnel key passphrase
// (SSH_TUNNEL_PRIVATE_KEY_PASSPHRASE). Combined with the root:root owner set in
// addPackageFiles, that keeps the file readable only by root. The remaining
// files carry no secrets and use the conventional world-readable modes. The
// repository does not ship a LICENSE file, so it is bundled only when present
// and packaging never fails on its absence.
func packageFiles(o options) []packageFile {
	files := []packageFile{
		{o.binarySrc, o.binaryDest, 0o755, rpmpack.GenericFile},
		{o.unitSrc, unitDestination, 0o644, rpmpack.GenericFile},
		{o.confSrc, confDestination, 0o640, rpmpack.ConfigFile | rpmpack.NoReplaceFile},
	}
	if _, err := os.Stat(o.licenseSrc); err == nil {
		files = append(files, packageFile{o.licenseSrc, licenseDest, 0o644, rpmpack.LicenceFile})
	}
	return files
}

// addPackageFiles adds the binary, systemd unit, sample config file, and (when
// present) the license to the RPM, all stamped with the binary's mtime so the
// package is reproducible for a given build artifact. The config file is marked
// %config(noreplace) so operator edits survive upgrades.
func addPackageFiles(rpm *rpmpack.RPM, o options) error {
	st, err := os.Stat(o.binarySrc)
	if err != nil {
		return err
	}
	mtime := uint32(st.ModTime().Unix()) //nolint:gosec // RPM MTime is uint32 epoch seconds; build-artifact mtimes are positive and well within range.

	for _, f := range packageFiles(o) {
		body, err := os.ReadFile(f.src)
		if err != nil {
			return err
		}
		rpm.AddFile(rpmpack.RPMFile{
			Name:  f.dest,
			Body:  body,
			Mode:  f.mode,
			Owner: "root",
			Group: "root",
			MTime: mtime,
			Type:  f.typ,
		})
	}
	return nil
}
