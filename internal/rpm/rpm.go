// Package rpm builds RPM packages. Write builds the DevBox Gateway package from
// Options; WritePackage builds any other package in this repository (such as
// SauronAgent, see cmd/mksauronagent) from a Package description.
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

// Package describes an RPM to build: its metadata, payload, and scriptlets.
// Scriptlets follow rpm conventions ($1 is the number of package instances left
// after the transaction) and are omitted from the package when empty.
type Package struct {
	Name        string
	Version     string
	Release     string
	Arch        string
	Summary     string
	Description string
	URL         string
	License     string
	Requires    []string
	// Files is the payload. Every file is stamped with the mtime of Files[0]
	// (the main binary), so the package is reproducible for a given build
	// artifact.
	Files  []File
	PostIn string
	PreUn  string
	PostUn string
	Output string
}

// File is one payload entry: its source path on the build host, absolute
// install destination, permission bits, and rpmpack file classification
// (%config(noreplace), %doc, %license, ...). Files are always owned root:root.
type File struct {
	Source      string
	Destination string
	Mode        uint
	Type        rpmpack.FileType
}

// Write builds the DevBox Gateway RPM from the supplied options.
func Write(o Options) error {
	return WritePackage(Package{
		Name:        packageName,
		Version:     o.Version,
		Release:     o.Release,
		Arch:        o.Arch,
		Summary:     summary,
		Description: description,
		URL:         url,
		License:     o.License,
		Requires:    packageRequires(),
		Files:       packageFiles(o),
		PostIn:      postinScript,
		PreUn:       preunScript,
		PostUn:      postunScript,
		Output:      o.Output,
	})
}

// WritePackage builds an RPM package from p.
func WritePackage(p Package) error {
	requires, err := relations(p.Requires)
	if err != nil {
		return err
	}

	packageRPM, err := rpmpack.NewRPM(rpmpack.RPMMetaData{
		Name:        p.Name,
		Summary:     p.Summary,
		Description: p.Description,
		Version:     p.Version,
		Release:     p.Release,
		Arch:        p.Arch,
		URL:         p.URL,
		Licence:     p.License,
		Requires:    requires,
	})
	if err != nil {
		return err
	}

	if err := addFiles(packageRPM, p.Files); err != nil {
		return err
	}

	if p.PostIn != "" {
		packageRPM.AddPostin(p.PostIn)
	}
	if p.PreUn != "" {
		packageRPM.AddPreun(p.PreUn)
	}
	if p.PostUn != "" {
		packageRPM.AddPostun(p.PostUn)
	}

	destination, err := os.Create(p.Output)
	if err != nil {
		return err
	}
	if err := packageRPM.Write(destination); err != nil {
		_ = destination.Close()
		return err
	}
	return destination.Close()
}

// packageRequires are the DevBox Gateway RPM's hard requires. The nwfilter
// driver and its firewall tools are mandatory alongside the local KVM stack;
// VM network protection must not depend on optional package recommendations.
func packageRequires() []string {
	return []string{"libvirt-libs", "ca-certificates", "libvirt-daemon-kvm", "libvirt-daemon-driver-nwfilter", "qemu-kvm"}
}

// relations converts plain package names into rpmpack requires.
func relations(names []string) (requires rpmpack.Relations, err error) {
	for _, dependency := range names {
		if err := requires.Set(dependency); err != nil {
			return nil, fmt.Errorf("add require %q: %w", dependency, err)
		}
	}
	return requires, nil
}

// packageFiles returns the install manifest. The config file is installed 0640
// (root read/write, no group or world read) because it can hold secrets such as
// SNI_HASH_SECRET. Combined with the root:root
// owner set in addFiles, that keeps the file readable only by root. The
// remaining files carry no secrets and use the conventional world-readable
// modes. The LICENSE file is bundled when present; packaging tolerates its
// absence (e.g. out-of-tree builds) rather than failing.
func packageFiles(o Options) []File {
	files := []File{
		{o.BinarySource, o.BinaryDestination, 0o755, rpmpack.GenericFile},
		{o.UnitSource, unitDestination, 0o644, rpmpack.GenericFile},
		{o.ConfigSource, confDestination, 0o640, rpmpack.ConfigFile | rpmpack.NoReplaceFile},
	}
	if _, err := os.Stat(o.LicenseSource); err == nil {
		files = append(files, File{o.LicenseSource, licenseDest, 0o644, rpmpack.LicenceFile})
	}
	return files
}

// addFiles adds the payload to the RPM, all owned root:root and stamped with
// the mtime of files[0] (the main binary) so the package is reproducible for a
// given build artifact. Config files are marked through their Type, e.g.
// %config(noreplace) so operator edits survive upgrades.
func addFiles(packageRPM *rpmpack.RPM, files []File) error {
	if len(files) == 0 {
		return fmt.Errorf("rpm payload is empty")
	}
	info, err := os.Stat(files[0].Source)
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

	for _, file := range files {
		body, err := os.ReadFile(file.Source)
		if err != nil {
			return err
		}
		packageRPM.AddFile(rpmpack.RPMFile{
			Name:  file.Destination,
			Body:  body,
			Mode:  file.Mode,
			Owner: "root",
			Group: "root",
			MTime: mtime,
			Type:  file.Type,
		})
	}
	return nil
}
