// Package sauronpkg describes the SauronAgent RPM and Debian packages built from
// the SauronAgent/ tree. One sauronagent package carries both the guest audit
// agent and the hypervisor collector, laid out exactly as SauronAgent's own
// `make install PREFIX=/usr` lays them out, so its documented quick start ("make
// install ... or install the package") applies unchanged: install the package
// and enable the unit of the component this machine runs. The agent runs on its
// built-in defaults; the standalone collector also needs its .yaml.example
// copied and filled in. On DevBox Gateway hosts, leave sauronhost disabled:
// the gateway always provides the collector on AF_VSOCK port 9000. The formats
// are written by the same pure-Go internal/rpm and internal/deb writers that
// build the DevBox Gateway packages.
package sauronpkg

import (
	"fmt"
	"path"
	"path/filepath"
	"runtime"

	"github.com/define42/devbox-gateway/internal/deb"
	"github.com/define42/devbox-gateway/internal/rpm"
	"github.com/google/rpmpack"
)

// Name is the package name in both formats.
const Name = "sauronagent"

const (
	summary     = "SauronAgent guest audit agent and SauronHost hypervisor collector"
	description = "SauronAgent streams Linux audit events from inside KVM guests to the hypervisor over virtio-vsock. The guest agent (sauronagent) installs its built-in execution, identity, privilege and system-security audit policy with CAP_AUDIT_CONTROL, discovers private SSH directories with CAP_DAC_READ_SEARCH, reads the kernel audit multicast feed with CAP_AUDIT_READ, spools unacknowledged events to disk, and never speaks IP. No auditd or audit command-line tools are required. The hypervisor collector (sauronhost) identifies every guest by its VSOCK CID, deduplicates replays, and writes normalized JSON events to the journal, a file, or syslog. Install the package in each guest and enable sauronagent.service. On hypervisors without DevBox Gateway, also install the package and enable sauronhost.service. DevBox Gateway always provides its own collector on fixed AF_VSOCK port 9000; leave sauronhost.service disabled on gateway hosts to avoid a port conflict."
	url         = "https://github.com/define42/SauronAgent"
	licenseTag  = "Apache-2.0"
	debSection  = "admin"

	docDir       = "/usr/share/doc/" + Name
	unitDir      = "/usr/lib/systemd/system"
	sysusersConf = "/usr/lib/sysusers.d/" + Name + ".conf"
	tmpfilesConf = "/usr/lib/tmpfiles.d/" + Name + ".conf"

	rpmLicenseDest = "/usr/share/licenses/" + Name + "/LICENSE"
	debLicenseDest = docDir + "/copyright"
)

// Neither unit is preset or enabled on install: the package holds a guest agent
// and a hypervisor collector, and only the operator knows which one this machine
// should run (and the collector has no configuration until it is copied from
// its .example). The scriptlets therefore only create the service accounts and
// directories -- the sysusers/tmpfiles steps of the SauronAgent install guide --
// reload systemd, restart whichever unit was already running on upgrade, and
// stop both on final removal. Upgrades restart safely: unacknowledged agent
// events are in the spool, and the collector's peers reconnect and resend.
//
// Nothing is deleted on removal or purge. The spool and the collector's output
// hold audit evidence, and the system accounts may still own files.
const (
	setupAccounts = `if command -v systemd-sysusers >/dev/null 2>&1; then
    systemd-sysusers ` + sysusersConf + ` || :
fi
if command -v systemd-tmpfiles >/dev/null 2>&1; then
    systemd-tmpfiles --create ` + tmpfilesConf + ` || :
fi
`
	units = "sauronagent.service sauronhost.service"

	// $1 is the count of package instances that will remain after the
	// transaction (0 = final removal, 1 = initial install, >1 = upgrade).
	rpmPostin = setupAccounts + `if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi
`
	rpmPreun = `if [ "$1" = 0 ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now ` + units + ` || :
fi
`
	rpmPostun = `if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
    if [ "$1" -ge 1 ]; then
        systemctl try-restart ` + units + ` || :
    fi
fi
`

	// postinst's $2 is the previously configured version, empty on first
	// install.
	debPostinst = `#!/bin/sh
set -e
[ "$1" = "configure" ] || exit 0
` + setupAccounts + `if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
    if [ -n "$2" ]; then
        systemctl try-restart ` + units + ` || :
    fi
fi
`
	debPrerm = `#!/bin/sh
set -e
if [ "$1" = "remove" ] && command -v systemctl >/dev/null 2>&1; then
    systemctl --no-reload disable --now ` + units + ` || :
fi
`
	debPostrm = `#!/bin/sh
set -e
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || :
fi
`
)

// Options describes where the SauronAgent inputs live and what to build.
type Options struct {
	Version string
	Release string // rpm only
	// Arch defaults to the build host's architecture in the format's spelling
	// (x86_64 for rpm, amd64 for deb). Recognized CPU aliases are normalized to
	// the selected format in both metadata and default output filenames.
	Arch string
	// Source is the SauronAgent source tree holding packaging/, examples/,
	// docs/, README.md and LICENSE.
	Source string
	// BinDir holds the prebuilt sauronagent and sauronhost binaries; it
	// defaults to <Source>/bin, where SauronAgent's `make build` puts them.
	BinDir string
	// Output defaults to dist/sauronagent-<version>-<release>.<arch>.rpm or
	// dist/sauronagent_<version>_<arch>.deb.
	Output string
}

type kind int

const (
	plainFile kind = iota
	configFile
	docFile
	licenseFile
)

// file is one format-neutral manifest entry.
type file struct {
	source      string
	destination string
	mode        uint32
	kind        kind
}

// manifest mirrors SauronAgent's `make install PREFIX=/usr`. The binary comes
// first so the rpm writer stamps every file with its mtime. The agent needs no
// configuration file. The collector's example config is installed as a .example
// file, never as the live configuration, exactly as make install does; it is
// still marked as a config file because it lives in /etc.
func manifest(o Options, licenseDest string) []file {
	binDir := o.BinDir
	if binDir == "" {
		binDir = filepath.Join(o.Source, "bin")
	}
	src := func(name string) string { return filepath.Join(o.Source, filepath.FromSlash(name)) }

	files := []file{
		{filepath.Join(binDir, "sauronagent"), "/usr/bin/sauronagent", 0o755, plainFile},
		{filepath.Join(binDir, "sauronhost"), "/usr/bin/sauronhost", 0o755, plainFile},
		{src("packaging/systemd/sauronagent.service"), unitDir + "/sauronagent.service", 0o644, plainFile},
		{src("packaging/systemd/sauronhost.service"), unitDir + "/sauronhost.service", 0o644, plainFile},
		{src("packaging/systemd/sauronagent.sysusers.conf"), sysusersConf, 0o644, plainFile},
		{src("packaging/systemd/sauronagent.tmpfiles.conf"), tmpfilesConf, 0o644, plainFile},
		{src("examples/sauronhost.yaml"), "/etc/sauronhost/sauronhost.yaml.example", 0o644, configFile},
	}
	for _, name := range []string{"README.md", "docs/protocol.md", "docs/security.md", "docs/deployment.md", "examples/qemu-vsock.md"} {
		files = append(files, file{src(name), docDir + "/" + path.Base(name), 0o644, docFile})
	}
	return append(files, file{src("LICENSE"), licenseDest, 0o644, licenseFile})
}

// rpmFileType maps a manifest kind to its rpm file classification.
func rpmFileType(k kind) rpmpack.FileType {
	switch k {
	case configFile:
		return rpmpack.ConfigFile | rpmpack.NoReplaceFile
	case docFile:
		return rpmpack.DocFile
	case licenseFile:
		return rpmpack.LicenceFile
	case plainFile:
		return rpmpack.GenericFile
	}
	return rpmpack.GenericFile
}

// RPM returns the rpm description of the package, with defaults applied.
func RPM(o Options) rpm.Package {
	arch := o.Arch
	if arch == "" {
		arch = rpm.Arch(runtime.GOARCH)
	}
	arch = rpmArchitecture(arch)
	output := o.Output
	if output == "" {
		output = fmt.Sprintf("dist/%s-%s-%s.%s.rpm", Name, o.Version, o.Release, arch)
	}

	var files []rpm.File
	for _, f := range manifest(o, rpmLicenseDest) {
		files = append(files, rpm.File{Source: f.source, Destination: f.destination, Mode: uint(f.mode), Type: rpmFileType(f.kind)})
	}

	return rpm.Package{
		Name:        Name,
		Version:     o.Version,
		Release:     o.Release,
		Arch:        arch,
		Summary:     summary,
		Description: description,
		URL:         url,
		License:     licenseTag,
		Files:       files,
		PostIn:      rpmPostin,
		PreUn:       rpmPreun,
		PostUn:      rpmPostun,
		Output:      output,
	}
}

// Deb returns the Debian description of the package, with defaults applied.
// The binaries are static (CGO_ENABLED=0), so there is no Depends field.
func Deb(o Options) deb.Package {
	arch := o.Arch
	if arch == "" {
		arch = deb.Arch(runtime.GOARCH)
	}
	arch = debArchitecture(arch)
	output := o.Output
	if output == "" {
		output = fmt.Sprintf("dist/%s_%s_%s.deb", Name, o.Version, arch)
	}

	var files []deb.File
	for _, f := range manifest(o, debLicenseDest) {
		files = append(files, deb.File{Source: f.source, Destination: f.destination, Mode: int64(f.mode), Conffile: f.kind == configFile})
	}

	return deb.Package{
		Name:        Name,
		Version:     o.Version,
		Arch:        arch,
		Maintainer:  deb.Maintainer,
		Section:     debSection,
		Homepage:    url,
		Summary:     summary,
		Description: description,
		Files:       files,
		Postinst:    debPostinst,
		Prerm:       debPrerm,
		Postrm:      debPostrm,
		Output:      output,
	}
}

// Write builds the package in the given format ("rpm" or "deb") and returns the
// path it was written to.
func Write(format string, o Options) (string, error) {
	switch format {
	case "rpm":
		p := RPM(o)
		if err := validateBinaries(o, p.Arch); err != nil {
			return "", err
		}
		return p.Output, rpm.WritePackage(p)
	case "deb":
		p := Deb(o)
		if err := validateBinaries(o, p.Arch); err != nil {
			return "", err
		}
		return p.Output, deb.WritePackage(p)
	default:
		return "", fmt.Errorf("unknown package format %q (want rpm or deb)", format)
	}
}
