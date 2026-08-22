// Command mkrpm packages the prebuilt devbox-gateway binary together with its
// systemd unit, sample config file, and license into an RPM using the
// pure-Go github.com/google/rpmpack. No rpmbuild, spec file, or Go toolchain is
// needed in a buildroot, so the package can be produced on any build host. It is
// invoked by the Makefile `rpm` target after `make build`.
package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"

	"github.com/define42/devbox-gateway/internal/rpm"
)

const packageName = "devbox-gateway"

func main() {
	o := rpm.Options{}
	flag.StringVar(&o.Version, "version", "0.0.0", "package version")
	flag.StringVar(&o.Release, "release", "1", "package release")
	flag.StringVar(&o.Arch, "arch", rpm.Arch(runtime.GOARCH), "package architecture")
	flag.StringVar(&o.License, "licence", "Proprietary", "license tag for the RPM metadata")
	flag.StringVar(&o.BinarySource, "binary", "dist/devbox-gateway", "path to the prebuilt binary")
	flag.StringVar(&o.BinaryDestination, "binary-dest", "/usr/bin/devbox-gateway", "install path for the binary")
	flag.StringVar(&o.UnitSource, "unit", "devbox-gateway.service", "path to the systemd unit file")
	flag.StringVar(&o.ConfigSource, "conf", "devbox-gateway.conf", "path to the sample config file")
	flag.StringVar(&o.LicenseSource, "license", "LICENSE", "path to the license file (skipped if it does not exist)")
	flag.StringVar(&o.Output, "out", "", "output rpm path (default dist/<name>-<version>-<release>.<arch>.rpm)")
	flag.Parse()

	if o.Output == "" {
		o.Output = fmt.Sprintf("dist/%s-%s-%s.%s.rpm", packageName, o.Version, o.Release, o.Arch)
	}

	if err := rpm.Write(o); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", o.Output)
}
