// Command mkdeb packages the prebuilt devbox-gateway binary together with its
// systemd unit, sample config file, and license into a Debian .deb. No dpkg-deb,
// debian/ tree, or Go toolchain is needed in a buildroot, so the package can be
// produced on any build host. It is invoked by the Makefile `deb` target after
// `make build` and mirrors the sibling cmd/mkrpm command.
package main

import (
	"flag"
	"fmt"
	"log"
	"runtime"

	"github.com/define42/devbox-gateway/internal/deb"
)

const packageName = "devbox-gateway"

func main() {
	o := deb.Options{}
	flag.StringVar(&o.Version, "version", "0.0.0", "package version")
	flag.StringVar(&o.Arch, "arch", deb.Arch(runtime.GOARCH), "package architecture")
	flag.StringVar(&o.BinarySource, "binary", "dist/devbox-gateway", "path to the prebuilt binary")
	flag.StringVar(&o.BinaryDestination, "binary-dest", "/usr/bin/devbox-gateway", "install path for the binary")
	flag.StringVar(&o.UnitSource, "unit", "devbox-gateway.service", "path to the systemd unit file")
	flag.StringVar(&o.ConfigSource, "conf", "devbox-gateway.conf", "path to the sample config file")
	flag.StringVar(&o.LicenseSource, "license", "LICENSE", "path to the license file (skipped if it does not exist)")
	flag.StringVar(&o.Output, "out", "", "output deb path (default dist/<name>_<version>_<arch>.deb)")
	flag.Parse()

	if o.Output == "" {
		o.Output = fmt.Sprintf("dist/%s_%s_%s.deb", packageName, o.Version, o.Arch)
	}

	if err := deb.Write(o); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", o.Output)
}
