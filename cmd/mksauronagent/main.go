// Command mksauronagent packages the prebuilt SauronAgent binaries (the guest
// audit agent and the hypervisor collector built from ./SauronAgent) together
// with their systemd units, sysusers/tmpfiles entries, example configs, docs,
// and license into an RPM or a Debian .deb, using the same pure-Go writers as
// cmd/mkrpm and cmd/mkdeb. It is invoked by the Makefile `sauron-rpm` and
// `sauron-deb` targets after SauronAgent's own `make build`.
package main

import (
	"flag"
	"fmt"
	"log"

	"github.com/define42/devbox-gateway/internal/sauronpkg"
)

func main() {
	o := sauronpkg.Options{}
	format := flag.String("format", "rpm", "package format: rpm or deb")
	flag.StringVar(&o.Version, "version", "0.0.0", "package version")
	flag.StringVar(&o.Release, "release", "1", "package release (rpm only)")
	flag.StringVar(&o.Arch, "arch", "", "package architecture (default: the build host's, in the format's spelling)")
	flag.StringVar(&o.Source, "src", "SauronAgent", "path to the SauronAgent source tree")
	flag.StringVar(&o.BinDir, "bindir", "", "directory holding the prebuilt sauronagent and sauronhost binaries (default <src>/bin)")
	flag.StringVar(&o.Output, "out", "", "output path (default dist/sauronagent-<version>-<release>.<arch>.rpm or dist/sauronagent_<version>_<arch>.deb)")
	flag.Parse()

	output, err := sauronpkg.Write(*format, o)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("wrote %s\n", output)
}
