# Contributing

DevBox-Gateway and `SauronAgent/` share the root `go.mod` and `go.sum`.
Run the commands below from the repository root unless a command uses
`make -C SauronAgent`.

## Prerequisites

- Linux with Go at the version required by [go.mod](go.mod), Git and Make.
- A C compiler, `pkg-config` and libvirt development headers for gateway builds
  and tests (`libvirt-dev` on Debian/Ubuntu, `libvirt-devel` on Fedora/RHEL).
- Node.js and TypeScript 5.5.4 on `PATH` for local dashboard builds. The
  [Dockerfiles](Dockerfile) install this compiler version inside container builds.
- Docker and Docker Compose v2 for the local stack and tests that launch
  temporary services; Docker Buildx for native package builds.
- A QEMU/KVM and libvirt test host with permission to access `qemu:///system`,
  create domains, storage pools and network filters, and use their files.
  Live vsock tests also need `/dev/vhost-vsock` and an available AF_VSOCK
  listener; some skip when the host does not support them.
- Python 3 for tests of the guest provisioning script; those tests skip if it
  is unavailable.

Use a development hypervisor: integration tests create and remove real libvirt
resources. See [libvirt and VM storage](page/docs/configuration/storage.md) for the
runtime requirements. The [CI workflow](.github/workflows/go.yml) shows the test
host setup; its relaxed libvirt permissions are for an isolated CI runner.
Initial tests may download a large VM image and container images.

## Get started

```sh
git clone https://github.com/define42/DevBox-Gateway.git
cd DevBox-Gateway
go mod download
make build
```

`make build` compiles `ui/dashboard.ts` into the embedded
`internal/webassets/dashboard.js`, then writes the gateway binary to
`dist/devbox-gateway`. After changing UI source, rebuild and include the updated
bundle in the same change:

```sh
tsc -p tsconfig.json
```

To run the local stack, first prepare the host described in
[Quick start](page/docs/installation/docker-compose.md), then run:

```sh
make run
```

This stops the existing Compose services, rebuilds the gateway image, and starts
the gateway, LDAP fixture and Splunk. Open `https://localhost`, accept the local
self-signed certificate, and sign in with `johndoe` / `dogood`. Successful login
opens `/api/dashboard`. These credentials and the bundled TLS settings are for
local development. See the README for the bundled Splunk configuration and terms.

For work limited to the guest agent or standalone collector, use:

```sh
make -C SauronAgent build
make -C SauronAgent test
make -C SauronAgent test-race
```

The build writes static `sauronagent` and `sauronhost` binaries under
`SauronAgent/bin/`. These builds share the root dependency versions and do not
need the gateway's libvirt headers. Deployment and protocol details are in
[SauronAgent/README.md](SauronAgent/README.md).

## VM image changes

Image sources live in `images/<variant>/`; generated disks belong in
`dist/images/`, and downloads are cached in `.cache/images/`. For the Ubuntu
26.04 XFCE image, run:

```sh
make image-check IMAGE=ubuntu26.04-xfce
make image IMAGE=ubuntu26.04-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=ubuntu26.04-xfce IMAGE_VERSION=0.0.0
```

Use `IMAGE=ubuntu24.04-xfce` or `IMAGE=rocky9-xfce` with the same targets to build
and test Ubuntu 24.04 XFCE or Rocky Linux 9 XFCE. `IMAGE` defaults to
`ubuntu26.04-xfce` when omitted.

The syntax and upload-source check is quick. The full build requires Linux
x86_64, Docker access, Bash, curl, Python 3, `flock`, `sha256sum`, Git, Make, and
the root module's Go toolchain. It builds the SauronAgent deb or RPM from this
checkout and installs it into the selected desktop image. KVM is optional but
speeds up the build.
The smoke test needs host `qemu-system-x86_64`, `qemu-img`, `xorriso`, and `timeout`
and boots a temporary overlay without modifying the base image. See the
[Ubuntu 26.04](images/ubuntu26.04-xfce/README.md),
[Ubuntu 24.04](images/ubuntu24.04-xfce/README.md), and
[Rocky](images/rocky9-xfce/README.md) image READMEs for artifact paths and
guest configuration.

## Checks before a pull request

Run the full test target before submitting changes:

```sh
make test
```

This includes both the gateway and SauronAgent, writes `coverage.out` and
`coverage.html`, and enforces 80% aggregate coverage by default. The target uses
`-p=1` because multiple packages share the system libvirt daemon. Keep that
setting for full-suite commands, and do not run concurrent libvirt test suites
against the same host.

For changes to linting, authentication or request handling, also run:

```sh
make lint
go test -race -p=1 -timeout=15m ./...
```

The longer race-test timeout allows for VM image copies and guest startup. Use
a larger timeout if required by the test host. Report any skipped tests or
missing services alongside the result.

Other checks used by CI are:

```sh
make gosec
go vet ./...
go run golang.org/x/vuln/cmd/govulncheck@latest ./...
```

`make lint` runs `golangci-lint` for `./cmd/...` and `./internal/...`, then
`go vet` for SauronAgent. `make gosec` scans the gateway packages; the root vet
and vulnerability commands cover the full module. Pull-request CI also builds
and validates gateway deb and RPM packages with `make deb rpm VERSION=0.0.0`.
See [building from source](page/docs/development/building.md) for packaging details.

## Code and documentation

- Use `gofmt`, idiomatic Go names, focused handlers and helpers, and co-located
  `*_test.go` files. Prefer table-driven tests for branching behavior.
- Explain constraints and failure behavior in exported API comments. Update the
  relevant guides in [page/docs/](page/docs/index.md) and SauronAgent docs when
  configuration or behavior changes. Keep the README focused on the project
  overview and getting started. Follow the [documentation development guide](page/docs/development/documentation.md)
  to preview the site and run its strict build before submitting documentation changes.
- Define environment-backed parameters in `internal/config/config.go` using
  its settings pattern. Do not read environment variables directly in feature
  code or add global configuration parameters.
- Keep dependencies in the root module. Run `go mod tidy` after dependency
  changes and include the resulting `go.mod` and `go.sum` updates.
- Keep real credentials, private keys, certificates and production LDAP
  endpoints out of commits.

## Commits, pull requests and releases

Keep commits focused and use short, specific messages. A pull request should
explain the behavior change, list commands run and their results, and include
screenshots when the dashboard or login flow changes.

The [release workflow](.github/workflows/go.yml) creates version tags and GitHub
Releases with generated release notes, builds gateway and SauronAgent packages,
and publishes gateway container images after pushes to `main`. It calls the
[Ubuntu 26.04 image workflow](.github/workflows/ubuntu26.04-xfce.yml),
[Ubuntu 24.04 image workflow](.github/workflows/ubuntu24.04-xfce.yml), and
[Rocky image workflow](.github/workflows/rocky9-xfce.yml) with the same version
to build and boot-test all three images. Release publication waits for the
gateway and all three image jobs to succeed, then attaches the packages, split
image parts, image checksums, and build manifests to one `vMAJOR.MINOR.PATCH` release.
The SauronAgent installed in each image also uses that release version. Describe
changes in commit and pull-request text so the release notes are useful.

Each image workflow also runs for relevant image, build, and SauronAgent changes
on pull requests, using version `0.0.0`, and supports manual runs with a numeric
`MAJOR.MINOR.PATCH` version input that defaults to `0.0.0`. These standalone runs
publish workflow artifacts only; they do not create tags or GitHub Releases.

Preserve the existing license boundaries: the gateway has an
[MIT license](LICENSE), while `SauronAgent/` has an
[Apache-2.0 license](SauronAgent/LICENSE). Bundled browser assets retain their own
license files.
