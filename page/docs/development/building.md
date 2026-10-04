# Building from source

Requirements for a local development binary:

- Go (see `go.mod` for the minimum version).
- A C toolchain and `libvirt-dev` headers (the binary is built with
  `CGO_ENABLED=1`).
- Node.js + TypeScript 5.5.4 for the dashboard bundle.

Build the dashboard bundle and the binary locally:

```sh
tsc -p tsconfig.json          # compile ui/dashboard.ts → internal/webassets/dashboard.js
CGO_ENABLED=1 go build -o devbox-gateway ./cmd/devbox-gateway
```

`make build` performs both steps and writes the binary to `dist/devbox-gateway`.
This binary links against the build host's libraries. Use the native package
targets below to build distributable packages against their supported baselines.

Or build the production container image:

```sh
docker compose build
```

The multi-stage [Dockerfile](https://github.com/define42/DevBox-Gateway/blob/main/Dockerfile) compiles the TypeScript UI and the Go
binary in a Go/Alpine builder. Its `GO_VERSION` and `ALPINE_VERSION` build
arguments select the image tags; the root `go.mod` specifies the required Go
version. The Alpine runtime contains the gateway binary, `libvirt-libs`, and
`ca-certificates`.

## Building the RPM

Gateway native package builds require Docker with Buildx on the host. Go, the
C toolchain, libvirt headers, and TypeScript 5.5.4 run inside
[`Dockerfile.native`](https://github.com/define42/DevBox-Gateway/blob/main/Dockerfile.native); the Go version comes from `go.mod`.
Both package formats currently support Linux amd64 only (`ARCH=x86_64` and
`DEB_ARCH=amd64`). Other architecture overrides are rejected.

To produce the same RPM the [release workflow](../installation/rpm.md#installing-the-rpm) publishes,
run (overriding `VERSION` as needed):

```sh
make rpm VERSION=1.4.0
```

This compiles the UI and a `CGO_ENABLED=1` binary against Rocky Linux 9's
libraries, then packages it together with the systemd unit and
`devbox-gateway.conf` into `dist/devbox-gateway-<version>-1.x86_64.rpm`. The
[`cmd/mkrpm`](https://github.com/define42/DevBox-Gateway/blob/main/cmd/mkrpm) command uses RPM's `elfdeps` scanner to declare the
binary's actual ABI requirements and the pure-Go [`internal/rpm`](https://github.com/define42/DevBox-Gateway/blob/main/internal/rpm)
writer to create the archive. The container build installs the package with
`dnf` and checks dynamic linking and process startup before exporting it.

## Building the deb

To produce the same `.deb` the [release workflow](../installation/deb.md#installing-the-deb) publishes,
run (overriding `VERSION` as needed):

```sh
make deb VERSION=1.4.0
```

This builds a separate binary against Debian 12's libraries and writes
`dist/devbox-gateway_<version>_amd64.deb`. The [`cmd/mkdeb`](https://github.com/define42/DevBox-Gateway/blob/main/cmd/mkdeb) command
uses `dpkg-shlibdeps` to derive minimum library package versions and the
pure-Go [`internal/deb`](https://github.com/define42/DevBox-Gateway/blob/main/internal/deb) writer to create the archive. The
container build installs the package with `apt` and checks dynamic linking and
process startup before exporting it. Neither native package target reuses a
binary built on the host. CI runs both builds for pull requests and releases.

## Building the SauronAgent packages

To produce the same SauronAgent packages the
[release workflow](../installation/sauronagent.md#installing-sauronagent) publishes, run (overriding `VERSION`
as needed):

```sh
make sauron-rpm VERSION=1.4.0
make sauron-deb VERSION=1.4.0
```

This builds the static `sauronagent` and `sauronhost` binaries with
SauronAgent's own Makefile into separate directories under `SauronAgent/bin/`
for each package format and architecture, then packages them into
`dist/sauronagent-<version>-1.x86_64.rpm` / `dist/sauronagent_<version>_amd64.deb`
through the [`cmd/mksauronagent`](https://github.com/define42/DevBox-Gateway/blob/main/cmd/mksauronagent) command, which reuses the
pure-Go `internal/rpm` and `internal/deb` writers. SauronAgent and the gateway
share the root Go module and its dependencies. The gateway also compiles in
the host collector from `SauronAgent/collector`. Both need the Go version
specified in the root `go.mod`. With an older local toolchain, prefix the
commands with `GOTOOLCHAIN=auto`.

For ARM64, use `make sauron-rpm ARCH=aarch64` or
`make sauron-deb DEB_ARCH=arm64`. The package targets select the matching Go
architecture automatically. The packaging command checks both executable ELF
headers and rejects binaries that do not match the requested architecture.
Recognized CPU aliases are normalized to the selected package format in metadata
and default filenames (for example, `-format deb -arch x86_64` produces `amd64`).

## Building VM images

VM image recipes live under [`images/`](https://github.com/define42/DevBox-Gateway/blob/main/images), with one directory per image
variant. The Ubuntu 26.04 XFCE, Ubuntu 24.04 XFCE, and Rocky Linux 9 XFCE recipes
build standalone QCOW2 desktop disks and install SauronAgent from the same
checkout, enabling its guest service.
Image builds run separately from gateway and container builds.

[GitHub Releases](https://github.com/define42/DevBox-Gateway/releases) publish
all three images alongside the gateway and SauronAgent packages under the same
`vMAJOR.MINOR.PATCH` tag. Each image filename and its
installed SauronAgent use that gateway release version. Publication waits for
all three images to build and pass their boot tests. For prebuilt downloads,
follow [Downloading VM images](../vm-images.md#downloading-vm-images).

On a Linux x86_64 host with Docker access, Bash, curl, Python 3, `flock`,
`sha256sum`, Git, Make, and the Go version specified in `go.mod`, run:

```sh
make image-check IMAGE=ubuntu26.04-xfce
make image IMAGE=ubuntu26.04-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=ubuntu26.04-xfce IMAGE_VERSION=0.0.0

make image-check IMAGE=ubuntu24.04-xfce
make image IMAGE=ubuntu24.04-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=ubuntu24.04-xfce IMAGE_VERSION=0.0.0

make image-check IMAGE=rocky9-xfce
make image IMAGE=rocky9-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=rocky9-xfce IMAGE_VERSION=0.0.0
```

`IMAGE` defaults to `ubuntu26.04-xfce` when omitted.

The build downloads the selected distribution's source image and a container
with the image customization tools. KVM speeds up customization; software
emulation works when `/dev/kvm` is absent but is considerably slower. The smoke
test additionally requires host `qemu-system-x86_64`, `qemu-img`, `xorriso`, and
`timeout`; it boots a temporary overlay and leaves the base image unchanged.

Output goes to `dist/images/<variant>/` as
`<variant>-v0.0.0.img`, with `.img.sha256` and
`.img.manifest.json` sidecars. The manifest records the build commit, source
checksum, builder container, and SauronAgent version. Downloads are cached under
`.cache/images/`. Both directories are ignored by Git. See the
[Ubuntu 26.04 image README](https://github.com/define42/DevBox-Gateway/blob/main/images/ubuntu26.04-xfce/README.md),
[Ubuntu 24.04 image README](https://github.com/define42/DevBox-Gateway/blob/main/images/ubuntu24.04-xfce/README.md), and
[Rocky image README](https://github.com/define42/DevBox-Gateway/blob/main/images/rocky9-xfce/README.md) for contents, release
downloads, and gateway installation.

## UI (TypeScript)

The dashboard UI source lives in `ui/dashboard.ts`. Rebuild the embedded asset
with:

```sh
tsc -p tsconfig.json
```

The compiled output is `internal/webassets/dashboard.js` and is embedded into the binary
via Go's `embed` package.
