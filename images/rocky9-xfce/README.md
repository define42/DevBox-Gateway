# Rocky Linux 9 XFCE image

Builds an amd64 Rocky Linux 9 desktop image for DevBox Gateway from Rocky's
official GenericCloud Base image. The desktop recipe and SauronAgent are built
together from this repository.

## Build and check

Run from the repository root:

```sh
make image-check IMAGE=rocky9-xfce
make image IMAGE=rocky9-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=rocky9-xfce IMAGE_VERSION=0.0.0
```

`IMAGE_VERSION` must be a numeric `MAJOR.MINOR.PATCH` version. It also becomes
the version of the SauronAgent RPM installed in the image. It defaults to the
root `VERSION` setting, or `0.0.0` when neither is specified. From this directory,
`make`, `make check`, and `make test` run the same build and validation scripts.

The build requires Linux x86_64, access to Docker, Bash, curl, Python 3, `flock`,
`sha256sum`, Git, Make, and the Go toolchain specified in the root `go.mod`.
It downloads `ghcr.io/define42/virt-tools-container:latest` for libguestfs and
QEMU image tools. KVM is used when `/dev/kvm` is present; software emulation
works without it but takes considerably longer. Allow room for the downloaded
base image, a 16 GiB virtual build disk, the builder container, and the final
compressed image.

`image-check` validates shell syntax and every file uploaded by the recipe.
`image-test` additionally requires host `qemu-system-x86_64`, `qemu-img`,
`xorriso`, and `timeout`. It boots a temporary QCOW2 overlay with a NoCloud seed
to check cloud-init, D-Bus, NetworkManager, DHCP, firewalld, XRDP, XFCE, the
IntelliJ IDEA installation and bundled Java runtime, and SauronAgent
configuration while leaving the base disk unchanged.

## Image contents

- XFCE, LightDM, XRDP with its Xorg backend, and clipboard redirection.
- Cloud-init, Python 3, and NetworkManager for gateway provisioning.
- Firefox, Visual Studio Code, Vim, Nmap, and network administration tools.
- IntelliJ IDEA 2026.2.3 with its bundled Java runtime, matching the Ubuntu image.
- SauronAgent built and packaged from the same checkout, with its guest service
  enabled. The gateway supplies the host collector.
- Full glibc locale coverage and an XFCE configuration optimized for remote use.

The build verifies the base image against Rocky's published `CHECKSUM`, expands
the guest disk to 16 GiB, enables CRB and EPEL, applies `run-command.virt`, and
installs the locally built SauronAgent RPM. It resets cloud-init state and
machine identity, relabels SELinux files offline, then sparsifies and compresses
a standalone QCOW2 image with an `.img` extension.

Kernel updates retain the cloud image's root filesystem identity and generate
portable initramfs images, so their boot settings do not inherit the builder
appliance's devices or kernel command line.

## Files and output

`build.sh` handles downloads, SauronAgent packaging, and the builder container.
`customize.sh` runs inside the container. `run-command.virt` and the adjacent
configuration files define the guest. `smoke-test.sh` boots the result.

For `IMAGE_VERSION=0.0.0`, the output directory is `dist/images/rocky9-xfce/`:

```text
rocky9-xfce-v0.0.0.img
rocky9-xfce-v0.0.0.img.sha256
rocky9-xfce-v0.0.0.img.manifest.json
```

The manifest records the source image URL and checksum, Git commit and dirty
state, builder container digest, image version, and SauronAgent version.
Downloads are cached by checksum in `.cache/images/rocky9-xfce/`; temporary
build workspaces are removed when the build exits. `make clean` in this
directory removes the selected version's output files.

## GitHub Actions and releases

The [gateway release workflow](../../.github/workflows/go.yml) calls the
[Rocky image workflow](../../.github/workflows/rocky9-xfce.yml) on pushes to
`main`, passing the gateway's numeric `MAJOR.MINOR.PATCH` version. The image and
its installed SauronAgent use that exact version and the same source commit.
After the gateway builds and image boot tests succeed, the gateway workflow
publishes both Rocky and Ubuntu image assets alongside the gateway and
SauronAgent packages in the same `vMAJOR.MINOR.PATCH` GitHub Release.

The Rocky image workflow also runs independently for relevant image, build,
and SauronAgent changes on pull requests, using version `0.0.0`. Manual runs
accept a numeric version input that defaults to `0.0.0`. Successful image
builds upload workflow artifacts; pull-request and manual runs do not create
tags or GitHub Releases.

CI splits the disk into `.img.part-*` assets smaller than GitHub's 2 GiB
per-file limit and includes the checksum and manifest. Download every part
and both sidecars into one directory. Substitute the release's version, then
reconstruct and verify:

```sh
image="rocky9-xfce-v1.2.3.img"
cat "$image".part-* > "$image"
sha256sum --check "$image.sha256"
```

Local builds produce the complete `.img` directly.

## Use with DevBox Gateway

Copy the complete `.img` into the gateway's configured `BASE_IMAGE_DIR`, or
upload it through the administrator's **Base Images** modal. For the default
Docker Compose setup, after a local build:

```sh
sudo install -d /data/baseimages
sudo install -m 0644 \
  dist/images/rocky9-xfce/rocky9-xfce-v0.0.0.img /data/baseimages/
```

Native gateway packages default to
`/var/lib/libvirt/devbox-gateway/baseimages`. The gateway provisions the VM's
user, password hash, network settings, and individual XRDP TLS identity using
NoCloud. SauronAgent sends guest events over virtio-vsock to the gateway's
embedded collector.

The image has no preset desktop login. Outside DevBox Gateway, attach your own
NoCloud seed with account credentials or SSH keys. `make run` from this directory
boots a disposable snapshot with SSH forwarded to host port `2222` and RDP to
`3390`; use `RUN_QEMU_ARGS` to attach a seed. Memory, CPU and port defaults can
be overridden with `RUN_MEMORY`, `RUN_CPUS`, `RUN_SSH_PORT` and `RUN_RDP_PORT`.

## IntelliJ IDEA

IntelliJ IDEA is installed in `/opt/intellij-idea` from JetBrains' Linux x86_64
archive, verified against the same pinned SHA-256 checksum as the Ubuntu image.
Launch it from the XFCE application menu in the **Development/Programming**
category, or run `idea` in a terminal. Settings and projects belong to each
user; the installation is shared by all users.

## Guest defaults

The recipe disables IPv6 and uses SELinux permissive mode. Firewalld is enabled
with the shipped `xrdp` zone as its default, allowing SSH and RDP connections.
The XFCE compositor is disabled to reduce remote desktop overhead.

Both the base image and builder container use mutable `latest` references.
The manifest records the exact source checksum and builder digest used by
each build; builds at different times need not be byte-for-byte identical.
