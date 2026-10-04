# Ubuntu Resolute XFCE image

Builds an Ubuntu Resolute (26.04) amd64 desktop image for DevBox Gateway from
Ubuntu's official server cloud image. The recipe, desktop assets, and guest
agent are built together from this repository.

## Build and check

Run from the repository root:

```sh
make image-check IMAGE=ubuntu-resolute-xfce
make image IMAGE=ubuntu-resolute-xfce IMAGE_VERSION=0.0.0
make image-test IMAGE=ubuntu-resolute-xfce IMAGE_VERSION=0.0.0
```

`IMAGE_VERSION` must be a numeric `MAJOR.MINOR.PATCH` version. It also becomes
the version of the SauronAgent deb installed in the image. It defaults to the
root `VERSION` setting, or `0.0.0` when neither is specified.

The build requires Linux x86_64, access to Docker, Bash, curl, Python 3, `flock`,
`sha256sum`, Git, Make, and the Go toolchain specified in the root `go.mod`.
It downloads `ghcr.io/define42/virt-tools-container:latest` for libguestfs and
QEMU image tools. KVM is used when `/dev/kvm` is present; software emulation
works without it but takes considerably longer. Allow room for the downloaded
server image, a 16 GiB virtual build disk, the builder container, and the final
compressed image.

`image-check` validates shell syntax and every file uploaded by the recipe.
`image-test` additionally requires host `qemu-system-x86_64`, `qemu-img`,
`xorriso`, and `timeout`. It boots a temporary QCOW2 overlay with a NoCloud seed
to check first-boot provisioning, leaving the base disk unchanged.

## Image contents

- XFCE, LightDM, XRDP, Xorg, and a default XFCE session for new users.
- Cloud-init and Python 3 for the gateway's first-boot user and TLS provisioning.
- PipeWire and XRDP playback/microphone redirection.
- Firefox, Google Chrome, VS Code, and IntelliJ IDEA 2026.2.3 with its bundled Java runtime.
- Go from the longsleep/golang-backports repository.
- Docker from Ubuntu, with Buildx and Docker Compose.
- SauronAgent built and packaged from the same checkout, with only its guest
  service enabled. The gateway supplies the host collector.

The build verifies the downloaded Ubuntu image against its published SHA-256,
expands the guest disk to 16 GiB, applies `run-command.virt`, and installs the
SauronAgent deb. It resets cloud-init state and machine identity, then sparsifies
and compresses a standalone QCOW2 image with an `.img` extension.

## Files and output

`build.sh` handles downloads, SauronAgent packaging, and the builder container.
`customize.sh` runs inside the container. `run-command.virt` and the adjacent
desktop configuration files define the guest. `smoke-test.sh` boots the result.
Keep source assets here; generated files are ignored by Git.

For `IMAGE_VERSION=0.0.0`, the output directory is
`dist/images/ubuntu-resolute-xfce/`:

```text
ubuntu-resolute-xfce-v0.0.0.img
ubuntu-resolute-xfce-v0.0.0.img.sha256
ubuntu-resolute-xfce-v0.0.0.img.manifest.json
```

The manifest records the source image URL and checksum, Git commit and dirty
state, builder container digest, image version, and SauronAgent version.
Source downloads are cached by checksum in `.cache/images/ubuntu-resolute-xfce/`;
temporary build workspaces are removed when the build exits.

## GitHub Actions and releases

The [gateway release workflow](../../.github/workflows/go.yml) calls the
[image workflow](../../.github/workflows/ubuntu-resolute-xfce.yml) on pushes to
`main`, passing the gateway's numeric `MAJOR.MINOR.PATCH` version. The image and
its installed SauronAgent use that exact version and the same source commit.
After the gateway build and both Ubuntu and Rocky image boot tests succeed,
the gateway workflow publishes the image assets alongside the gateway and
SauronAgent packages in the same `vMAJOR.MINOR.PATCH` GitHub Release.

The image workflow also runs independently for relevant image, build, and
SauronAgent changes on pull requests, using version `0.0.0`. Manual runs accept
a numeric `MAJOR.MINOR.PATCH` version input that defaults to `0.0.0`. Every
successful image build uploads workflow artifacts; pull-request and manual
runs do not create tags or GitHub Releases.

CI splits the disk into `.img.part-*` assets smaller than GitHub's 2 GiB
per-file limit and includes the checksum and manifest. Download every part
and both sidecars into one directory. Substitute the release's version, then
reconstruct and verify:

```sh
image="ubuntu-resolute-xfce-v1.2.3.img"
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
  dist/images/ubuntu-resolute-xfce/ubuntu-resolute-xfce-v0.0.0.img \
  /data/baseimages/
```

Native gateway packages default to
`/var/lib/libvirt/devbox-gateway/baseimages`. Keep versioned filenames so users
can distinguish images in the dashboard. The gateway creates a NoCloud seed
with the VM's user, password hash, network settings, and individual XRDP TLS
identity. New VMs start SauronAgent automatically and send guest events over
virtio-vsock to the gateway's embedded collector.

## RDP audio

The image includes `pipewire-audio`, `pipewire-module-xrdp`, and
`pulseaudio-utils`. The XRDP module loads automatically when an XFCE RDP
session starts and selects the `xrdp-sink` output and `xrdp-source` input.

Enable audio playback in your RDP client. For microphone forwarding, also
enable audio recording/input redirection. In Windows Remote Desktop Connection,
these options are under **Local Resources → Remote audio → Settings**: select
**Play on this computer** and, if needed, **Record from this computer**.

After changing client settings, log out of XFCE and start a new RDP session.
Inside that session, use `pactl info`, `pactl list short sinks`, and
`pactl list short sources` to check the audio server and redirected devices.

## IntelliJ IDEA

IntelliJ IDEA is installed in `/opt/intellij-idea` from JetBrains' Linux x86_64
archive, verified against its pinned SHA-256 checksum. Launch it from the XFCE
application menu in the **Development/Programming** category, or run `idea` in
a terminal. Settings and projects belong to each user; the installation is
shared by all users.

## Guest defaults

Docker is enabled at boot and its Unix socket is available to every local user
without `sudo`. Docker access grants root-equivalent privileges, so image users
must be trusted. The recipe also disables and removes AppArmor.

The image uses NoCloud for first-boot configuration and has no preset desktop
login. When running it outside DevBox Gateway, attach your own seed disk or
CD-ROM with `user-data` and `meta-data`, and supply the account credentials or
SSH keys you intend to use. The disk format is QCOW2 for QEMU/KVM; convert it to
the required disk format before using another hypervisor.
