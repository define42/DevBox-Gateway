# Downloading VM images

The [GitHub Releases](https://github.com/define42/DevBox-Gateway/releases) page
includes prebuilt VM images alongside the gateway and SauronAgent RPM and DEB packages.

## Choose an image

Open the chosen release's **Assets** list and select an image:

| Guest desktop | Reconstructed filename | Image details |
| --- | --- | --- |
| Ubuntu 26.04 XFCE | `ubuntu26.04-xfce-v<version>.img` | [Ubuntu 26.04 image README](https://github.com/define42/DevBox-Gateway/blob/main/images/ubuntu26.04-xfce/README.md) |
| Ubuntu 24.04 XFCE | `ubuntu24.04-xfce-v<version>.img` | [Ubuntu 24.04 image README](https://github.com/define42/DevBox-Gateway/blob/main/images/ubuntu24.04-xfce/README.md) |
| Rocky Linux 9 XFCE | `rocky9-xfce-v<version>.img` | [Rocky image README](https://github.com/define42/DevBox-Gateway/blob/main/images/rocky9-xfce/README.md) |

All three are x86_64 QCOW2 disks with XFCE, XRDP, cloud-init, IntelliJ IDEA
2026.2.3, and SauronAgent. The `v<version>` suffix and the installed SauronAgent
use the gateway release version; `26.04`, `24.04`, and `9` identify the guest
operating systems.

## Download and verify

For your chosen image and release, download **every** `.img.part-*` asset,
its `.img.sha256` checksum, and its `.img.manifest.json` into one directory.
The manifest records the source image and build provenance. Reconstruct the
complete disk and verify it from that directory, replacing `1.2.3` with the
chosen release version:

```sh
image="ubuntu26.04-xfce-v1.2.3.img"
# For Ubuntu 24.04, use image="ubuntu24.04-xfce-v1.2.3.img" instead.
# For Rocky Linux 9, use image="rocky9-xfce-v1.2.3.img" instead.
cat "$image".part-* > "$image"
sha256sum --check "$image.sha256"
```

## Upload the first base image

The gateway can start with an empty image library and creates `BASE_IMAGE_DIR`
if it is missing. After the checksum reports `OK`, sign in as an administrator,
open **Admin → Base Images**, choose the complete `.img` under **Upload Base
Image**, and select **Upload**. The image becomes available for VM creation
after the upload succeeds. Repeat these steps to add more images.

Administrator access requires direct membership in `ADMIN_GROUP` and any
configured login-access group requirement. The native packages do not supply
an administrator account; configure your directory and `ADMIN_GROUP` first.
See the [production walkthrough](installation/production.md#7-log-in-as-an-administrator).

## Copy an image on the host

As an alternative to the administrator upload, copy the verified complete
`.img` into `BASE_IMAGE_DIR` before or after starting the gateway. For Docker
Compose:

```sh
sudo install -d /data/baseimages
sudo install -m 0644 "$image" /data/baseimages/
```

For native RPM or DEB installations:

```sh
sudo install -d /var/lib/libvirt/devbox-gateway/baseimages
sudo install -m 0644 "$image" /var/lib/libvirt/devbox-gateway/baseimages/
```

Use your configured directory instead if you changed `DATA_ROOT_DIR` or
`BASE_IMAGE_DIR`.
The gateway provisions each VM's login account when it creates the VM; these
images have no preset desktop login.

See [Libvirt and VM storage](configuration/storage.md#libvirt-and-vm-storage) for host prerequisites,
or [Building VM images](development/building.md#building-vm-images) to build an image locally.
