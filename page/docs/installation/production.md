# Production installation with the RPM

This walkthrough installs DevBox Gateway on a Rocky Linux 9 x86_64 host, connects
it to your LDAP directory, and takes you through the first administrator login,
image upload, and desktop connection. For a Debian 12
host, use the [DEB installation guide](deb.md) for package and libvirt setup;
the gateway configuration and dashboard steps are the same.

**The gateway can start with an empty base-image library.** It creates the
configured directory if missing. Sign in as an administrator to upload the
first image through the dashboard, then create a VM from it.

## 1. Prepare the host and directory

You need:

- A Rocky Linux 9 x86_64 host with root or `sudo` access and hardware
  virtualization available to QEMU/KVM. If the host is itself a VM, its
  hypervisor must expose nested virtualization.
- Enough memory and disk space for your desktops. Defaults are four vCPUs,
  4 GiB RAM, and a 200 GiB virtual disk per VM; QCOW2 disk usage grows as guests
  write data. Reserve the gateway's `192.168.123.0/24` network for its managed
  guests. See [libvirt and storage](../configuration/storage.md).
- A hostname such as `desktop.example.com` that resolves to the host from your
  clients, and a matching TLS certificate trusted by those clients.
- An LDAP directory reachable from the host, including a user who will be an
  administrator. The example below uses `alice@example.com` as the directory
  bind identity and the `userPrincipalName` attribute for search and identity.
  The directory must accept that bind and allow the user to read their own
  entry and `memberOf`. Adapt the attributes to your directory as described in
  [LDAP configuration](../configuration/ldap.md).
- Direct membership in `devbox-users` for gateway users. Administrators also
  need direct membership in `devbox-admins`. These example groups must exist
  in your directory; the gateway does not create them or resolve nested groups.

This guide uses local audit files. Splunk can be configured later through the
[audit](../operations/audit-logs.md) and
[guest-event](../operations/guest-events.md) settings.

## 2. Install the RPM

Choose a version from [GitHub Releases](https://github.com/define42/DevBox-Gateway/releases).
Replace `1.2.3` below with that version, without the `v` prefix:

```sh
version=1.2.3
curl --fail --location --remote-name \
  "https://github.com/define42/DevBox-Gateway/releases/download/v${version}/devbox-gateway-${version}-1.x86_64.rpm"
sudo dnf install "./devbox-gateway-${version}-1.x86_64.rpm"
sudo dnf install libvirt-daemon libvirt-client
```

The RPM installs the gateway binary, systemd service, configuration template,
and its libvirt/QEMU dependencies. Installation does not start the gateway.
The additional packages ensure `libvirtd` and the `virsh` client are available
for the monolithic-daemon setup and connection checks below.
See the [RPM reference](rpm.md) for package contents and upgrades.

## 3. Enable libvirt and guest-event transport

For a fresh host, this walkthrough uses the monolithic `libvirtd` service:

```sh
sudo systemctl enable --now libvirtd.service
```

Keep an existing host's libvirt mode. If it is already configured to use
modular daemons, enable these sockets instead of starting `libvirtd`:

```sh
sudo systemctl enable --now virtqemud.socket virtnetworkd.socket \
  virtstoraged.socket virtnwfilterd.socket virtproxyd.socket
```

`virtproxyd.socket` provides `/var/run/libvirt/libvirt-sock`, the socket used by
the gateway, when modular daemons are in use. On a modular host,
`libvirtd.service` must remain masked as part of libvirt's
[modular setup](https://libvirt.org/daemons.html#switching-to-modular-daemons):
the gateway unit has `Wants=libvirtd.service`, so merely disabling it does not
prevent a startup attempt. Do not activate both daemon modes together. If you
are unsure which mode the host uses, follow libvirt's
[daemon-mode checks](https://libvirt.org/daemons.html#checking-whether-modular-monolithic-mode-is-in-use).

Load the vsock module now and on future boots, then verify KVM and the exact
libvirt connection the gateway needs:

```sh
sudo modprobe vhost_vsock
printf '%s\n' vhost_vsock | sudo tee /etc/modules-load.d/devbox-gateway.conf
test -c /dev/kvm
sudo virsh -c 'qemu+unix:///system?socket=/var/run/libvirt/libvirt-sock' version
```

The `test` command must succeed and `virsh` must report the host's libvirt/QEMU
versions. The gateway requires libvirt 6.2.0 or newer. It creates its storage
pool, dedicated NAT network, and network filter when it starts; you do not need
to define them manually. Leave the standalone `sauronhost` service disabled:
the gateway already runs the guest-event collector on AF_VSOCK port 9000.

## 4. Configure DNS, TLS, and network access

Point `desktop.example.com` at the host and allow client TCP connections to port
443. Both HTTPS and RDP use this port. This walkthrough connects clients
directly to the gateway; a normal HTTP reverse proxy cannot carry its raw RDP
connections.

If firewalld is active and the client-facing interface uses the `public` zone:

```sh
sudo firewall-cmd --get-active-zones
sudo firewall-cmd --permanent --zone=public --add-port=443/tcp
sudo firewall-cmd --reload
```

Use the zone for your client-facing interface if it differs. See Rocky Linux's
[firewalld guide](https://docs.rockylinux.org/guides/security/firewalld/) for zone
selection. Allow the same TCP port through any upstream firewall. The host must
also reach your LDAP server; the example uses LDAPS on port 636.

Obtain a certificate for `desktop.example.com` through your certificate
authority. With its PEM certificate chain and matching unencrypted private key
available locally as `fullchain.pem` and `privkey.pem`, install them:

```sh
sudo install -d -m 0700 /etc/devbox-gateway/tls
sudo install -m 0644 fullchain.pem /etc/devbox-gateway/tls/fullchain.pem
sudo install -m 0600 privkey.pem /etc/devbox-gateway/tls/privkey.pem
```

Clients must trust the frontend certificate's CA. The host must trust the LDAP
server's CA, and its certificate must cover the LDAP hostname. Keep certificate
verification enabled. This guide uses static PEM files; see
[TLS certificates](../configuration/tls.md) if you prefer ACME.

## 5. Edit devbox-gateway.conf

```sh
sudo vi /etc/devbox-gateway/devbox-gateway.conf
```

Set the following values, replacing the example hostnames, directory base,
identity attribute, and groups with your deployment's values. Edit existing
active settings instead of appending duplicate keys. The first occurrence of
a key wins within the file; explicit process environment variables override it.

```ini
LISTEN_ADDR=:443
FRONT_DOMAIN=desktop.example.com
CERT_FILE=/etc/devbox-gateway/tls/fullchain.pem
KEY_FILE=/etc/devbox-gateway/tls/privkey.pem
ACME_ENABLE=false

DATA_ROOT_DIR=/var/lib/libvirt/devbox-gateway
BASE_IMAGE_DIR=/var/lib/libvirt/devbox-gateway/baseimages

LDAP_URL=ldaps://ldap.example.com:636
LDAP_BASE_DN=dc=example,dc=com
LDAP_USER_DOMAIN=@example.com
LDAP_USER_FILTER=(userPrincipalName=%s)
LDAP_USERNAME_ATTRIBUTE=userPrincipalName
LDAP_STARTTLS=false
LDAP_SKIP_TLS_VERIFY=false
LDAP_REQUIRED_GROUPS=devbox-users
ADMIN_GROUP=devbox-admins

AUDIT_LOG_FILE=/var/log/devbox-gateway/audit.jsonl
SAURON_EVENT_LOG_FILE=/var/log/devbox-gateway/sauron.jsonl
```

Leave the application and guest Splunk endpoint, token, and index settings
unset and their ACK settings disabled for this local-logging setup. An
administrator must belong directly to **both** example groups: `ADMIN_GROUP`
grants administrator access but does not bypass `LDAP_REQUIRED_GROUPS`.

This file uses literal `KEY=VALUE` entries, not shell commands. Put comments on
separate lines and use absolute paths; `$DATA_ROOT_DIR` is not expanded inside
another value. The [configuration reference](../configuration/index.md) lists
all settings, including VM sizing and idle shutdown.

The service must be able to create and access `BASE_IMAGE_DIR`. The native
path above is created at startup if it does not exist; you can also prepare
the directory yourself. No image is required yet. Filesystem errors, such as
an inaccessible directory or a path that names a file, still prevent startup.

## 6. Start the gateway and check it

```sh
sudo systemctl enable --now devbox-gateway
sudo systemctl --no-pager --full status devbox-gateway
sudo journalctl -u devbox-gateway -n 100 --no-pager
curl --fail https://desktop.example.com/api/health
curl --fail https://desktop.example.com/api/ready
```

The service should be active, with `ok` from `/api/health` and `ready` from
`/api/ready`. Run the HTTPS checks from a machine that trusts your certificate.
If startup fails, use the journal to resolve directory access, libvirt access,
vsock support, certificate files, or invalid settings before retrying.
After correcting a repeated startup failure:

```sh
sudo systemctl reset-failed devbox-gateway
sudo systemctl start devbox-gateway
```

Health checks do not test LDAP login. Application events are written to
`/var/log/devbox-gateway/audit.jsonl`; guest events appear in
`/var/log/devbox-gateway/sauron.jsonl` as agents connect. See
[health checks](../operations/health-checks.md) for readiness scope and
[audit logs](../operations/audit-logs.md) for log retention and rotation.

## 7. Log in as an administrator

1. Open `https://desktop.example.com` in a browser.
2. Enter the bare **Username**, for example `alice`, and the account's directory
   **Password**, then select **Continue**. Do not enter `alice@example.com`:
   the gateway appends the configured domain. Native installations have no
   bundled `johndoe` or `admin` test accounts.
3. On the dashboard, select **Admin**, then **Base Images**. If **Admin** is
   absent, check `ADMIN_GROUP` and the account's direct `memberOf` values.
   Sign in again after directory membership changes.

The **Base Images** dialog is available even when the library is empty.
Uploading images requires administrator access; ordinary users cannot upload
the first image themselves.

## 8. Upload the first VM image

On the computer running your browser, download **all** parts for one Ubuntu
26.04, Ubuntu 24.04, or Rocky Linux 9 XFCE image from the chosen release, plus
its checksum and manifest. Keep them together in one directory. These guest
choices work with the Rocky Linux host; they do not need to match the host
distribution.

In that directory, reconstruct and verify the image. Set `version` to the same
release used above; this example chooses Ubuntu 26.04:

```sh
version=1.2.3
image="ubuntu26.04-xfce-v${version}.img"
cat "$image".part-* > "$image"
sha256sum --check "$image.sha256"
```

Continue only when the checksum reports `OK`. The [VM image guide](../vm-images.md)
lists all filenames and explains the manifest. Release images already include
cloud-init, XFCE, XRDP, IntelliJ IDEA, and the matching SauronAgent.

1. Under **Upload Base Image**, choose the complete disk file, then select
   **Upload**.
2. Wait for **Base image uploaded.** and confirm the image appears under
   **Available Images**.

Accepted filenames end in `.img`, `.qcow2`, or `.raw`, but the content must
always be QCOW2. Do not upload `.part-*`, checksum, or manifest files. Uploads
cannot overwrite an existing filename. The dialog shows available storage and
the upload limit, which follows `VM_DISK_SIZE_GB` (200 GiB by default).

VM creation requires a valid base image. If the last image is deleted, new VM
creation remains unavailable until another is added; the gateway can still
start and administrators can upload a replacement.

For an alternative import method, [copy a verified image directly on the
host](../vm-images.md#copy-an-image-on-the-host) into `BASE_IMAGE_DIR`. This can
be done before or after starting the gateway.

## 9. Create a desktop and connect

Return to **My DevBoxes** and select **Create DevBox**. Enter a **New DevBox
Name**, choose a **Base Image**, and set the guest **Username**. Submit
**Create DevBox**; the gateway creates and starts the VM.

The guest's password is the password used for this gateway login. Wait until
the VM's **RDP** button is enabled, select it, and open the downloaded `.rdp`
file in an RDP client within two minutes. Log into the guest with the guest
username and that password. Each downloaded connection token is single-use;
select **RDP** again for a new connection. See the
[RDP client guide](../usage/rdp.md) for the connection requirements.

For subsequent changes to `devbox-gateway.conf` or the static certificate files,
run `sudo systemctl restart devbox-gateway`. A restart reloads those files,
invalidates browser sessions, and disconnects active gateway connections.
