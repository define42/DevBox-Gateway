# TLS certificates

There are three supported modes for the front-side certificate:

1. **Self-signed (default for local dev).** Leave `CERT_FILE`, `KEY_FILE` and
   `ACME_ENABLE` empty. A self-signed certificate is generated in-memory on
   start.
2. **Static PEM files.** Set `CERT_FILE` and `KEY_FILE` to readable PEM files
   inside the container/process.
3. **ACME.** Set `ACME_ENABLE=true`, set `FRONT_DOMAIN` to the public hostname,
   and set `ACME_EMAIL`. Only `FRONT_DOMAIN` is managed; creating or deleting VMs
   does not request public certificates. Optionally set `ACME_CA=staging` while
   testing. ACME state is persisted under `$DATA_ROOT_DIR/acme`.

Each new VM receives a unique backend certificate and private key through its
cloud-init seed ISO. Libvirt metadata stores the public certificate, its internal
server name, and the domain UUID. The gateway validates certificate trust,
server name, validity, and the exact leaf certificate before forwarding RDP
traffic. The public routing token is separate from this backend identity.
Backend TLS session resumption is disabled so every connection verifies the current
provisioned identity. Certificates are valid for ten years; recreating a VM
generates a new key and certificate.

The seed configures xrdp to use `/etc/xrdp/devbox-cert.pem` and
`/etc/xrdp/devbox-key.pem`; the key is installed as `0640 root:xrdp`. Base images
must include cloud-init, Python 3, xrdp with its `xrdp` group, and a working
`xrdp.service`. Provisioning forces TLS 1.2 or newer and restarts xrdp. A missing
identity or a guest that presents a different certificate is rejected without
forwarding client credentials. See [Libvirt and VM storage](storage.md#libvirt-and-vm-storage)
for the required network isolation and the recreation policy for older VMs.
