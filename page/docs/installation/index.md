# Deployment options

The [production installation walkthrough](production.md) takes you from a
Rocky Linux 9 host to your first desktop, including configuration and
administrator image uploads.

Choose a native package for a host service, or Docker Compose for the bundled
development stack:

| Deployment | Supported host | Docker required on the host? |
| --- | --- | --- |
| [Native RPM](rpm.md#installing-the-rpm) | Rocky Linux 9, x86_64 | No |
| [Native DEB](deb.md#installing-the-deb) | Debian 12, amd64 | No |
| [Docker Compose development stack](docker-compose.md#quick-start-docker-compose) | Linux x86_64 with KVM | Yes, with Docker Compose v2 |

The RPM and DEB run the gateway directly as a systemd service using the host's
libvirt/QEMU/KVM stack. Configure an LDAP server for authentication; Splunk is
optional, and native installations default to local audit files. Download
[prebuilt VM images](../vm-images.md#downloading-vm-images) to use with either native package.

Docker is needed for the repository's gateway package builds, VM image builds,
and integration tests that launch containers. These build and test requirements
do not apply when installing release packages and using prebuilt VM images.

The [SauronAgent installation guide](sauronagent.md#installing-sauronagent)
covers guest images that do not already include the audit agent. The prebuilt
VM images include it, and the gateway contains the host collector.
