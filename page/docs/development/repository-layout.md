# Repository layout

```
.
├── cmd/
│   ├── devbox-gateway/  Minimal gateway process entrypoint.
│   ├── mkdeb/           Debian packaging CLI adapter.
│   ├── mkrpm/           RPM packaging CLI adapter.
│   └── mksauronagent/   SauronAgent RPM/deb packaging CLI adapter.
├── internal/
│   ├── audit/       Application audit events and durable HEC delivery.
│   ├── backendidentity/ Per-VM backend TLS certificates and identity validation.
│   ├── cert/        TLS certificate management (self-signed + ACME via certmagic).
│   ├── cloudinit/   NoCloud document and seed ISO generation.
│   ├── config/      Environment-backed settings registry (the only place env
│   │                vars may be read from).
│   ├── console/     Serial console and noVNC WebSocket handlers.
│   ├── dashboard/   Dashboard HTML / JSON rendering and VM listing.
│   ├── deb/         Debian package construction and archive writing.
│   ├── gateway/     Application lifecycle, HTTP handlers, TLS dispatch, and listeners.
│   ├── hash/        Password hashing for cloud-init.
│   ├── identity/    Authenticated user identity and administrator role.
│   ├── ldap/        LDAP login authentication.
│   ├── rdp/         RDP/X.224/MCS parsing, TLS-to-TLS proxy.
│   ├── rpm/         RPM package construction and manifests.
│   ├── sauron/      Embedded SauronAgent collector: vsock listener, event log, Splunk HEC sink.
│   ├── sauronpkg/   SauronAgent package manifest and maintainer scripts.
│   ├── session/     Cookie session manager and middleware.
│   ├── splunkhec/   Splunk HTTP Event Collector client shared by audit and sauron.
│   ├── virt/        Libvirt VM lifecycle (create/start/stop/remove/resize).
│   ├── vmname/      VM name construction and validation.
│   └── webassets/   Embedded static assets, including the compiled dashboard.js.
├── SauronAgent/     Guest audit agent and hypervisor collector in the root Go module;
│                    the gateway embeds its collector package.
├── images/
│   ├── Makefile     Image build, recipe validation, and boot smoke-test targets.
│   ├── rocky9-xfce/  Rocky Linux 9 XFCE image recipe and desktop assets.
│   ├── ubuntu24.04-xfce/  Ubuntu 24.04 XFCE image recipe and desktop assets.
│   └── ubuntu26.04-xfce/  Build scripts, guest customization recipe, and desktop assets.
├── dist/images/     Generated QCOW2 images, checksums, and manifests (ignored).
├── .cache/images/   Downloaded base images and build workspaces (ignored).
├── ui/              TypeScript sources for the dashboard.
├── testldap/        glauth config + cert/key used for local LDAP.
├── testsplunk/      Post-setup task creating the local Splunk's audit and SauronAgent indexes.
├── page/
│   ├── docs/        Installation, configuration, operations, development, and HTTP reference.
│   ├── mkdocs.yml   Documentation site metadata, navigation, and theme.
│   └── requirements.txt  Pinned documentation build dependencies.
├── docs/            LDAP identity migration procedure.
├── CONTRIBUTING.md  Contributor setup, checks, and review guidance.
├── go.mod, go.sum   Shared dependencies for the gateway and SauronAgent.
└── Dockerfile, docker-compose.yml, Makefile, tsconfig.json
```
