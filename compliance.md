# NATO AC/35-D/2003-REV5 §26.3.1 compliance comparison

The solution provides substantial coverage of §26.3.1, but **full compliance is not yet demonstrated**. This comparison covers DevBox-Gateway, SauronAgent on Linux guests, and the collector. It is an implementation assessment, not an accreditation or certification.

The requirements below paraphrase Annex 1, Appendix 4, §26.3.1, printed page 1-44. [NATO directive](https://www.jftc.nato.int/wp-content/uploads/2025/01/AC-35-D-2003-REV5_-_DIRECTIVE_ON_CLASSIFIED_PROJECT_AND_INDUSTRIAL_SECURITY.pdf#page=45)

## Coverage comparison

| §26.3.1 requirement | Implemented coverage | Assessment / remaining requirement |
|---|---|---|
| Generate and maintain an audit log | DevBox-Gateway emits structured JSON application audits to HEC when configured, otherwise to a local file. HEC delivery first fsyncs application events to a persistent spool and replays them after restart. The gateway also always starts its guest-event collector on AF_VSOCK port 9000; SauronAgent collects guest events, spools them, and forwards them to the collector. [Application delivery](internal/audit/hec.go), [guest storage](internal/sauron/sauron.go#L110) | **Conditional; operational verification needed.** Persistence materially reduces outage and restart loss but does not make an event durable when disk persistence itself fails. Spool capacity, filesystem durability, disk-full handling and outage recovery must be verified. Guest agents must be installed and running. New VMs receive a vsock device; existing VMs without one are not automatically migrated. |
| Include system, application and user events selected through the Security Authority's risk assessment | System-security rules cover execution, permissions, credentials, persistence, kernel, network, time and mounts. DevBox-Gateway logs authentication and selected VM/admin operations. [Built-in policy](SauronAgent/internal/audit/security_paths.go#L32) | **Partial.** The approved event inventory must be mapped against coverage. Not every application action or access denial is currently audited. |
| Record every successful and unsuccessful login attempt | DevBox-Gateway logs successful authentication and failures, including malformed requests, missing credentials, invalid usernames and rate limits. SauronAgent consumes guest authentication records. [DevBox-Gateway logging](internal/gateway/handlers.go#L378) | **Implemented for DevBox-Gateway login; conditional for guests.** SSH, PAM, desktop login and other authentication services must actually emit audit records. Execution auditing alone does not prove login coverage. |
| Record logout, including applicable timeouts | DevBox-Gateway records explicit logout, 30-minute browser-session expiry and IP-mismatch invalidation. SauronAgent consumes guest logout/session-end records. [Expiry auditing](internal/session/session_expiry.go#L170) | **Implemented for browser sessions; conditional for guest sessions.** Browser-session expiry does not terminate existing RDP, noVNC or serial-console streams; dashboard-control WebSockets enforce expiry separately. |
| Record creation, removal and modification of access rights and privileges | Audits permission, ownership, extended-attribute and credential-ID changes; watches account/group files, sudo/polkit configuration and discovered SSH directories. [Syscall rules](SauronAgent/internal/audit/security_syscalls.go#L13) | **Implemented for covered local Linux mechanisms.** LDAP/AD group changes and application-specific roles require auditing in their owning systems. |
| Record password creation, removal and modification | Watches `/etc/shadow`, `/etc/gshadow` and `/etc/security/opasswd`; consumes password-change audit records when emitted. [Credential watches](SauronAgent/internal/audit/rules.go#L274) | **Partial overall.** Local store changes are detected, but file watches alone do not identify every logical per-account change. LDAP/AD and application password stores need their own audit records. Password values should not be logged. |
| Include event date, time and event type | DevBox-Gateway records timestamps and actions; SauronAgent preserves event timestamps, categories, audit keys and raw records. [Event schema](SauronAgent/internal/event/event.go#L22) | **Implemented.** Clock accuracy and synchronization still need operational verification. |
| Associate events with an individual user | DevBox-Gateway records usernames and source IPs. SauronAgent preserves UID, login UID (`auid`) and account information supplied by audit records. [Identity extraction](SauronAgent/internal/event/normalize.go#L516) | **Conditional.** Login UID must be populated and traceable to individuals, including after privilege elevation. Shared accounts or an unset login UID weaken attribution. |
| Include success or failure | DevBox-Gateway supplies an explicit result. SauronAgent extracts the source record's `success` or `res` value. [Result extraction](SauronAgent/internal/event/normalize.go#L755) | **Partial.** SauronAgent leaves the result absent when the source supplies neither value. Verify outcome coverage for every required event class. |

## SauronAgent built-in audit rule inventory

This table describes the policy compiled into SauronAgent, not proof that every rule is active on a deployed guest. The agent enables kernel auditing and installs/verifies the baseline through `NETLINK_AUDIT` at startup; no guest YAML, audit rules file, `auditd`, or audit command-line tools are required. Sources: [rule installation and required watches](SauronAgent/internal/audit/rules.go), [syscall masks](SauronAgent/internal/audit/security_syscalls.go), and [path discovery](SauronAgent/internal/audit/security_paths.go).

Syscall rows use `always,exit`, an ABI-specific `arch` filter and the listed key. There is **no UID, login-UID or success filter**: root, other users, and successful/failed attempts are included. Path permission matching is architecture-independent. `wa` means writes and attribute changes, not reads; `x` means execution. Directory paths below have a trailing `/` and use recursive `AUDIT_DIR` matching, subject to Linux Audit mount boundaries. Grouped paths describe individual watches; compatible rules already installed by another controller can satisfy the required coverage.

| Audit key | Rule type / permissions | Syscalls or watched paths | What it records / scope |
|---|---|---|---|
| `exec` | Syscall | `execve`, `execveat` | Program execution attempts; executable and arguments, not terminal output. |
| `permission_change` | Syscall | `chmod`, `fchmod`, `fchmodat`, `fchmodat2` | File permission changes, including executable and set-ID mode bits. |
| `ownership_change` | Syscall | `chown`, `fchown`, `lchown`, `fchownat`; also `chown32`, `fchown32`, `lchown32` on i386/ARM | File owner/group changes. |
| `attribute_change` | Syscall | `setxattr`, `lsetxattr`, `fsetxattr`, `removexattr`, `lremovexattr`, `fremovexattr`, `setxattrat`, `removexattrat` | Extended-attribute changes, including ACLs and file capabilities when changed through these calls. |
| `privilege_change` | Syscall | `setuid`, `setreuid`, `setresuid`, `setgid`, `setregid`, `setresgid`, `capset`; also `setuid32`, `setreuid32`, `setresuid32`, `setgid32`, `setregid32`, `setresgid32` on i386/ARM | Process user/group identity and capability changes. |
| `kernel_module` | Syscall | `init_module`, `finit_module`, `delete_module` | Kernel module loading and unloading. |
| `kernel_replacement` | Syscall | `kexec_load`, `kexec_file_load` where defined by the ABI | Loading a replacement kernel through kexec. |
| `network_config` | Syscall | `sethostname`, `setdomainname` | Hostname and domain-name changes; not a rule for every network operation. |
| `time_change` | Syscall | `adjtimex`, `settimeofday`, `clock_settime`, `clock_adjtime`; also `clock_settime64`, `clock_adjtime64` on i386/ARM | System clock and time-adjustment operations. |
| `filesystem_mount` | Syscall | `mount`, `umount2`, `mount_setattr` | Mount, unmount and mount-attribute changes through these calls. |
| `sauron_identity` | Required file watch, `wa` | `/etc/passwd` | Local account database changes. |
| `sauron_identity` | Required file watch, `wa` | `/etc/group` | Local group database changes. |
| `sauron_credentials` | Required file watch, `wa` | `/etc/shadow` | Local password-store changes. |
| `sauron_credentials` | Required file watch, `wa` | `/etc/gshadow` | Protected group credential/membership store changes. |
| `sauron_credentials` | Required file watch, `wa` | `/etc/security/opasswd` | Local password-history store changes. |
| `privilege_config` | Discovered paths, `wa` | `/etc/sudoers`, `/etc/sudoers.d/`, `/etc/polkit-1/` | Sudo and polkit authorization policy changes. |
| `authentication_config` | Discovered directories, `wa` | `/etc/pam.d/`, `/etc/security/` | PAM and local authentication/security configuration changes. |
| `ssh_config` | Discovered paths, `wa` | `/etc/ssh/sshd_config`, `/etc/ssh/sshd_config.d/` | SSH server configuration changes. |
| `privilege_use` | Discovered executable watches, `x` | `/usr/bin/sudo`, `/usr/bin/su`, `/usr/bin/pkexec`, `/usr/bin/systemd-run` | Execution of these privilege/service tools; execution is not proof that an elevation request succeeded. |
| `persistence` | Discovered paths, `wa` | `/etc/systemd/system/`, `/usr/lib/systemd/system/`, `/etc/cron.d/`, `/var/spool/cron/`, `/etc/crontab`, `/etc/rc.local`, `/etc/ld.so.preload`, `/etc/profile.d/` | Changes to the listed service, scheduled-job, startup, preload and shell-profile locations. |
| `ssh_keys` | Discovered directories, `wa` | Existing `<home>/.ssh/` for homes in local `/etc/passwd`, plus `/root/.ssh/` | Changes below discovered SSH directories, including authorized keys and SSH configuration; not key contents. |
| `kernel_config` | Discovered paths, `wa` | `/etc/modprobe.d/`, `/etc/modules-load.d/`, `/etc/sysctl.d/`, `/etc/sysctl.conf` | Module and sysctl configuration changes. |
| `boot_config` | Discovered directories, `wa` | `/etc/default/`, `/etc/grub.d/` | Changes below the listed default/boot configuration directories. |
| `mac_policy` | Discovered directories, `wa` | `/etc/selinux/`, `/etc/apparmor.d/` | SELinux and AppArmor policy-file changes. |
| `crypto_policy` | Discovered directory, `wa` | `/etc/crypto-policies/` | System cryptographic policy-file changes. |
| `firewall` | Discovered paths, `wa` | `/etc/firewalld/`, `/etc/nftables.conf` | Firewall configuration-file changes. |
| `network_config` | Discovered paths, `wa` | `/etc/hosts`, `/etc/resolv.conf`, `/etc/NetworkManager/`, `/etc/systemd/network/` | Host resolution, DNS and listed network configuration changes. |
| `time_change` | Discovered file, `wa` | `/etc/localtime` | Local timezone-file changes. |
| `time_config` | Discovered paths, `wa` | `/etc/chrony.conf`, `/etc/chrony.d/` | Chrony time-synchronization configuration changes. |
| `filesystem_config` | Discovered file, `wa` | `/etc/fstab` | Persistent filesystem mount configuration changes. |

### Rule coverage conditions

- **Architectures:** supported builds are `amd64`, `386`, `arm`, `arm64`, `riscv64`, `ppc64`, `ppc64le`, `s390x` and `loong64`. `amd64` installs both native x86-64 and i386 compatibility syscall rules; the other builds cover their native ABI. `arm64`, `riscv64` and `loong64` omit the nonexistent legacy `chmod`, `chown` and `lchown` calls. i386 omits `kexec_file_load`. A syscall mask can include newer calls that an older running kernel does not implement; installation does not probe by executing them.
- **Required versus discovered paths:** the five identity/credential watches are mandatory. A watched file may be absent if its parent exists. For the additional discovered paths, absent directories or absent file parents are skipped and reported; missing files with existing parents are watched for later creation. Discovery errors such as inaccessible paths or unexpected file types fail startup.
- **Discovery is startup-only:** SSH homes come from local `/etc/passwd` plus `/root`, not LDAP/NSS or a `/home/*` wildcard. Restart after adding users, creating previously absent directories/parents, or changing symlink targets. Existing file symlinks are watched at both their declared name and resolved target; directory symlinks are watched at the resolved target. Check the `audit managed paths discovered` journal entry for skipped paths, pending files and SSH-directory counts.
- **Overlapping rules:** Linux Audit normally selects the first matching rule/key, not one event per matching table row. Specific file/executable watches take precedence over directory and broad syscall rules: `/etc/security/opasswd` retains `sauron_credentials`, and `/usr/bin/sudo` execution uses `privilege_use`. Compatible pre-existing execution coverage can be accepted with a different key from `exec`. Interpret the key together with syscall and path fields.
- **Installation and persistence:** the agent needs `CAP_AUDIT_CONTROL`, `CAP_AUDIT_READ` and access for private-directory discovery (`CAP_DAC_READ_SEARCH`). It preserves unrelated rules, does not claim the audit daemon PID or lock policy, and leaves rules active when it exits. Incomplete immutable policy or conflicting suppressing rules prevent startup. This is not continuous enforcement against another controller clearing the rules; restart to re-establish the baseline.
- **Event limits:** file watches record operation metadata, not file contents or before/after diffs. Execution arguments can themselves contain sensitive values. Guest authentication/password-change records, SELinux AVC, SECCOMP and audit-subsystem records are also consumed when their sources emit them; these are not additional syscall rules installed by this table. Normalizer support for an event category does not establish universal coverage of that category. See [normalization](SauronAgent/internal/event/normalize.go) and the [event schema](SauronAgent/internal/event/event.go).

## DevBox-Gateway structured audit event inventory

These are DevBox-Gateway's application audit events, separate from SauronAgent guest events and ordinary diagnostic logs. When `SPLUNK_HEC_ENDPOINT` is nonblank, HEC is their sole output, `AUDIT_LOG_FILE` is ignored, and pending delivery is persisted under `<DATA_ROOT_DIR>/audit-spool`. Otherwise events are written as JSON Lines to the required `AUDIT_LOG_FILE` (default `/var/log/devbox-gateway/audit.jsonl`). The delivery spool is not a permanent audit-file copy. Guest events use the separate `SAURON_EVENT_LOG_FILE` / `SAURON_SPLUNK_HEC_*` outputs. See [audit definitions and writer](internal/audit/audit.go), [output settings](internal/config/config.go), and [Splunk forwarding and examples](#splunk-forwarding-and-index-separation).

Every application audit record has `time`, `level`, `msg="audit"`, `action`, `user` and `result`. `result` is `success` or `failure`; omitted results at call sites default to `success`. Optional fields are `source_ip`, `vm`, `resource_type`, `resource`, `protocol`, `operation`, `administrator` and `duration_ms`. Empty optional strings are omitted; `administrator` appears only when true and duration only when positive. Passwords, password hashes and session tokens are not part of this audit schema. Invalid or unavailable login identities can produce an empty `user`.

| Event / action | When DevBox-Gateway records it | Result and distinguishing fields | Implementation |
|---|---|---|---|
| Login: `user.login` | Outcome of each `POST /login` reaching the login audit middleware, including successful authentication and rejected attempts. | `success` only after authenticated session setup produces the successful redirect. Failures use `operation=origin_rejected`, `malformed_request`, `missing_credentials`, `invalid_username`, `rate_limited`, `authentication_failed` or `session_failed`. Includes source IP and a validated/authenticated username when available. | [Login outcome middleware](internal/gateway/handlers.go#L378) |
| Explicit logout: `user.logout` | An authenticated, same-origin logout request destroys the user's sessions and requests closure of their live connections. | `operation=explicit`; `success` or `failure` according to session destruction. Includes requesting source IP and administrator flag when applicable. No authenticated identity means no explicit-logout audit event. | [Logout handler](internal/gateway/handlers.go#L278) |
| Session expiry: `user.logout` | A tracked authenticated browser session reaches its 30-minute absolute expiry; a timer records it without requiring another browser request. | `operation=timeout`; result reflects expired-session deletion. Uses the user and source IP retained at session commit. This is browser-session expiry, not a record that an existing RDP/noVNC/serial stream has ended. | [Expiry audit](internal/session/session_expiry.go#L170) |
| IP-mismatch invalidation: `user.logout` | A request no longer matches the authenticated session's bound IP; the session invalidation is claimed and audited once. | `operation=client_ip_changed`; `success` or `failure` according to invalidation. `source_ip` is the new request's canonical address when valid, not the previous bound address. | [IP enforcement](internal/session/session.go#L681) |
| VM creation: `vm.create` | Authenticated dashboard create validation failures, and the outcome of VM provisioning/initial startup. Includes malformed form, invalid name/base-image selection, missing provisioning credential, duplicate-name/limit and provisioning failures when reached. | `success` or `failure`; actor, source IP, administrator flag and VM name when safely available. Success is provisioning/startup success, not proof that the guest OS is ready. | [Create validation and operation](internal/gateway/handlers.go#L734) |
| VM start: `vm.start` | Dashboard start request: target validation/authorization and start-operation outcomes after authentication. | `success` or `failure`; actor, source IP and VM. Administrator lifecycle actions carry `administrator=true`. | [Lifecycle routes](internal/gateway/handlers.go#L574) |
| VM shutdown: `vm.stop` | Dashboard shutdown request: target validation/authorization and shutdown-operation outcomes after authentication. | `operation=shutdown`; `success` or `failure`; actor, source IP, VM and administrator flag when applicable. | [Lifecycle audit emission](internal/gateway/handlers.go#L922) |
| VM restart: `vm.reboot` | Dashboard restart request: target validation/authorization and restart-operation outcomes after authentication. | `operation=restart`; `success` or `failure`; actor, source IP, VM and administrator flag when applicable. | [Lifecycle audit emission](internal/gateway/handlers.go#L922) |
| VM removal: `vm.remove` | Dashboard removal request: target validation/authorization and removal-operation outcomes after authentication. | `success` or `failure`; actor, source IP, VM and administrator flag when applicable. | [Lifecycle audit emission](internal/gateway/handlers.go#L922) |
| Connection established: `connection.connect` | An authorized RDP proxy or noVNC/serial bridge is established and accepted into live-connection tracking. | `result=success`; `protocol=rdp`, `novnc` or `serial`, actor, source IP and VM. Console/noVNC includes administrator status when applicable; the RDP emitter does not set it. | [RDP](internal/rdp/rdp.go#L158), [console/noVNC](internal/console/console.go#L58) |
| Connection ended: `connection.disconnect` | The established RDP/noVNC/serial proxy or bridge returns, including normal closure and connection teardown. | `result=success` by default, same connection identity/protocol fields and `duration_ms`. There is no structured close-reason or transport-error field; success does not mean an error-free session. | [RDP](internal/rdp/rdp.go#L158), [console/noVNC](internal/console/console.go#L58) |
| Base-image upload: `admin.base_image.upload` | After administrator authorization: malformed upload, validation/storage failures, or successful image storage. | `success` or `failure`; `administrator=true`, `resource_type=base_image`, `resource` when a name is known, actor and source IP. Uploaded byte count is diagnostic-only. | [Upload handler](internal/gateway/handlers_base_images.go#L67), [failure audit](internal/gateway/handlers_base_images.go#L196) |
| Base-image deletion: `admin.base_image.delete` | After administrator authorization: malformed deletion request, invalid/missing image, deletion failure, or successful deletion. | `success` or `failure`; `administrator=true`, `resource_type=base_image`, `resource` when known, actor and source IP. | [Deletion handler](internal/gateway/handlers_base_images.go#L111), [failure audit](internal/gateway/handlers_base_images.go#L196) |

### DevBox-Gateway event boundaries

- The table covers all 11 currently defined application audit action names; logout has separate rows for its three operations. Ordinary `log.Printf` messages are diagnostic output, not interchangeable with these structured audit records.
- Failed connection authorization, connection limits and backend/TLS/WebSocket setup failures before a connection is established do not emit `connection.connect` with `result=failure`. Clicking **Connect**, granting RDP access and downloading an `.rdp` file do not themselves emit connection audit events.
- VM validation/ownership failures inside the authenticated lifecycle handlers are audited. However, API requests rejected earlier by session or same-origin middleware, and failed administrator checks before base-image operations, do not have dedicated structured denial events. The login middleware's explicit rejection coverage is separate.
- Browser-session expiry and IP-mismatch invalidation do not themselves close established RDP/noVNC/serial streams; explicit logout requests closure of the user's tracked connections. Dashboard/admin control WebSockets independently close at the session deadline, but do not emit the connection events above. See [dashboard socket lifetime](internal/console/dashboard_socket.go#L138).
- Dashboard/page views, VM/base-image listings, health checks, static-file requests, dashboard-control WebSockets, DevBox-Gateway process startup/shutdown and background VM auto-shutdown have no dedicated application audit action. VM resource/configuration changes and external LDAP/AD account, group or password changes are not represented by a dedicated action in this inventory.
- A successful VM lifecycle event reports the operation's return status, not continuous verification of the guest state. Structured VM/admin failures do not include a general error-reason field; details may only be in diagnostic logs. Connection payloads, terminal output and desktop contents are not captured by these audit events.

## Splunk forwarding and index separation

DevBox-Gateway supports direct forwarding to Splunk's HTTP Event Collector (HEC). The supplied [Docker Compose deployment](docker-compose.yml) routes application audit events and SauronAgent guest events into **two separate indexes**:

| Event stream | Index in the supplied deployment | Index setting | HEC `source` / `sourcetype` | HEC `host` and `time` |
|---|---|---|---|---|
| DevBox-Gateway application audits: login/logout, VM lifecycle, connections and base-image administration | `devbox_audit` | `SPLUNK_HEC_INDEX` | `devbox-gateway` / `devbox-gateway:audit` | DevBox-Gateway host's hostname; application forwarding timestamp |
| SauronAgent guest events and collector-generated `sauron.*` events | `devbox_sauron` | `SAURON_SPLUNK_HEC_INDEX` | `sauronagent` / `devbox-gateway:sauron` | Source VM name when available; collector receive timestamp (`received_at`) |

The index names are configurable, not hard-coded or enforced to be different. Both index settings default to empty, which omits the HEC `index` field and uses the token's default index. Set both explicitly to preserve the separation above. The two streams can use the same Splunk endpoint, with independently configured tokens and indexes. Sources: [application forwarding](internal/audit/hec.go), [guest forwarding](internal/sauron/forward.go), and [HEC envelope](internal/splunkhec/splunkhec.go).

### Forwarding configuration

Set these environment-backed settings on **DevBox-Gateway**, not inside a SauronAgent YAML file. Replace the example endpoint and token placeholders with deployment values; do not commit real tokens.

```ini
SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SPLUNK_HEC_TOKEN=<application-hec-token>
SPLUNK_HEC_INDEX=devbox_audit
SPLUNK_HEC_SKIP_TLS_VERIFY=false
DEVBOX_GATEWAY_SPOOL_MAX_MIB=10240

SAURON_SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SAURON_SPLUNK_HEC_TOKEN=<guest-hec-token>
SAURON_SPLUNK_HEC_INDEX=devbox_sauron
SAURON_SPLUNK_HEC_SKIP_TLS_VERIFY=false
```

A URL without a path uses `/services/collector/event`. Provision the indexes and allow the corresponding HEC tokens to write to them; DevBox-Gateway does not create Splunk indexes. The bundled development Splunk instance provisions both through [post-setup tasks](testsplunk/create_index.yml). Use HTTPS with a trusted certificate. For token setup, including the current client's requirement to disable HEC indexer acknowledgement, see the [HEC setup instructions](README.md#forwarding-to-splunk-hec).

HEC forwarding is optional and disabled when its endpoint is unset; remove the associated token/index settings as well when disabling it. Application audits then use `AUDIT_LOG_FILE`. With application HEC configured, that file setting is entirely ignored: DevBox-Gateway does not create, open or append to the application audit file, and existing files are not deleted. Invalid HEC configuration fails startup without switching to file logging.

SauronAgent collection remains mandatory: DevBox-Gateway always starts the collector on AF_VSOCK port 9000. The guest JSON Lines output is independently controlled by `SAURON_EVENT_LOG_FILE` and can run alongside guest HEC forwarding; at least one of those guest outputs must be configured.

### Delivery and compliance boundaries

- **Application audits:** HEC is the sole output when configured. Before the delivery sink accepts an event, it is appended and fsynced under `<DATA_ROOT_DIR>/audit-spool`; delivery resumes after a gateway restart, and pending records do not expire during an outage. Delivery is at-least-once, so a crash around acknowledgement can produce duplicates. Only valid HEC JSON with `code: 0` advances the spool: `400`, `403`, other HTTP failures, invalid responses and nonzero HEC codes remain pending rather than being dropped automatically. `DEVBOX_GATEWAY_SPOOL_MAX_MIB` bounds the spool at 10 GiB by default. At capacity, pending records are preserved and new audit writes wait for space, which can delay their user actions. A 48-hour objective must be sized from the measured encoded byte rate multiplied by 172800 seconds and operational headroom; 10 GiB alone is not a time guarantee. `AUDIT_LOG_FILE` remains unused in HEC mode, and acknowledged spool data is reclaimed rather than retained as a permanent local copy. Disk/oversize errors are diagnostic failures to persist. During shutdown, capacity waits receive a five-second grace period; after it, not-yet-persisted writes fail so shutdown can complete, while already-spooled records remain for restart replay. This is not an absolute lossless guarantee when storage cannot accept an event. See [application delivery](internal/audit/hec.go).
- **Guest events:** forwarding uses the persistent `SAURON_SPOOL_DIR` spool and resumes after DevBox-Gateway restarts. With HEC enabled, guest acknowledgement requires acceptance into this spool and any other configured sink, not receipt by Splunk. Delivery is at-least-once, so duplicates are possible. The spool is bounded by `SAURON_SPOOL_MAX_MIB` (10 GiB by default); a full spool stops new acknowledgements, leaving events in the guests' bounded spools. Permanently invalid or oversized HEC events can be dropped with diagnostics. This is not an unlimited or loss-free retention guarantee. See [guest spool and forwarding](internal/sauron/forward.go) and [guest spool limits](SauronAgent/internal/spool/spool.go).

Separate indexes permit different access and retention policies, but forwarding alone does not establish those policies, tamper protection, review procedures or full NATO compliance. Verify both streams end to end in the deployed Splunk instance, including failure/recovery behaviour and the controls identified under [related requirements](#related-requirements-outside-this-comparison).

### JSON event examples

The following values are **synthetic examples**, not captured production events or evidence of successful delivery. Timestamps, usernames, IP addresses, VM identifiers and sequence numbers are illustrative. The HEC wrapper's `index`, `source`, `sourcetype`, `host` and numeric Unix-seconds `time` are routing metadata; its `event` value is the JSON payload sent for indexing.

#### DevBox-Gateway application events: `devbox_audit`

A successful login, shown as a complete HEC event object:

```json
{
  "time": 1789898400,
  "host": "hypervisor-01",
  "source": "devbox-gateway",
  "sourcetype": "devbox-gateway:audit",
  "index": "devbox_audit",
  "event": {
    "time": "2026-09-20T10:00:00Z",
    "level": "INFO",
    "msg": "audit",
    "action": "user.login",
    "user": "alice",
    "result": "success",
    "source_ip": "192.0.2.10"
  }
}
```

Additional application payload examples show a failed login, VM creation, an RDP connection and disconnection, browser-session expiry, and administrator image upload. With HEC configured, each object below is placed in its own wrapper like the one above with `index=devbox_audit`. With HEC disabled, each object is written as one local JSON Lines record instead. The array groups examples for documentation only: actual HEC batches concatenate wrapped event objects, not a JSON array.

```json
[
  {
    "time": "2026-09-20T09:59:00Z",
    "level": "INFO",
    "msg": "audit",
    "action": "user.login",
    "user": "alice",
    "result": "failure",
    "source_ip": "192.0.2.10",
    "operation": "authentication_failed"
  },
  {
    "time": "2026-09-20T10:01:00Z",
    "level": "INFO",
    "msg": "audit",
    "action": "vm.create",
    "user": "alice",
    "result": "success",
    "source_ip": "192.0.2.10",
    "vm": "alice.dev"
  },
  {
    "time": "2026-09-20T10:01:30Z",
    "level": "INFO",
    "msg": "audit",
    "action": "connection.connect",
    "user": "alice",
    "result": "success",
    "source_ip": "192.0.2.10",
    "vm": "alice.dev",
    "protocol": "rdp"
  },
  {
    "time": "2026-09-20T10:16:30Z",
    "level": "INFO",
    "msg": "audit",
    "action": "connection.disconnect",
    "user": "alice",
    "result": "success",
    "source_ip": "192.0.2.10",
    "vm": "alice.dev",
    "protocol": "rdp",
    "duration_ms": 900000
  },
  {
    "time": "2026-09-20T10:30:00Z",
    "level": "INFO",
    "msg": "audit",
    "action": "user.logout",
    "user": "alice",
    "result": "success",
    "source_ip": "192.0.2.10",
    "operation": "timeout"
  },
  {
    "time": "2026-09-20T11:00:00Z",
    "level": "INFO",
    "msg": "audit",
    "action": "admin.base_image.upload",
    "user": "operator",
    "result": "success",
    "source_ip": "192.0.2.20",
    "resource_type": "base_image",
    "resource": "ubuntu.qcow2",
    "administrator": true
  }
]
```

#### SauronAgent guest events: `devbox_sauron`

Guest HEC payloads retain an additional collector envelope: `received_at`, trusted `source` identity and the normalized guest `event`. The examples below are shortened native x86-64 audit events. Raw records, record-type lists, additional syscall/path details and some process and guest-reported identity fields are omitted for readability; production output preserves raw records by default. The VM owner in `source.labels.owner` identifies the DevBox-Gateway owner, whereas `uid` and `auid` identify guest accounts and must be resolved against guest identity records. Guest-supplied identity under `source.reported` is not authoritative VM attribution.

Program execution (`process.exec`):

```json
{
  "time": 1789898520.318,
  "host": "alice.dev",
  "source": "sauronagent",
  "sourcetype": "devbox-gateway:sauron",
  "index": "devbox_sauron",
  "event": {
    "received_at": "2026-09-20T10:02:00.318Z",
    "source": {
      "cid": 7,
      "vm": "alice.dev",
      "host": "hypervisor-01",
      "uuid": "287548af-9df6-4829-8890-0d8678481827",
      "labels": { "owner": "alice" },
      "known": true,
      "reported": { "hostname": "dev" }
    },
    "event": {
      "version": 1,
      "sequence": 1201,
      "timestamp": "2026-09-20T10:02:00.312Z",
      "type": "process.exec",
      "severity": "info",
      "audit_id": "1789898520.312:8421",
      "boot_id": "8f1d0c1e-2b4a-4a7e-9f31-0d5c6b2a7e10",
      "pid": 4821,
      "uid": 1000,
      "gid": 1000,
      "auid": 1000,
      "exe": "/usr/bin/id",
      "command": "id",
      "result": "success",
      "fields": {
        "arch": "c000003e",
        "syscall": "59",
        "syscall_name": "execve",
        "key": "exec",
        "argv": ["id"],
        "exit": 0
      }
    }
  }
}
```

Credential-store replacement (`file.modify`): this example represents a successful `rename` replacing `/etc/shadow`, selected by the `sauron_credentials` watch. It records the operation and paths, not a password, hash, file-content diff or proof of a particular account's password change. `uid=0` with `auid=1000` illustrates an elevated process retaining its original login identity.

```json
{
  "time": 1789898580.418,
  "host": "alice.dev",
  "source": "sauronagent",
  "sourcetype": "devbox-gateway:sauron",
  "index": "devbox_sauron",
  "event": {
    "received_at": "2026-09-20T10:03:00.418Z",
    "source": {
      "cid": 7,
      "vm": "alice.dev",
      "host": "hypervisor-01",
      "uuid": "287548af-9df6-4829-8890-0d8678481827",
      "labels": { "owner": "alice" },
      "known": true,
      "reported": { "hostname": "dev" }
    },
    "event": {
      "version": 1,
      "sequence": 1242,
      "timestamp": "2026-09-20T10:03:00.412Z",
      "type": "file.modify",
      "severity": "info",
      "audit_id": "1789898580.412:8490",
      "boot_id": "8f1d0c1e-2b4a-4a7e-9f31-0d5c6b2a7e10",
      "pid": 4890,
      "uid": 0,
      "gid": 0,
      "auid": 1000,
      "exe": "/usr/bin/passwd",
      "command": "passwd alice",
      "result": "success",
      "fields": {
        "arch": "c000003e",
        "syscall": "82",
        "syscall_name": "rename",
        "key": "sauron_credentials",
        "exit": 0
      },
      "paths": ["/etc/shadow+", "/etc/shadow"]
    }
  }
}
```

For both guest examples, HEC `time` matches the collector's `received_at`, not the guest-controlled `event.timestamp`. Inside the indexed JSON payload, the normalized type is `event.type` and the audit key is `event.fields.key`; the extra outer `event` in the examples belongs to the HEC wrapper. `result=success` describes the audited syscall, not the eventual exit status of the launched program. See the [collector envelope](SauronAgent/internal/output/sink.go), [event schema](SauronAgent/internal/event/event.go), and [normalizer](SauronAgent/internal/event/normalize.go).

## Remaining work before claiming compliance

- Validate deployed end-to-end coverage on the target systems, including event fields, authentication sources, timeouts, storage failures and outages. Live-kernel verification remains outstanding.
- Validate application-spool sizing, filesystem durability, capacity backpressure,
  disk-error alerting, restart replay and duplicate handling before claiming every
  required event is retained. HEC mode has no permanent local audit-file copy.
- Integrate external identity and application audit sources for changes outside the covered local Linux mechanisms.
- Obtain Security Authority acceptance of the risk-assessed event inventory and its mapping to the deployed logging coverage.

## Related requirements outside this comparison

Audit protection, restricted log access, retention and review are separate requirements in **§§26.3.2–26.3.5**; adding audit rules does not establish those controls. [Related clauses](https://www.jftc.nato.int/wp-content/uploads/2025/01/AC-35-D-2003-REV5_-_DIRECTIVE_ON_CLASSIFIED_PROJECT_AND_INDUSTRIAL_SECURITY.pdf#page=46)
