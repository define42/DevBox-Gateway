# NATO AC/35-D/2003-REV5 §26.3.1 compliance comparison

The solution provides substantial coverage of §26.3.1, but **full compliance is not yet demonstrated**. This comparison covers DevBox-Gateway, SauronAgent on Linux guests, and the collector. It is an implementation assessment, not an accreditation or certification.

The requirements below paraphrase Annex 1, Appendix 4, §26.3.1, printed page 1-44. [NATO directive](https://www.jftc.nato.int/wp-content/uploads/2025/01/AC-35-D-2003-REV5_-_DIRECTIVE_ON_CLASSIFIED_PROJECT_AND_INDUSTRIAL_SECURITY.pdf#page=45)

## Coverage comparison

| §26.3.1 requirement | Implemented coverage | Assessment / remaining requirement |
|---|---|---|
| Generate and maintain an audit log | Gateway writes structured JSON audit logs and always starts its guest-event collector on AF_VSOCK port 9000. SauronAgent collects guest events, spools them, and forwards them to the collector. [Storage implementation](internal/sauron/sauron.go#L110) | **Implemented; operational verification needed.** Guest agents must be installed and running, storage persistent, and disk-full/outage behaviour tested. New VMs receive a vsock device; existing VMs without one are not automatically migrated. |
| Include system, application and user events selected through the Security Authority's risk assessment | System-security rules cover execution, permissions, credentials, persistence, kernel, network, time and mounts. Gateway logs authentication and selected VM/admin operations. [Built-in policy](SauronAgent/internal/audit/security_paths.go#L32) | **Partial.** The approved event inventory must be mapped against coverage. Not every application action or access denial is currently audited. |
| Record every successful and unsuccessful login attempt | Gateway logs successful authentication and failures, including malformed requests, missing credentials, invalid usernames and rate limits. SauronAgent consumes guest authentication records. [Gateway logging](internal/gateway/handlers.go#L378) | **Implemented for gateway login; conditional for guests.** SSH, PAM, desktop login and other authentication services must actually emit audit records. Execution auditing alone does not prove login coverage. |
| Record logout, including applicable timeouts | Gateway records explicit logout, 30-minute browser-session expiry and IP-mismatch invalidation. SauronAgent consumes guest logout/session-end records. [Expiry auditing](internal/session/session_expiry.go#L170) | **Implemented for browser sessions; conditional for guest sessions.** Browser-session expiry is not termination of an already-open RDP/WebSocket connection. |
| Record creation, removal and modification of access rights and privileges | Audits permission, ownership, extended-attribute and credential-ID changes; watches account/group files, sudo/polkit configuration and discovered SSH directories. [Syscall rules](SauronAgent/internal/audit/security_syscalls.go#L13) | **Implemented for covered local Linux mechanisms.** LDAP/AD group changes and application-specific roles require auditing in their owning systems. |
| Record password creation, removal and modification | Watches `/etc/shadow`, `/etc/gshadow` and `/etc/security/opasswd`; consumes password-change audit records when emitted. [Credential watches](SauronAgent/internal/audit/rules.go#L274) | **Partial overall.** Local store changes are detected, but file watches alone do not identify every logical per-account change. LDAP/AD and application password stores need their own audit records. Password values should not be logged. |
| Include event date, time and event type | Gateway records timestamps and actions; SauronAgent preserves event timestamps, categories, audit keys and raw records. [Event schema](SauronAgent/internal/event/event.go#L22) | **Implemented.** Clock accuracy and synchronization still need operational verification. |
| Associate events with an individual user | Gateway records usernames and source IPs. SauronAgent preserves UID, login UID (`auid`) and account information supplied by audit records. [Identity extraction](SauronAgent/internal/event/normalize.go#L516) | **Conditional.** Login UID must be populated and traceable to individuals, including after privilege elevation. Shared accounts or an unset login UID weaken attribution. |
| Include success or failure | Gateway supplies an explicit result. SauronAgent extracts the source record's `success` or `res` value. [Result extraction](SauronAgent/internal/event/normalize.go#L755) | **Partial.** SauronAgent leaves the result absent when the source supplies neither value. Verify outcome coverage for every required event class. |

## Remaining work before claiming compliance

- Validate deployed end-to-end coverage on the target systems, including event fields, authentication sources, timeouts, storage failures and outages. Live-kernel verification remains outstanding.
- Integrate external identity and application audit sources for changes outside the covered local Linux mechanisms.
- Obtain Security Authority acceptance of the risk-assessed event inventory and its mapping to the deployed logging coverage.

## Related requirements outside this comparison

Audit protection, restricted log access, retention and review are separate requirements in **§§26.3.2–26.3.5**; adding audit rules does not establish those controls. [Related clauses](https://www.jftc.nato.int/wp-content/uploads/2025/01/AC-35-D-2003-REV5_-_DIRECTIVE_ON_CLASSIFIED_PROJECT_AND_INDUSTRIAL_SECURITY.pdf#page=46)
