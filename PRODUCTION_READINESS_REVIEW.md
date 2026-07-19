# Production Readiness Review — DevBox Gateway

**Date:** 2026-07-19 · **Reviewed at:** `4d4785d` (v0.1.78) · **Scope:** full repository — all Go source, UI, deployment artifacts, CI, and docs.

## Verdict

**Conditionally production-ready.** For its intended deployment — a single-host, self-hosted VDI gateway serving a small set of trusted (LDAP-authenticated) users — the project is unusually mature: the security design, test depth, CI pipeline, and documentation are well beyond what the v0.1.x version number suggests. It is **not** yet ready for deployments with untrusted/semi-trusted users, multi-node scale, or formal compliance requirements. The gaps are specific and fixable; the highest-priority ones are resource governance (no per-user quotas), the currently-failing vulnerability gate, the missing license, and observability.

---

## What is genuinely strong

**Security design (the core of this product) is excellent.**

- RDP access requires an explicit, **single-use, 2-minute, IP-bound grant** minted by clicking Connect in an authenticated dashboard session (`internal/session/session.go`) — a standing login never implicitly authorizes RDP.
- SNI routing labels are **HMAC-SHA256-blinded** (`internal/hash/hash.go`), so VM/user names never appear in cleartext ClientHello, labels cannot be forged, and lookups use constant-time compare.
- Backend routing **fails closed**: only the gateway's own DHCP lease inside `192.168.122.0/24` is ever dialed (`internal/virt/list.go`), so a rooted guest cannot steer the proxy (SSRF) via agent/ARP-reported addresses.
- Guest-to-guest isolation via libvirt `<port isolated='yes'/>`, with a **boot-time minimum-libvirt-version check** (6.2.0) so the gateway refuses to run where isolation would silently not apply.
- Web layer: strict CSP (`script-src 'self'`, no inline), HSTS, session cookie `Secure`/`HttpOnly`/`SameSite=Lax`, session bound to client IP with forced re-login on roaming, same-origin enforcement on every mutating route, login rate limiting (per-username and per-IP), and a DOM-building UI that renders all dynamic data via `textContent` (no injection sink found).
- Auth: empty-password LDAP binds are rejected before dialing (RFC 4513 anonymous-bind bypass), the username character allowlist (`internal/vmname`) incidentally prevents LDAP filter injection, local-user digests compare in constant time, and VM ownership is authorized against libvirt **domain metadata**, not name parsing.
- Input handling: single-source-of-truth VM naming, base-image path-traversal guard, XML-escaped domain definitions, TPKT length caps, bounded form bodies, per-connection panic recovery, and a front-connection concurrency cap (`netutil.LimitListener`, default 1024).
- SSH reverse tunnel: host-key pinning via known_hosts, literal-IP-only relay address (DNS cannot redirect the dial), keepalive-driven fail-fast with supervisor restart.

**Engineering quality.** ~7.7k lines of production Go carry ~8.4k lines of tests (unit + real-libvirt integration + testcontainers LDAP), `go build`/`go vet`/`gofmt` are clean (verified locally), lint and coverage gate in CI, dependabot on modules and actions, weekly scheduled govulncheck, automated tagged releases with RPM/deb/GHCR artifacts. The README is exemplary, including an honest "Security notes" section that documents the residual risks (shared-NAT grant caveat, no live LDAP re-checking, unverified backend TLS).

---

## Findings

### Blockers (fix before calling it production)

1. **No per-user resource quotas of any kind.** Any authenticated user can create unlimited VMs, each up to 8 vCPU / 32 GiB RAM / 200 GB (virtual) disk — until host CPU, RAM, or the storage pool is exhausted. One compromised or careless account can take down every user's desktop. There is also no cap on concurrent VM creations. *Recommend:* per-user VM count + aggregate resource ceilings enforced in `virt.BootNewVM`, and host free-space checks before volume creation.

2. **VM creation runs synchronously inside the HTTP request** (`handlers.go` → `virt.BootNewVM` → full base-image copy through a libvirt stream). With multi-GB images the request can run for minutes before the "VM creation started." response; browsers/proxies time out, users re-submit, and each attempt does the full copy. *Recommend:* enqueue creation, return immediately, surface progress via the existing 10-second dashboard poll.

3. **The security gate is red and being ignored.** The `govulncheck` workflow has failed on `main` since 2026-07-13 (GO-2026-5932: deprecated `golang.org/x/crypto/openpgp`, pulled in by `github.com/xor-gate/debpkg`, used only by the `cmd/mkdeb` packaging helper — it is *not* reachable from the gateway binary). The finding itself is low-risk, but a permanently failing vulnerability gate trains everyone to ignore it, which defeats its purpose. *Recommend:* replace/fork debpkg or scope the scan to the server binary, and make the gate green again.

4. **No license.** There is no LICENSE file; the README's License section points back at the repository, and the RPM metadata defaults to "Proprietary" while artifacts are published publicly on GitHub Releases and GHCR. Nobody outside the author can legally deploy this to production. *Recommend:* commit a license and reference it from README/packaging.

5. **Unbounded WebSocket reads on the serial and VNC bridges** (`internal/console/console.go`): only the ping socket calls `SetReadLimit`. `ReadMessage` buffers an entire message in memory, so an authenticated user can send one huge frame and OOM the gateway. One line per handler to fix; the RTT socket already shows the pattern.

### High priority

6. **Observability is minimal.** Unstructured stdlib logs, a bare `/api/health`, no metrics (connections, sessions, cert expiry, tunnel state, VM operations), no pprof. Production triage of "RDP is slow/failing" will be guesswork. *Recommend:* Prometheus metrics + structured logging (slog).

7. **Restarts sever every live session with no drain.** `gatewayRuntime.Close` stops the listener but does not wait for active RDP/console connections; sessions and rate-limit state are in-memory (`memstore`), so a restart (including the RPM's `try-restart` on upgrade) drops all desktops and logs everyone out. Acceptable for the niche if operators know; document it prominently, and consider draining.

8. **Single-instance by design.** In-memory sessions, grants, rate limiter, and connection registry mean no HA/failover story. Fine at this scale — state it explicitly in the README so nobody load-balances two instances (which would also break IP-bound grants).

9. **Live connections outlive authentication.** Session expiry (30 min) gates only *new* connections; an open RDP/VNC/serial stream continues indefinitely (only explicit logout closes tracked connections, and there is no idle/absolute cap on streams). Combined with revocation being login-time-only (documented), consider a maximum session duration for proxied streams.

10. **Local users are unsalted, un-stretched SHA-256** (`sha256("user:password")` in config). The README honestly warns, but a leaked config file brute-forces at GPU speed, and the digest format invites weak secrets. *Recommend:* bcrypt/argon2id digests instead.

### Medium

11. **Docs/code drift on a security default:** README's config table and the shipped `devbox-gateway.conf` both present `LDAP_SKIP_TLS_VERIFY=true` as the default; the code default is `false` (safe). The docs could lead an operator to believe verification is already off — or to explicitly set it off "to match". Also stale: the README "Features" bullet still claims *base image auto-download* (removed; boot now fails without operator-supplied images), and AGENTS.md/README repo layout reference root files (`dashboard.go`, `console.go`) that moved into `internal/`.
12. **`UpdateVMResources` returns raw internal errors to the browser** (`handlers.go` resources route sends `err.Error()`, which can carry libvirt detail); every sibling route uses a generic message.
13. **`.rdp` files hardcode port 443** (`GenerateRDPContent`: `full address:s:%s:443`) while `LISTEN_ADDR`/`SSH_TUNNEL_REMOTE_ADDR` are configurable — a non-443 deployment silently produces broken connect files. Derive the port from config or validate the combination at boot.
14. **Invalid config values are silently swallowed:** a typo like `TIMEOUT=10sec` or `MAX_CONCURRENT_CONNECTIONS=1k` parses as *default* with no warning (`internal/config/config.go` setters ignore parse errors). Fail fast or log loudly.
15. **`cert.NewTLSManager` calls `log.Fatalf` on cert-load failure**, bypassing `bootGateway`'s error path (the `return nil, err` after it is dead code) and any cleanup. Return the error like every other boot step.
16. **Login lockout enables username denial-of-service:** 5 bad passwords lock a username across all IPs for 15 min (by design, and configurable) — an attacker who knows usernames can keep victims locked out indefinitely. Consider IP-scoped lockout plus CAPTCHA-style friction, or document the tradeoff.
17. **Test suite is not runnable outside CI:** integration tests hard-require a local libvirtd, Docker, and an internet-fetched base image with no `t.Skip` guards — `go test ./...` fails on a stock dev machine (verified: 12/15 packages pass here; `virt`, `ldap`, `rdp` fail purely on missing infrastructure). Add skip guards or a build tag so contributors get a clean signal.

### Low / polish

- systemd unit runs the gateway as root with no sandboxing directives (`ProtectSystem=`, `NoNewPrivileges=`, etc.); the container likewise runs as root with the libvirt socket mounted (effectively host-root — inherent to the design, worth stating). The unit's `CAP_NET_BIND_SERVICE` suggests a non-root ambition worth pursuing.
- Cloud-init keyboard layout is hardcoded to Danish (`dk`) in `internal/virt/ubuntuiso.go`.
- `getRemoteGatewayRotuer` typo; `cv_session` cookie name; embedded static file server exposes directory listings (harmless, all assets are public).
- Lint/gosec invoked with `@latest` (unpinned tool versions) in the makefile; CI passed lint on `main`, but builds are not reproducible over time.
- Bus factor is 1 (45 of 51 human commits by one author; project ~7 months old). No SECURITY.md / vulnerability-reporting channel.

---

## Verification performed

- Read all production Go packages, the UI TypeScript, deployment artifacts, CI workflows, and README end-to-end.
- `go build ./...`, `go vet ./...`, `gofmt`, and `golangci-lint run` (the repo's own config) — all clean locally, 0 issues (Go 1.25, libvirt headers installed).
- `go test`: all 12 infrastructure-independent packages pass locally, plus ~60 root-package handler/limiter/listener tests; `virt`/`ldap`/`rdp` integration failures here are environmental (no libvirtd/Docker in the review sandbox — CI's latest `Go` run on `main` is green including these).
- govulncheck: confirmed via the failing CI run's log — exactly one finding (GO-2026-5932), confined to `cmd/mkdeb`; none in the gateway binary.
- GitHub Actions history: `Go` workflow green on `main`; `govulncheck` red since 2026-07-13; releases auto-published through v0.1.78.

## Suggested order of work

1. License file (trivial, unblocks everything else).
2. Green the govulncheck gate (replace debpkg or scope the scan).
3. WebSocket read limits (one-line fixes).
4. Per-user quotas + async VM creation.
5. Metrics + structured logging.
6. Doc corrections (`LDAP_SKIP_TLS_VERIFY` default, auto-download claim, layout), `.rdp` port, config-parse warnings, `log.Fatalf`, error-message hygiene.
7. Test skip guards for machines without libvirt/Docker.
