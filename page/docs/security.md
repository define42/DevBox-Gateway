# Security notes

- Do **not** commit real certificates, private keys, production LDAP
  endpoints, or real Splunk HEC tokens. The files under `testldap/` and
  `testsplunk/`, and the Splunk credentials in `docker-compose.yml`, are
  intended for local development only.
- Every VM has a host-enforced MAC/IPv4 binding and a unique pinned backend
  certificate. Network filtering rejects guest spoofing; TLS verification
  independently rejects a redirected connection to the wrong VM. Root access
  to the hypervisor and its libvirt socket remains a trusted administrative
  boundary. Keep unrelated guests off the gateway's dedicated bridge.
- RDP access is gated by an explicit, single-use authorization rather than a
  standing login: the gateway admits a proxied RDP connection only when the VM's
  owner clicked **RDP** for that VM, from the same client IP, within the last
  2 minutes (see `rdpConnectWindow` in `internal/session`), and each click
  authorizes exactly one connection (the grant is consumed on use — see
  `ConsumeRDPConnectGrant`). The VM's own RDP login still applies on top. Note the
  token is bound to the source IP. A host behind the same NAT could spend it
  during the window only if it also obtains the random token, for example by
  intercepting the pre-TLS request (and would still face the VM's RDP login).
  Because consumption happens at connection time, a connection that fails
  after authorization spends the grant, and reconnecting requires clicking
  **RDP** again.
- Logout is user-wide within the running gateway process: a valid `POST
  /logout` destroys all active browser sessions for that username and closes
  tracked live RDP, serial-console, and VNC WebSocket connections. External
  directory changes are checked at the next LDAP login. Existing browser
  sessions retain their cached identity and role until logout or expiry, and
  can authorize new connections during that time. Already-open streams are
  not continuously re-checked against LDAP.
- All environment-backed parameters must be defined in
  `internal/config/config.go`. Reading `os.Getenv` directly from feature code
  is not allowed and is enforced by `make lint`.
- The public listener defaults to `:443` and is configurable with `LISTEN_ADDR`.
  There is no public plaintext HTTP listener. An optional profiler listener,
  configured with `PPROF_LISTEN_ADDR`, uses HTTP on a literal loopback IP.
