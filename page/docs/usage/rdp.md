# Connecting an RDP client

Always connect by downloading the per-VM `.rdp` file from the dashboard — do
**not** try to point a client at the gateway by hand. Click the VM's **RDP**
button to get a ready-to-use file (named after the VM, e.g.
`alice-desktop.rdp`) and open it in an RDP client (mstsc, FreeRDP,
Remmina, …). The file targets `FRONT_DOMAIN` and the public port selected by
`RDP_PORT` or `LISTEN_ADDR` (`443` by default), with the routing token and TLS
settings included.

**Each downloaded file contains a new, single-use token valid for 2 minutes.**
Clicking **RDP** authorizes one connection for that VM and downloads its file.
Open the file in your RDP client within that window. The token is consumed
atomically after the frontend TLS handshake succeeds and before the gateway
connects to the VM. A consumed token cannot be reused, including after a failed
backend connection; click **RDP** again to reconnect.

Downloaded files use the shared `FRONT_DOMAIN` hostname and carry the token in
`loadbalanceinfo`:

```ini
full address:s:desktop.example.com:443
loadbalanceinfo:s:0123456789abcdef0123456789abcdef
```

Each token contains 16 cryptographically random bytes encoded as 32 lowercase
hexadecimal characters. The gateway stores its association with the VM, the
issuing browser session, the owner, the client's IP, and the expiry time. It
checks these conditions when admitting the connection. Clicking **RDP** again
for the same VM in the same browser session replaces that session's previous
token for the VM. Logging out or losing the issuing session invalidates its
unused tokens, and a gateway restart invalidates all outstanding tokens.
The two-minute limit applies to starting a connection; it does not disconnect
an active desktop session.

Configure DNS and a frontend certificate for the single `FRONT_DOMAIN` hostname.
ACME manages only this hostname. RDP routing requires the `loadbalanceinfo`
token; TLS SNI does not select a VM. VM subdomains and their wildcard DNS or
frontend certificates are unnecessary. **Older HMAC-token and SNI-only `.rdp`
files no longer work; download a fresh file for each connection.**
`SNI_HASH_SECRET` and the persisted `sni_hash.secret` file are no longer used.
Existing secret files are left untouched and can be removed by the operator.

The token travels in cleartext in the initial X.224 request before TLS. TLS
authenticates the shared gateway hostname but does not bind that pre-TLS token
to the connection. Randomness, a short expiry, and single use limit guessing
and replay, but do not prevent an active network intermediary from intercepting
or replacing a token. The gateway still enforces the issuing session, VM
ownership, and client IP checks, including for an intercepted token.

The gateway requires TLS-protected RDP (`PROTOCOL_SSL`); clients and backends
that only offer the legacy Standard RDP Security will be rejected. Backend TLS
connections require TLS 1.2 or newer.
