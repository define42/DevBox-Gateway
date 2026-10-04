# Architecture

The gateway shares TCP port `:443` between its HTTPS dashboard and RDP proxy.
Connections are demultiplexed by sniffing the first byte on the accepted TCP
socket: a TLS handshake record (`0x16`) is routed to the HTTPS handler, anything
else is treated as an RDP X.224 Connection Request. LDAP authentication gates
dashboard access and authorization for proxied RDP connections.

```
                  ┌──────────────────────── TCP :443 ────────────────────────┐
client ──TLS──►   │  byte-sniff: 0x16 → HTTPS, else → RDP X.224              │
                  └──────────────┬──────────────────────────┬────────────────┘
                                 │                          │
                       HTTPS / WebSocket                 RDP / TLS
                                 │                          │
                ┌────────────────▼─────────────┐  ┌─────────▼─────────────────┐
                │ chi router + Huma API        │  │ Read token, terminate TLS │
                │  /login, /logout             │  │ → dial backend VM         │
                │  /api/dashboard/*            │  │ → new RDP TLS handshake   │
                │  /api/dashboard/console/...  │  │ → bidirectional proxy     │
                │  /api/dashboard/vnc/...      │  └─────────┬─────────────────┘
                │  static assets               │            │
                └────────────────┬─────────────┘            │
                                 │                          │
                       LDAP bind / session                  │
                                 │                          │
                  ┌──────────────▼──────────────────────────▼────────────────┐
                  │              libvirt (QEMU/KVM) on the host              │
                  └──────────────────────────────────────────────────────────┘
```

The RDP flow on the front side is:

1. Read the client's X.224 Connection Request (TPKT) and its routing token.
2. Reply with an X.224 Connection Confirm selecting `PROTOCOL_SSL` (TLS).
3. Complete the TLS handshake and resolve the required token to a VM. Missing,
   invalid, and unknown routing tokens are rejected.
4. Authorize the VM owner and consume the single-use Connect grant.
5. Load the VM's host-assigned address and provisioned certificate identity,
   then TCP-connect to the backend.
6. Send a fresh Connection Request to the backend requesting TLS only.
7. Read the backend's Connection Confirm and require `PROTOCOL_SSL`.
8. Verify the backend certificate and its provisioned server name during TLS.
9. Splice bytes between client TLS and backend TLS for the rest of the session.

On shutdown, the gateway stops accepting HTTP requests and gives active handlers
up to 5 seconds to finish. It then cancels remaining requests and closes their
connections, allowing up to another 5 seconds for cleanup before closing the
audit sink. Cancelled VM creation rolls back its partially created resources;
interrupted image uploads remove their temporary files. RDP and WebSocket
sessions are drained separately.
