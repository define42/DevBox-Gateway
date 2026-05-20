# RDP-TLS-Gateway

[![codecov](https://codecov.io/gh/define42/rdp-tls-gateway/graph/badge.svg?token=HS2KD8YHNG)](https://codecov.io/gh/define42/rdp-tls-gateway)

## UI (TypeScript)

Dashboard UI source lives in `ui/dashboard.ts`. Rebuild the embedded asset with:

```sh
tsc -p tsconfig.json
```

The compiled output is `static/dashboard.js`.

## Disabling clipboard and drive redirection

The gateway can enforce a "no clipboard" and/or "no local drive mapping"
policy on every RDP session it proxies, independently of the client
configuration or the VM-side Group Policy. When enabled, the gateway parses the
client's MCS Connect Initial PDU after the TLS handshake and renames the
`cliprdr` and/or `rdpdr` static virtual channel entries in the CS_NET block to
unused names. The server allocates MCS channel IDs as usual (so the RDP
connection still establishes) but no clipboard or drive redirection service is
ever bound to the renamed channels.

| Environment variable     | Default | Effect                                                                          |
|--------------------------|---------|---------------------------------------------------------------------------------|
| `RDP_DISABLE_CLIPBOARD`  | `false` | When `true`, strip the `cliprdr` virtual channel so clipboard redirection is disabled. |
| `RDP_DISABLE_DRIVES`     | `false` | When `true`, strip the `rdpdr` virtual channel so local drive mapping (and other RDPDR redirections such as printers and smart cards over RDPDR) is disabled. |

