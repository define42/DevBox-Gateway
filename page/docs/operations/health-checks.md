# HTTP endpoints and health checks

The [HTTP endpoint reference](../reference/http-api.md) describes the dashboard routes,
authentication, request formats, and WebSocket endpoints. OpenAPI, schema, and
interactive API-documentation routes are disabled in the gateway.

Both probes are public and return plain text:

| Probe | Response | Meaning |
| --- | --- | --- |
| `GET /api/health` | `200` with `ok\n` | HTTP listener liveness. |
| `GET /api/ready` | `200` with `ready\n`, or `503` with `not ready\n` | Application audit persistence, capacity and delivery status, plus guest collector readiness including expected agents, inventory freshness, pending stream alerts and unreported sequence gaps. |

Readiness responses contain no VM identities, storage paths or backend errors.
The probe reports known failures; it does not test LDAP, free disk space or
whether Splunk events are searchable. A remote HEC outage leaves readiness
healthy while events queue durably below 90% spool usage, until application-audit
delivery has kept failing for `SPLUNK_HEC_STALL_TIMEOUT`. A rejected guest record keeps readiness
unhealthy until the record is accepted by every configured output. The gateway
retains copies of rejected records and retries them every second, preserving
their original attribution even after a guest disconnects or its identity
resolves. Guest replay can also recover a matching failure; unrelated events
and heartbeats cannot clear it. Generic collector write/flush failures can clear
after a later successful write to every output. Retained retries are bounded at
4096 records and 64 MiB of encoded data. Overflow or failure to retain a copy
requires operator recovery and restart. These copies and their health state
are lost on restart, so investigate delivery before restarting. Application
audit persistence errors also require investigation and
restart to clear. See [output recovery](https://github.com/define42/DevBox-Gateway/blob/main/SauronAgent/docs/deployment.md#output-failure-recovery)
for the matching and recovery rules.
Application-audit capacity pressure and persistence failures also refuse new
mutations and streams; logout, ordinary reads and probes remain available.
Other readiness failures do not themselves block dashboard or RDP access.

For the local Compose setup with a self-signed certificate:

```sh
curl --insecure --fail https://localhost/api/health
curl --insecure --fail https://localhost/api/ready
```

Use certificate verification when probing a deployment with a trusted certificate.
