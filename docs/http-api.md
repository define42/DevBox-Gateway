# HTTP and WebSocket endpoints

These routes serve the bundled browser UI. This reference describes the current
implementation; it does not establish a versioned API contract. The gateway
disables Huma's OpenAPI, documentation and schema endpoints.

## Authentication and request rules

- Login creates the `cv_session` cookie with `Secure`, `HttpOnly`, `SameSite=Lax`
  and path `/`. Sessions have a 30-minute absolute lifetime and are held in
  memory, so a gateway restart requires a new login.
- A session is bound to the client's IP from the connection's `RemoteAddr`.
  A request from a different IP invalidates it. Forwarded-IP headers do not
  supply the session identity.
- Authenticated HTTP routes redirect a missing or expired session to `/login`
  with `303 See Other`. A client following redirects may receive an HTML login
  page instead of JSON. WebSocket handlers return `401` before upgrade when
  authentication is missing; administrator checks return `403` for non-admins.
- Every POST listed below requires an `Origin` matching the request's scheme
  and host, including any explicit port. If `Origin` is absent, a matching
  `Referer` is required. After authentication where required, an invalid or
  missing origin/referrer is rejected with `403`. Unauthenticated dashboard
  requests redirect to login before this check. Use HTTPS and send the session
  cookie on authenticated requests.
- Ordinary form requests use `application/x-www-form-urlencoded` and have a
  1 MiB body limit. Base-image uploads use the separate multipart limit below.

See [session handling](../internal/session/session.go) and
[HTTP handlers](../internal/gateway/handlers.go).

## HTTP routes

| Method | Path | Access | Purpose and input |
| --- | --- | --- | --- |
| GET | `/` | Public | Redirect to `/login` with `303`. |
| GET | `/login` | Public | Render the login form. |
| POST | `/login` | Public, same-origin | Authenticate `username` and `password`; username is the bare directory name without `@domain`. Also accepts HTTP Basic credentials on this route. Success sets the session cookie and redirects to `/api/dashboard` with `303`. |
| POST | `/logout` | Same-origin | Clear the current session; for an authenticated user, remove all their sessions and request closure of tracked connections. Redirect to `/login` with `303`. No form fields. |
| GET | `/static/*` | Public | Embedded dashboard, noVNC and other browser assets. |
| GET | `/api/health` | Public | Listener liveness: `200` with `ok\n`. |
| GET | `/api/ready` | Public | Audit and collector readiness: `200` with `ready\n`, or `503` with `not ready\n`. No backend details in the response. |
| GET | `/api/dashboard` | Session | Render the user's dashboard. |
| GET | `/api/dashboard/data` | Session | JSON inventory for the user, including available base images. HTTP bootstrap sets `rdpReady` to false; the dashboard WebSocket probes readiness. |
| POST | `/api/dashboard` | Session, same-origin | Create a VM using the fields below. Returns JSON or an opted-in NDJSON progress stream. |
| POST | `/api/dashboard/start` | Owner or administrator, same-origin | Start the VM selected by `vm_name`. |
| POST | `/api/dashboard/restart` | Owner or administrator, same-origin | Reboot the selected VM, or start it if shut off; field `vm_name`. |
| POST | `/api/dashboard/shutdown` | Owner or administrator, same-origin | Request graceful ACPI shutdown of `vm_name`. Success means the request was accepted; it does not wait for the guest to stop or automatically force power off. |
| POST | `/api/dashboard/power-off` | Owner or administrator, same-origin | Immediately power off `vm_name` through libvirt's destroy operation. This can lose unsaved work or damage files. The dashboard asks for confirmation before calling this route; API clients must obtain their own user confirmation. |
| POST | `/api/dashboard/remove` | Owner or administrator, same-origin | Remove the selected VM and its managed volumes; field `vm_name`. |
| POST | `/api/dashboard/rdp` | Owner, same-origin | Download an `.rdp` file for `vm_name`, containing a short-lived, single-use routing token bound to the session and client IP. Administrator status does not bypass ownership. |
| GET | `/api/admin` | Administrator | Render the administrator dashboard. |
| GET | `/api/admin/data` | Administrator | JSON inventory across users. |
| GET | `/api/admin/base-images` | Administrator | JSON with `baseImages`, `maxUploadBytes` and `availableStorageBytes`; failures may include `error`. |
| POST | `/api/admin/base-images` | Administrator, same-origin | Upload one `multipart/form-data` file part named `base_image`, with its filename in `Content-Disposition`. Success returns `201`. |
| POST | `/api/admin/base-images/delete` | Administrator, same-origin | Delete the image named by the `base_image` form field. |

For existing VM actions, submit the full `name` returned by the inventory,
including its owner prefix. Administrator lifecycle actions target an existing
persistent libvirt domain. For creation, `vm_name` is only the hostname portion;
the gateway adds the authenticated owner prefix.

Once removal starts, the persistent definition and ownership remain until
managed volume and network cleanup succeeds. If cleanup fails, the same owner
or an administrator can retry `/api/dashboard/remove` after restoring the
dependency. Power actions return `409` while deletion is pending; this
state survives gateway restarts.

Login failures normally render the HTML login form with an error and status
`200`; rate limiting returns `429` with `Retry-After`. Do not treat status `200`
alone as a successful login.

Dashboard actions normally return `{"ok":true,"message":"..."}` or
`{"ok":false,"error":"..."}`. Validation failures use `400`, denied actions
use `403`, creation conflicts use `409`, and operation failures generally use
`500`. Middleware and WebSocket errors can be redirects or plain text instead.
See [response types](../internal/dashboard/dashboard.go) and
[base-image handlers](../internal/gateway/handlers_base_images.go).

### VM creation fields

| Field | Required | Meaning |
| --- | --- | --- |
| `vm_name` | Yes | Valid hostname for the new VM. |
| `vm_base_image` | Yes | Exact filename from the available base-image list. |
| `vm_username` | No | Guest account name; defaults to the gateway username. Must start with a lowercase letter or underscore, contain only lowercase letters, digits, hyphens or underscores, and be at most 32 characters. |

CPU and memory come from `VM_VCPU_COUNT` and `VM_MEMORY_MIB`, not form fields.
The guest password comes from the salted hash retained at login. There is no
guest-password form field; a session without the required hash must log in again.

### Creation progress

Send `Accept: application/x-ndjson` to request progress. The first progress
record commits a `200` response with
`Content-Type: application/x-ndjson; charset=utf-8`. Each line is a JSON object:

```json
{"type":"progress","copiedBytes":524288,"totalBytes":1048576}
{"type":"progress","copiedBytes":1048576,"totalBytes":1048576}
{"type":"result","ok":true,"message":"VM created."}
```

These are illustrative values. Progress describes disk copying. The terminal
`result` carries the creation outcome; after streaming starts, a failure is a
`result` with `ok:false` and `error`, while the HTTP status remains `200`.
Failures before streaming starts use the ordinary JSON response and status.
Even when NDJSON was requested, check `Content-Type` before selecting a parser.
If the connection ends without a result, inspect the inventory before retrying.
Implementation: [creation stream](../internal/dashboard/creation_stream.go).

### Base-image uploads

Use `.img`, `.qcow2` or `.raw` filenames with QCOW2 content. The upload limit is
the configured VM disk capacity (`VM_DISK_SIZE_GB`); the HTTP request has an
additional 1 MiB allowance for multipart overhead. Read `maxUploadBytes` from
the listing response. Existing filenames are rejected rather than overwritten.
See [base-image storage](../internal/virt/internal/storage/images.go).

## WebSocket routes

All routes below use an authenticated HTTPS WebSocket upgrade (`wss://`).

| Path | Access | Stream |
| --- | --- | --- |
| `/api/dashboard/ws` | Session | User VM snapshots and application ping/pong messages. |
| `/api/admin/ws` | Administrator | Inventory across users and host metrics. |
| `/api/dashboard/console/{name}/ws` | VM owner | Serial terminal input and output. |
| `/api/dashboard/vnc/{name}/ws` | VM owner | VNC transport used by the embedded noVNC client. |

Use the inventory's full VM name for `{name}`. Serial/VNC access requires
ownership even for administrators. The WebSocket origin check permits an absent
`Origin`; when present, its host must match the request host. This differs from
the POST origin check, which also checks the scheme and requires an origin or
referrer.

Dashboard control sockets close at the session deadline. Existing serial/VNC
streams do not close solely because that deadline passes; explicit logout
requests closure of tracked connections. For message formats and connection
limits, see [dashboard sockets](../internal/console/dashboard_socket.go),
[serial](../internal/console/serial.go), [VNC](../internal/console/vnc.go) and
[shared WebSocket handling](../internal/console/console.go).

## Health and readiness checks

For the bundled local stack with its self-signed development certificate:

```sh
curl --insecure --fail https://localhost/api/health
curl --insecure --fail https://localhost/api/ready
```

Use normal certificate verification for a deployment with a trusted certificate.
`/api/health` accepts requests without authentication and is registered without
a method restriction; `GET` is sufficient. Its `200` response confirms that the
HTTP listener serves requests.

`GET /api/ready` checks application audit persistence status and the mandatory
guest collector. It returns plain text, disables caching, and includes no VM
identities, storage paths or backend errors. A stopped collector, known output
failure, failed or stale expected-VM inventory, overdue agent or pending stream
alert or sequence-gap report makes it return `503`. Gap reports remain pending
while their output write is in progress and retry every second independently
of guest traffic or inventory queries. Accepting a gap report records loss;
it does not establish delivery of the missing original events.

The gateway refreshes running managed VM expectations every 15 seconds. A
snapshot older than 45 seconds is stale. New expectations allow
`SAURON_AGENT_STARTUP_GRACE` (default `5m`) before first contact;
`SAURON_AGENT_TIMEOUT` (default `90s`) bounds later silence. Inventory and stream
conditions recover automatically. A rejected guest record clears only when a
retry of its retained copy or replay with matching VM identity, original event
boot ID and sequence is accepted by every configured output. A separate worker
retries up to 64 retained records every second with a five-second context deadline per
pass, preserving their original attribution after disconnect or identity
recovery. Heartbeats and unrelated successful writes cannot clear a rejection.
Generic collector write/flush failures may clear after a later successful write
to every output. Background retries do not advance guest acknowledgements;
normal guest acceptance still does that, and duplicate output is possible.

When fresh inventory can resolve a previously unknown or incomplete guest
identity, its next valid event or heartbeat triggers a reconnect. The new
connection is resolved by the collector and can satisfy that VM's stream check.
Concurrent sessions sharing a peer or trusted VM UUID serialize event
acceptance, so a duplicate cannot race the accepted copy's deduplication commit.
Originals are registered before blocking identity or output work, preventing
concurrent loss reports from acknowledging a received event before storage.
When the per-stream accounting limit of 64 accepted loss ranges is full, reports
wait for capacity before another output attempt; other streams continue.

The gateway retains up to 4096 rejected records and 64 MiB of encoded data in
memory, separately from its 4096 queued stream alerts. Overflow or failure to
retain a copy requires operator recovery and restart. Arrival protection is
also bounded by the effective deduplication window; its overflow requires the
same recovery. Investigate delivery before restarting: restart discards pending
copies and health state without establishing that the records arrived.
Application audit persistence failures also require investigation and restart. See
[output recovery](../SauronAgent/docs/deployment.md#output-failure-recovery).
An unexpected collector exit terminates the gateway with exit status 1.

Readiness reports observed failures; it does not probe LDAP, free disk space or
Splunk searchability, and a remote HEC outage alone does not fail it while local
spooling succeeds. A `503` does not itself block other HTTP or RDP requests.
See [readiness handling](../internal/gateway/readiness.go) and
[audit delivery boundaries](../compliance.md#delivery-and-compliance-boundaries).
