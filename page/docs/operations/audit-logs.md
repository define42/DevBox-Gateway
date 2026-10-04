# Audit logs and Splunk

See [compliance.md](https://github.com/define42/DevBox-Gateway/blob/main/compliance.md) for the NATO AC/35-D/2003-REV5 §26.3.1
coverage comparison, audit-rule and event inventories, Splunk index routing,
JSON event examples and remaining compliance gaps.

Application audit events use one output: Splunk HEC when
`SPLUNK_HEC_ENDPOINT` is nonblank, or `AUDIT_LOG_FILE` when it is unset.
In HEC mode the file setting is ignored. Existing audit files remain on disk;
the gateway does not open or append to them.

With HEC disabled, events are appended to the required `AUDIT_LOG_FILE` as
JSON Lines (NDJSON): each physical line is an independently parseable JSON
event. The native packages default to `/var/log/devbox-gateway/audit.jsonl`;
systemd creates its parent directory before starting the gateway. Docker
Compose configures `/data/logs/audit.jsonl` for use if application HEC is
disabled, visible on the host through the `/data` bind mount. The supplied
Compose deployment enables HEC, so it does not write this application file.

With application HEC disabled, configure the Splunk Universal Forwarder with
a file monitor for the selected path and set the source type to `_json`.
For example:

```ini
[monitor:///var/log/devbox-gateway/audit.jsonl]
disabled = false
sourcetype = _json
index = main
```

The audit file is deliberately not a credential store, but it contains user,
source-address, VM, resource, result, protocol, and duration metadata. Keep it
access-controlled. If the forwarder runs as a dedicated `splunk` user, grant
that account read/traverse access after the service has created the path:

```sh
sudo setfacl -m u:splunk:rx /var/log/devbox-gateway
sudo setfacl -m u:splunk:r /var/log/devbox-gateway/audit.jsonl
```

File mode fsyncs each record and follows external rename-and-create rotation:
rename the old file and create a replacement at `AUDIT_LOG_FILE`. The next
write detects the replacement and reopens it; a write racing rotation may land
in the renamed file. Configure retention externally and preserve the gateway's
write permissions and any forwarder read permissions on replacement files.
`copytruncate` is unsupported because truncation can discard concurrent writes.

An application audit persistence error is logged to the operational log and
makes `/api/ready` return `503`. This state remains until restart, even if later
writes succeed: the failed record cannot be reconstructed automatically.
Investigate the failure, restore storage and account for the audit gap before
restarting. User actions are not rolled back when their audit write fails.

Ordinary process diagnostics remain available through `journalctl` (or Docker
logs); application audit events go to the selected audit output.

## Forwarding to Splunk HEC

As an alternative to a Universal Forwarder, the gateway can send application
audit events directly to a Splunk HTTP Event Collector. Set the endpoint and token
(and optionally the index):

```ini
SPLUNK_HEC_ENDPOINT=https://splunk.example.com:8088
SPLUNK_HEC_TOKEN=11111111-2222-3333-4444-555555555555
SPLUNK_HEC_INDEX=devbox_audit
# Opt in only after enabling indexer acknowledgement on this HEC token.
SPLUNK_HEC_ACK_ENABLED=false
DEVBOX_GATEWAY_SPOOL_MAX_MIB=10240
```

- HEC is the sole application audit destination. `AUDIT_LOG_FILE` is ignored,
  even if empty or unwritable. Existing files are left in place, but no local
  application audit file is created, opened or appended in HEC mode.
- Each event arrives on the JSON event endpoint with `source=devbox-gateway`,
  `sourcetype=devbox-gateway:audit`, the gateway's hostname as `host`, and the
  same JSON schema used in file mode as the event body. The token
  must be allowed to write to `SPLUNK_HEC_INDEX`. When the token uses indexer
  acknowledgement, enable the corresponding gateway ACK setting below.
- Before the delivery sink accepts an event, it appends and fsyncs it under
  `<DATA_ROOT_DIR>/audit-spool`. A background worker sends persisted events in
  order and resumes from the spool after a gateway or Splunk restart. Pending
  events do not expire merely because an outage is long.
- Configure the collector's direct URL: redirects are not followed. With
  `SPLUNK_HEC_ACK_ENABLED=false` (the default), delivery succeeds when a `2xx`
  response contains valid HEC JSON with `code: 0`; no ACK request is made.
  Network failures, redirects, `400`, `403`, every other non-success status,
  invalid response bodies, and nonzero HEC codes retain the pending event and
  retry with backoff; no HEC rejection is treated as permission to drop it.
- The one exception is Splunk refusing the events themselves (`413`, or `400`
  with HEC code 6, 12, 13 or 15). The gateway then resends that batch one event
  at a time, so a batch that was only too large is still delivered whole. An
  event Splunk refuses on its own is appended and fsynced, as its complete HEC
  envelope, to `<DATA_ROOT_DIR>/audit-spool/rejected.jsonl` before delivery
  moves past it, and a process diagnostic names the file. Review that file and
  resubmit its envelopes once the cause is fixed; it is never rotated or
  truncated by the gateway. If it cannot be written, delivery pauses instead.
- Set `SPLUNK_HEC_ACK_ENABLED=true` to require indexer acknowledgement for
  application audits. The Splunk deployment must support HEC indexer
  acknowledgement and the token must have it enabled. The gateway sends a GUID
  in `X-Splunk-Request-Channel` on both event POSTs and ACK polls, using the same
  channel and token for each delivery. It polls `/services/collector/ack` with
  the returned `ackId`; only an explicit `true` for that exact ID advances the
  spool checkpoint. A `code: 0` event response alone is insufficient in this
  mode. Splunk documents a true ACK as confirmation of the desired replication
  factor; its parsing pipeline can still discard events, so ACK does not
  guarantee indexing or searchability. See [Splunk's indexer acknowledgement documentation](https://help.splunk.com/en/splunk-enterprise/get-data-in/collect-http-event-data/about-http-event-collector-indexer-acknowledgment).
- ACK polling keeps the event pending across `false` or missing status,
  malformed replies, transport/HTTP errors, and shutdown. Each delivery polls
  for at most five minutes before the forwarder retries the stored payload
  with backoff. The ACK URL uses the event URL's scheme and host, preserving
  any proxy prefix before `/services/collector`. If a load balancer fronts
  multiple HEC instances, configure affinity so event POSTs and their ACK
  polls reach the same instance and channel. The client retains affinity
  cookies; see [Splunk's load-balancer guidance](https://help.splunk.com/en/splunk-cloud-platform/get-data-in/splunk-connect-for-kafka/2.2/configure/load-balancing-configurations-for-splunk-connect-for-kafka).
  A lost ACK response, timeout or restart can cause a payload to be resent even
  if Splunk already processed it.
- ACK mode accepts standard `/services/collector`, `/services/collector/event`
  or `/services/collector/raw` paths, including `/1.0` variants of event/raw
  and optional proxy prefixes. A URL without a path uses the standard event
  endpoint. Other custom paths are rejected at startup when ACK is enabled.
- Delivery is at-least-once. A crash after Splunk accepts an event but before
  its local checkpoint advances can cause that event to be sent twice.
- Each spool directory is exclusively locked while open. Application and guest
  HEC spools must use separate directories, and a second gateway cannot open
  the same spool, including through a directory symlink.
- `DEVBOX_GATEWAY_SPOOL_MAX_MIB` bounds the spool (10 GiB by default). At 90%
  usage, `/api/ready` returns `503`; new HTTP mutations and WebSocket upgrades
  receive `503` with `Retry-After: 5`, and new RDP connections close before
  consuming a grant. Logout, ordinary reads and probes remain available.
  Admission resumes automatically when delivery frees enough capacity. The
  remaining 10% is headroom for work already admitted and disconnect events,
  not a guarantee that every concurrent operation can finish auditing.
  At the hard limit, new audit writes fail immediately without evicting pending
  events. Already-running actions are not rolled back: any event that cannot
  be persisted is reported in process diagnostics and latches readiness and
  new audited activity unhealthy until investigation and restart.
  Size a 48-hour objective from the measured encoded event rate:
  `bytes/second × 172800 × operational headroom`, converted to MiB. The default
  size is a byte limit, not a 48-hour guarantee.
- HEC remains the sole application audit output: acknowledged spool records are
  reclaimed, and the spool is not a permanent `audit.jsonl` copy or file
  fallback. SauronAgent guest logging and `SAURON_SPOOL_*` are separate.
- Disk failures, a single event too large for the spool, or writes attempted
  while the sink is closing are surfaced in process diagnostics and latch
  application audit readiness as unhealthy until restart. Monitor these errors
  and spool capacity through `journalctl` or Docker logs.
- Delivery that keeps failing for `SPLUNK_HEC_STALL_TIMEOUT` (one hour by
  default), such as a revoked token, a wrong index or a long outage, makes
  `/api/ready` return `503`. This delivery timeout alone does not reject new
  activity while local capacity remains available. Readiness recovers once a
  batch is delivered. Set it to `0` to disable this delivery-timeout check;
  capacity and persistence checks remain enabled.
- On shutdown, final worker events have a five-second acceptance window; full
  spools still reject immediately. Delivery gets a bounded drain period, and
  records already in the spool remain available for replay after restart.
- The gateway refuses to start when `SPLUNK_HEC_ENDPOINT` is set without
  `SPLUNK_HEC_TOKEN`, or when a token, index or enabled ACK setting lacks an
  endpoint. Leave ACK disabled in file mode.
  Invalid HEC configuration fails startup; it does not select file logging.
- Splunk's default HEC certificate is self-signed. Prefer installing the CA
  that signed it into the host (or container) trust store; set
  `SPLUNK_HEC_SKIP_TLS_VERIFY=true` only as a stopgap. A plain `http://`
  endpoint is accepted but sends the token unencrypted and logs a warning.

A search such as `index=devbox_audit sourcetype="devbox-gateway:audit"
action=user.login result=failure` then works without any additional props
configuration: Splunk extracts the JSON fields at search time.
