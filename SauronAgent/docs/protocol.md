# The SAUR wire protocol

Version 1.

This document specifies the protocol between a guest agent and the host
collector precisely enough to write an independent implementation of either
end. It describes what is on the wire, not how SauronAgent's Go packages are
organised.

The reference implementation lives in `internal/protocol` (`frame.go` for the
framing, `message.go` for the payload types).

## 1. Transport

A session is one `AF_VSOCK` `SOCK_STREAM` connection. The guest dials
`VMADDR_CID_HOST` (CID 2) on the collector's port, 9000 by default. The
collector binds `VMADDR_CID_ANY` and accepts from any CID.

A TCP transport implementation exists for development and integration tests.
The production agent's compiled settings select VSOCK. The framing is identical
over TCP; what is lost is the authoritative peer identity, because a TCP peer
address is a claim and a CID is not.

Nothing is layered under or over the framing: the connection carries a stream
of frames and nothing else. There is no length-prefixed record layer, no TLS
and no compression.

## 2. Frame layout

Every frame is a 20-byte header followed by an optional payload. **All
multi-byte integers are big-endian.**

```text
 offset  size  field
 ------  ----  --------------------------------------------------------------
      0     4  Magic          "SAUR" (0x53 0x41 0x55 0x52)
      4     1  Version        1
      5     1  Type           message type, see section 3
      6     2  Flags          uint16, reserved, MUST be 0
      8     8  Sequence       uint64, see section 6
     16     4  Payload length uint32, byte count of the payload
     20     N  Payload        N bytes, a single JSON value, see section 4
```

A complete ACK frame, byte for byte:

```text
00000000  53 41 55 52 01 04 00 00  00 00 00 00 00 00 00 00  |SAUR............|
00000010  00 00 00 13 7b 22 73 65  71 75 65 6e 63 65 22 3a  |....{"sequence":|
00000020  31 38 34 32 31 33 7d                              |184213}|
```

That is: magic `SAUR`, version 1, type 4 (ACK), flags 0, header sequence 0,
payload length 0x13 = 19, then the 19 payload bytes `{"sequence":184213}`.
39 bytes in total.

### Receiver requirements

A receiver MUST validate the whole header -- magic, version, type, flags and
length -- before reading a single payload byte, and MUST NOT allocate a buffer
from the length field until that length has been checked against its own
limit. The length field is the one place where a peer chooses the size of an
allocation on the other end; a 20-byte header must never be able to cost a
receiver an arbitrary amount of memory.

A receiver MUST reject, and close the connection on:

| Condition | Meaning |
|---|---|
| magic is not `SAUR` | the stream is not carrying Sauron frames |
| version is not 1 | the peer speaks a protocol this build does not |
| type is 0 or greater than 8 | undefined message type |
| flags is not 0 | a reserved bit was set |
| payload length exceeds the receiver's limit | see section 5 |

Reserved flags are rejected rather than ignored, deliberately: if a future
version gives a flag semantic meaning, an older receiver that ignored it would
silently misinterpret the frame instead of refusing it.

## 3. Message types

| Value | Name | Sent by | Payload |
|---|---|---|---|
| 1 | `HELLO` | agent | `Hello` |
| 2 | `READY` | host | `Ready` |
| 3 | `EVENT` | agent | `EventMessage` |
| 4 | `ACK` | host | `Ack` |
| 5 | `PING` | agent | `Ping` |
| 6 | `PONG` | host | `Pong` |
| 7 | `ERROR` | either | `ErrorMessage` |
| 8 | `SHUTDOWN` | either | `Shutdown` |

## 4. Payload encoding

The payload is exactly one JSON value, UTF-8 encoded, with no trailing newline
and no second document. Bytes after the end of the JSON value -- other than
insignificant whitespace -- MUST be rejected: accepting them would let a peer
smuggle a second document past a parser that stops at the first.

Unknown object members MUST be accepted and ignored. An agent and a collector
of different vintages have to interoperate, and a newer peer adding a field
must not take the stream down.

Sequence numbers are unsigned 64-bit. They appear both in the binary header
(exact) and, in some payloads, as JSON numbers. An implementation whose JSON
parser converts numbers to IEEE-754 doubles MUST take the sequence of an EVENT
from the frame header, not from the JSON body, or it will silently corrupt
values above 2^53.

### 4.1 `HELLO`

Sent by the agent as the first frame of a session.

```json
{"protocol_version":1,"agent_version":"1.0.0","hostname":"transfer03","boot_id":"5f1c7d2a-1f7e-4f41-9c33-2a5bd2c0b0e7","machine_id":"9d1f0a6c4f2b41d8a0b7c3e5d6f78901","kernel":"6.8.0-45-generic","first_sequence":184213}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `protocol_version` | uint8 | yes | must be 1 |
| `agent_version` | string | yes | build identifier of the agent |
| `hostname` | string | no | guest's own hostname |
| `boot_id` | string | no | guest boot identifier; scopes `sequence` |
| `machine_id` | string | no | persistent machine id |
| `kernel` | string | no | kernel release |
| `first_sequence` | uint64 | no | lowest sequence the agent still holds and can replay |

**Every field of HELLO is untrusted.** The collector records them under
`source.reported` and identifies the guest by the CID of the connection. A
compromised guest can put anything here, including another VM's hostname and
boot id; what it cannot do is dial from another VM's CID.

`first_sequence` is what lets the host distinguish "events 100-200 were lost"
from "the agent had already had 100-200 acknowledged and discarded them".

### 4.2 `READY`

The host's acceptance, sent in response to HELLO.

```json
{"protocol_version":1,"host_version":"1.0.0","session_id":"c2f1-0007","resume_from":184212,"max_payload_size":1048576}
```

| Field | Type | Required | Meaning |
|---|---|---|---|
| `protocol_version` | uint8 | yes | must be 1 |
| `host_version` | string | no | build identifier of the collector |
| `session_id` | string | no | identifies this connection in host logs |
| `resume_from` | uint64 | no | highest sequence already durably recorded for this (CID, boot id) |
| `max_payload_size` | uint32 | no | largest payload the host will accept |

`resume_from` is an optimisation, not a correctness requirement: the agent may
skip re-sending anything at or below it, and the host deduplicates either way.
Zero, or absent, means the host holds nothing for this stream and the agent
should send everything it has.

An agent MUST respect `max_payload_size` if it is present and smaller than the
agent's own limit. A frame larger than the host's limit is not a recoverable
error: the host will reject the frame and close the connection.

### 4.3 `EVENT`

One normalized event.

```json
{"event":{"version":1,"sequence":184213,"timestamp":"2026-09-18T17:25:45.312Z","type":"process.exec","…":"…"}}
```

The event object's schema is the normalized event model; see the README and
`internal/event/event.go`. For the protocol, only two rules matter:

1. The frame header's `Sequence` MUST equal the event's `sequence` field. A
   host receiving a frame where they disagree MUST reject it
   (`ERROR` code `bad_sequence`). Carrying the sequence in the header is what
   lets the host acknowledge and deduplicate without parsing JSON.
2. The event carries its own `boot_id`. The host uses the boot id for the
   deduplication key; see section 6.

### 4.4 `ACK`

```json
{"sequence":184213}
```

Acknowledgement is **cumulative**: acknowledging N means every sequence up to
and including N is durably held by the host, and the agent may discard all of
them from its spool. There is no negative acknowledgement and no selective
acknowledgement. A host MUST NOT acknowledge N unless every event it accepted
below N has been durably written, because the agent will delete them.

Acknowledgements are batched (`limits.ack_interval`, default every 64 events)
and time-bounded (`limits.ack_max_delay`, default 2s) so a slow trickle of
events is still released from the guest's spool promptly.

### 4.5 `PING` and `PONG`

The agent's heartbeat, sent every 30 seconds by the compiled policy.

```json
{"uptime":86400,"events_received":1502334,"events_sent":1502290,"events_spooled":44,"events_dropped":0,"audit_enabled":true,"queue_depth":12,"spool_bytes":262144}
```

```json
{"echo_uptime":86400,"unix_nano":1789752345318000000}
```

The counters are what distinguish a healthy quiet guest from one whose audit
subsystem has been switched off or whose agent is wedged: `audit_enabled:
false`, a rising `events_dropped`, or a `queue_depth` that never falls are all
visible without a single audit event arriving. `unix_nano` is the host's clock,
which lets a guest detect its own drift. All counter fields are advisory: they
come from the guest and are as trustworthy as the guest is.

### 4.6 `ERROR`

```json
{"code":"bad_sequence","message":"event sequence 184220 does not match frame sequence 184219","fatal":true}
```

| Code | Meaning |
|---|---|
| `bad_frame` | framing violation: magic, version, type, flags or length |
| `bad_payload` | the payload was not the JSON the message type calls for |
| `bad_sequence` | header and payload sequence disagree, or a sequence went backwards |
| `unexpected_type` | a message type that is not allowed in this state |
| `unauthorized` | the peer is not permitted (e.g. an unmapped CID with `allow_unknown_cids: false`) |
| `internal` | the sender failed for a reason of its own |
| `overloaded` | the sender cannot accept more right now |

`fatal: true` means the sender is about to close the connection. `message` is
free text for humans and MUST NOT be parsed.

A peer that receives ERROR with `fatal: true` should close, back off and
reconnect. Reconnecting immediately in a loop after a fatal protocol error
turns one bug into a denial of service against the collector.

### 4.7 `SHUTDOWN`

```json
{"reason":"systemd stop","last_sequence":184290}
```

Sent by either side before an orderly close, so that the peer can tell a
planned stop from a crash. `last_sequence` is the highest sequence the agent
sent. A collector SHOULD record a stream that ended with SHUTDOWN differently
from one that simply stopped: the first is maintenance, the second is the one
worth investigating.

## 5. Size limits

| Limit | Default | Defined by |
|---|---|---|
| Maximum payload, agent | 1 MiB | compiled `config.DefaultAgent` value |
| Maximum payload, host | 1 MiB | SauronHost `limits.max_payload_size` |
| Absolute ceiling | 64 MiB | compiled in (`MaxPayloadCeiling`) |

Both ends enforce their own receive limit. A value above the absolute ceiling
is clamped to it, so neither an agent build nor a host configuration mistake can
switch the protection off. A sender that would exceed its own limit MUST fail
the send locally rather than emit a frame the peer is certain to reject.

## 6. Sequence numbers, boot ids and deduplication

Every event is assigned a sequence number by the agent immediately after
normalization, before it is queued or spooled. Within one boot the sequence is
strictly increasing with no intentional gaps. Sequence 0 is reserved to mean
"no sequence" (as in `resume_from: 0`) and is never assigned to an event.

Sequence numbers are scoped by the guest's **boot id**. They restart on reboot,
and continue across an agent restart within one boot, recovered from the spool.

The deduplication key is therefore:

```text
(source CID, boot id, sequence)
```

* The **CID** comes from the connection, not from the guest.
* The **boot id** comes from the guest and is untrusted, but a guest that lies
  about it only damages its own stream's continuity.
* The **sequence** comes from the frame header.

Delivery is **at-least-once**. After a reconnect the agent re-sends everything
its spool still holds above `resume_from`, so duplicates are normal and
expected; the host suppresses them using a window of recent sequence numbers
per (CID, boot id) (`limits.dedup_window`, default 65536). The window must be
larger than the agent's built-in 1024-event unacked window by a wide margin, or
a replay after a long outage will be written twice.

A **gap** in received sequences is not the same as a duplicate and must not be
discarded quietly. Either the agent reported the loss itself -- a
`sauron.queue.overflow` or `sauron.spool.full` event names the exact missing
range -- or nobody did, and that is a finding.

## 7. Session state machine

```text
        agent                                host
          |                                    |
          |  connect (AF_VSOCK, CID 2:9000)    |
          |----------------------------------->|  accept, read peer CID,
          |                                    |  look up CID -> VM
          |  HELLO                             |
          |----------------------------------->|
          |                             READY  |
          |<-----------------------------------|
          |                                    |
          |  EVENT seq=N                       |   steady state:
          |----------------------------------->|   events flow, acks are
          |  EVENT seq=N+1                     |   cumulative and batched
          |----------------------------------->|
          |                        ACK seq=N+1 |
          |<-----------------------------------|
          |  PING                              |   every 30 seconds
          |----------------------------------->|
          |                               PONG |
          |<-----------------------------------|
          |  SHUTDOWN                          |   orderly stop (either side)
          |----------------------------------->|
          |                                    |
```

Rules:

1. The agent sends HELLO first and sends nothing else until READY arrives. The
   host bounds the wait with `limits.handshake_timeout` (default 10s) and
   closes a connection that stays silent.
2. After READY the agent may send EVENT, PING, ERROR and SHUTDOWN at any time.
   The host may send ACK, PONG, ERROR and SHUTDOWN at any time.
3. EVENT before READY, HELLO twice, or ACK from an agent are protocol errors
   (`unexpected_type`).
4. The host closes a connection that sends nothing at all, including
   heartbeats, for `limits.idle_timeout` (default 5 minutes).
5. Either side may close at any point. A closed connection loses nothing: the
   agent's spool still holds everything not yet acknowledged, and it will be
   re-sent after the reconnect.

### Reconnection

The agent reconnects with compiled exponential-backoff values and 20% jitter:
100ms initially, doubling to a 10s maximum. It keeps reading audit records and
spooling them throughout the outage. Jitter exists so that a fleet of guests
does not reconnect to a restarted collector in lockstep.

## 8. Error handling summary

An implementation must distinguish two kinds of failure, because they call for
opposite reactions:

* **Protocol errors** -- bad magic, version, type, flags, an oversized payload,
  malformed JSON, trailing data. These are statements about the peer. The
  stream is no longer parseable, so the connection is closed and the event is
  worth reporting (`sauron.protocol.violation`).
* **Transport errors** -- EOF, connection reset, a deadline. These say nothing
  about the peer's behaviour and are answered by reconnecting with backoff.

An EOF in the middle of a frame is classified as a transport error: a truncated
stream is how a connection dies, not how a peer lies.

A partially written frame is unrecoverable for the sender too. If a write fails
halfway through a frame, the connection MUST NOT be reused -- every later frame
would be read by the peer as a continuation of the truncated payload. Close and
reconnect instead.
