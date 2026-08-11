# Phase 5A — Outbound Data Gate design

Status: design only. Phase 5B has not started. This document does not authorize driver development, driver installation, test-signing, or changes to Windows security settings.

## Security objective and claim boundary

The target flow is:

```text
File read intent
  → exact process/file association
  → process-scoped network gate armed
  → destination-specific user decision
  → one-time ticket redemption
  → bounded flow grant or block
```

The gate is intended to delay selected outbound traffic after a protected disk-file read is requested and before that read is released to the application. It is not a claim that EgressGuard recognizes every upload. Windows Filtering Platform (WFP) supplies process, connection and packet/stream enforcement points; it does not supply file provenance. With TLS, HTTP/2 multiplexing, or encrypted QUIC/HTTP/3, EgressGuard cannot identify which encrypted bytes came from a file without application cooperation or content inspection. This design does neither.

The first enforcement scope excludes clipboard data, screenshots, camera input, generated data and data that exists only in RAM. It protects only a read that the minifilter actually intercepts before data is returned; it cannot retroactively protect file bytes already cached in a process. Memory-mapped and paging-I/O coverage must be measured in the 5C lab before any broader claim. The prototype must never block all Internet traffic, decrypt TLS, read or retain file content, weaken Secure Boot, enable Windows test-signing, or bypass Application Control.

## Architecture

### Components and responsibilities

| Component | Responsibility | Explicit non-responsibility |
|---|---|---|
| File-system minifilter | Observe selected pre-create/pre-read operations; form a stable file identity and exact requestor process identity; pend only eligible reads for a short bounded interval; publish a metadata-only `FileReadIntent`; release or cancel the read when the gate is armed or the deadline/failure policy fires. | Does not hash or copy content, show UI, make policy, infer a network destination, or retain a read indefinitely. |
| WFP callout | Enforce only narrowly installed process/process-group gate scopes; classify new TCP/UDP authorization and eligible established-flow outbound data; redeem a service-issued ticket atomically; install a bounded ephemeral grant. | Does not infer file provenance, parse HTTP, decrypt TLS, identify HTTP/2 or QUIC streams, or apply a machine-wide outbound block. |
| Policy Service | Own process generations, browser-group membership, file-intent/gate state, policy evaluation, timeouts, ticket issuance, bounded anti-replay state, persistent Always allow policy and critical failure alerts. Coordinate minifilter and WFP through authenticated, versioned channels. | Does not receive file bytes, packet payloads or TLS plaintext. It must not treat Phase 4 temporal correlation as proof of upload. |
| UI | Display protected metadata, destination/protocol, affected process group, expiry and limitations; collect `Allow once`, `Always allow`, or `Block`; surface critical fail-open and degraded-state alerts. | Does not talk directly to either driver, mint tickets, silently broaden policy, or claim a file was uploaded. |

The current Phase 4 ETW sensor remains separate, optional and observe-only. It can inform diagnostics but is not an enforcement authority.

### Ordered state machine

1. **Read intent.** Before an eligible non-paging disk read completes, the minifilter records the requestor as `(PID, ProcessStartTime)` and an opaque file version identity. It creates a random `IntentId`, applies a short kernel deadline, and sends metadata to the Policy Service.
2. **Association.** The service verifies that the process generation is live. For ordinary applications the gate subject is that exact process. For a supported multi-process browser, it resolves an authenticated `ProcessGroupId` whose membership is a set of exact process generations; a PID or parent PID alone never grants membership.
3. **Gate arming.** The service asks WFP to arm a volatile gate for that subject before instructing the minifilter to release the file read. The acknowledgement must prove that `ArmedCoverage` contains every capability in the request's `RequiredCoverage`; a partial acknowledgement is a fail-open condition. Arming is scoped to the subject and intent, not the whole host. The first matching outbound attempt supplies a normalized destination and protocol and transitions the intent to `AwaitingDecision`.
4. **Network hold.** New TCP/UDP authorization can be postponed only where WFP supports an initial ALE pend. A later real-enforcement phase may select a separately validated stream-layer hold for existing TCP or a datagram/transport hold for UDP/QUIC; Phase 5B uses reconnect-required simulation instead. Each hold has hard limits for time, bytes/packets, entries and memory. If a safe hold cannot be established, the prototype fails open and emits a critical alert.
5. **Decision.** The UI shows application/group, protected file label, destination IP/domain evidence, port, TCP/UDP, whether the flow pre-existed, collateral browser impact and decision expiry. The service rejects stale or mismatched replies.
6. **Ticket.** `Allow once` mints one short-lived ticket bound to the exact intent, subject, file version, destination, protocol, flow generation, boot instance and policy epoch. `Always allow` first creates a narrow persistent policy and then mints a ticket for the current hold. `Block` releases the hold as blocked; it does not create a host-wide firewall rule.
7. **Atomic redemption.** WFP accepts one valid ticket nonce exactly once and creates one ephemeral grant. Duplicate, expired, wrong-boot, wrong-generation, wrong-flow or altered tickets are rejected. The grant, not the ticket, covers the bounded packets/stream activity needed for the one authorized flow.

The minifilter must not release a protected read merely because the service received the intent. It releases only after WFP acknowledges the gate as armed, or after the explicit fail-open deadline. This ordering is the only intended protection against an application reading the file and immediately writing it to an already-open connection.

### Minifilter pending safety

Only eligible IRP-based, non-paging reads may enter the protected pending path. Fast I/O, paging I/O, memory-mapped access and any operation whose current context cannot satisfy the required IRQL, cancellation and completion rules are not pended; the prototype records a bounded critical fail-open event instead of claiming coverage.

Pending reads use a hard-bounded cancel-safe queue following the `FltCbdq` model. The design does not enqueue an unbounded number of system worker items. Every entry has one idempotent completion owner and must complete on a full-coverage gate acknowledgement, explicit disposition, request cancellation, process exit, instance teardown, service/driver shutdown, or the two-second watchdog deadline. Queue overflow releases the read fail-open and increments an exact monotonic critical counter. Stop/unload evidence must prove that every owned pending operation reached a terminal completion and that the queue is empty.

## Identity model

### Process identity and PID reuse

The protocol-visible identity remains `(PID, ProcessStartTime)` to match the existing Core model. Kernel implementations should additionally retain a non-user-controlled process-generation value, such as a process start key/object-derived generation, and map it to the protocol identity. Every lookup is revalidated at the point of minifilter intent creation, gate installation and ticket redemption. A PID with a different start time or kernel generation is a different subject; stale group membership, gates and tickets are discarded.

If exact identity cannot be obtained, enforcement is not guessed from PID alone. The prototype follows its fail-open rule and raises a critical alert.

### Browser process groups

Browsers commonly separate renderer, utility and network-service processes. A read may occur in one process while the socket belongs to another. The target architecture uses a bounded, expiring `ProcessGroup`:

- a random `ProcessGroupId` rooted in one verified browser instance;
- exact member identities, executable identity/signature evidence and lifecycle timestamps;
- parent/child creation evidence plus platform sandbox identity when available;
- a maximum member count, idle TTL and teardown when the root exits.

Parent PID, executable name or publisher alone is insufficient. A network-service process shared by several tabs creates unavoidable collateral: a conservative group gate can pause unrelated traffic in that browser instance. The UI must disclose that scope. Unknown browsers remain exact-process only and may not achieve cross-process association. Phase 5B only simulates group membership from process-tree evidence, exact generations and executable/signature evidence; no real browser-group enforcement is claimed until Phase 5E validates it.

### File identity, hash and mutation

`FileVersionIdentity` is metadata, not file content:

- volume identity plus filesystem file ID;
- creation/change evidence available from the filesystem, including USN when supported;
- end-of-file size and last-write/change timestamp;
- an HMAC-protected display token and optional extension.

A salted path hash identifies a path, not file contents. A cryptographic content hash cannot be produced while also promising that EgressGuard never reads file content. Phase 5A therefore does not require or claim a content hash. Initial prototype enforcement is NTFS-only. ReFS, remote, removable and every other unsupported volume are excluded from enforcement and fail open with a critical warning; the prototype does not downgrade them silently to a lower-assurance identity.

The minifilter revalidates the file version immediately before releasing the read. The service revalidates it before ticket issuance where the platform permits. Delete/recreate, rename across identity, truncation or any version mismatch invalidates the intent and ticket and requires a new decision. Hard links share the underlying file identity. A ticket never authorizes a later version merely because its path is unchanged.

## Network semantics

### Destination and protocol binding

A destination binding contains address family, normalized remote IP, remote port, transport (`TCP` or `UDP`), direction, compartment/interface evidence when available, and domain evidence with its provenance and observation time. DNS names are display/policy evidence only unless the current connection is cryptographically or platform-authoritatively bound to that name. An IP change does not inherit authorization silently.

`Allow once` is one ticket redemption for one exact flow generation. The redeemed grant has a short expiry and hard byte/packet/time limits. Opening another connection, changing destination/protocol, migrating beyond the validated QUIC tuple policy, or exceeding a grant bound requires a new decision.

`Always allow` is persistent but narrow. The Phase 5B scope is exactly one file-version identity plus application identity plus destination/protocol. It expires after 30 days, is revocable, and file mutation invalidates it immediately. It is never PID-based and never means “this application may send any file anywhere.” The UI must preview that exact scope and label the action `Remember for 30 days`. Policy changes increment `PolicyEpoch`, invalidating outstanding tickets.

`Block` applies to the current intent/flow. A persistent deny is a separate, explicit future action. The gate must not convert a single Block response into a blanket Windows Firewall rule.

### Existing connections, HTTP/2, HTTP/3 and QUIC

- **New connections:** ALE authorization is the preferred decision point. WFP permits pending an initial authorization, but not a reauthorization. The implementation must treat that distinction as a hard constraint.
- **Existing TCP/TLS/HTTP/2:** ALE has already allowed the flow. Phase 5B uses `ReconnectRequired` by default and simulates authorization only after a new flow is created. A group-wide stream hold is only a 5D lab experiment. Because HTTP/2 streams are multiplexed inside TLS, such a hold is at connection/process scope and cannot prove which logical request carries the file. If the lab cannot prove a safe bounded hold, the prototype fails open and makes no protection claim.
- **UDP/QUIC/HTTP/3:** QUIC runs over UDP, encrypts its traffic and multiplexes streams. Phase 5B likewise uses `ReconnectRequired` for an existing multiplexed flow. A 5D transport/datagram experiment may gate datagrams for a scoped flow, but cannot identify HTTP/3 stream semantics. Connection migration must invalidate or conservatively reauthorize the destination binding. No QUIC-specific enforcement claim is allowed until the 5D lab proves bounded behavior.
- **Unsupported or unsafe hold:** traffic is permitted after the bounded deadline, the intent becomes `FailedOpen`, and the service/UI publish a critical alert. The product must not imply that the file was protected.

The design deliberately accepts false positives and collateral delay within one scoped process/group rather than inspecting content. It does not accept an unbounded queue, an indefinite kernel wait, or a machine-wide Internet outage.

### WFP fail-open filter lifecycle

Every EgressGuard terminating or unknown-callout filter must set `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`. The prototype uses dynamic, non-persistent WFP sessions and filters only; it must not install boot-time or persistent enforcement filters. This platform flag is mandatory because a watchdog alone cannot prevent Windows from treating an unavailable terminating callout as Block.

Startup order is strict: register the runtime callout first, confirm its generation, then use one service-owned dynamic WFP session and one transaction to add only the EgressGuard provider, sublayer and filters carrying their exact ownership GUIDs. A failed transaction rolls back every owned object. Normal shutdown disables or removes the owned filters before unregistering the callout. Cleanup and rollback match the exact provider/sublayer/filter IDs and never enumerate-and-delete another vendor's objects.

If the callout is unregistered or unknown, the driver unloads or enters a recoverable fault-injected unavailable state, the Policy Service crashes, Base Filtering Engine (BFE) restarts, or installation rolls back, targeted and unrelated traffic must remain permitted. The next available service/driver handshake publishes sanitized critical fail-open evidence with the affected interval and exact counters. No success claim may rely only on a service watchdog; Phase 5D must verify the WFP-native unavailable-callout behavior and zero stale owned filters. An actual kernel bugcheck has no running network stack to “permit” and is a test failure followed by reboot/rollback evidence, never a successful fail-open case.

## Protocol and data contracts

These are design contracts for Phase 5B simulation, not additions to the current protocol yet.

| Contract | Required fields and invariants |
|---|---|
| `FileReadIntent` | Version, `IntentId`, exact process identity, optional authenticated `ProcessGroupId`, `FileVersionIdentity`, operation, observed time, kernel deadline, boot instance, monotonic sequence. No content or raw path. |
| `GateCoverage` | Versioned capability flags: `NewTcp`, `NewUdp`, `ExistingTcpStream`, `ExistingUdpDatagram`, and `ReconnectRequiredSimulation`. Unknown required flags are unsupported, never ignored. |
| `GateArmRequest/Ack` | Request carries `IntentId`, exact subject, `RequiredCoverage`, policy epoch, driver generation target, request nonce and armed deadline. Ack carries a unique Ack ID, the matching request nonce, exact intent/subject, `ArmedCoverage`, policy epoch, actual driver generation, ack nonce/monotonic time, armed deadline and unsupported/degraded reason. Duplicate requests are idempotent. The service accepts arm only when `ArmedCoverage` contains every `RequiredCoverage` flag and every binding is current and exact; partial, mismatched or stale acknowledgements cause explicit fail-open plus a critical alert. |
| `FileReadDisposition` | `IntentId`, exact process/file version, disposition (`ReleaseAfterGateArmed`, `FailOpenRelease`, or `Cancel`), matching Gate Ack ID when release follows arm, deadline, reason code and monotonic sequence. `ReleaseAfterGateArmed` is invalid without the accepted full-coverage Ack. |
| `FileReadCompletionAck` | Idempotent acknowledgement bound to the disposition sequence and exact intent/process/file version; includes terminal result, completion reason and minifilter generation. Duplicate dispositions return the same terminal acknowledgement. |
| `NetworkGateChallenge` | `ChallengeId`, `IntentId`, subject, normalized destination binding, flow generation, new/existing-flow indicator, protocol limitations and decision deadline. Bounded one active challenge per intent/flow. |
| `UserDecision` | Challenge ID, decision enum, requested persistent scope only for Always allow, UI audit timestamp and authenticated caller. The UI timestamp is never trusted for freshness; only the Policy Service's monotonic receipt time compared with the service-owned challenge deadline can accept or reject the decision. |
| `OneTimeTicket` | Ticket version/ID, random nonce, intent, subject, file-version digest, destination/protocol, flow generation, UTC audit times, monotonic not-before/deadline values, boot instance, policy epoch, grant bounds and service authenticator. |
| `TicketRedemption` | Atomically remove one entry from a bounded outstanding-ticket table and create an ephemeral grant. A consumed tombstone remains until that ticket's maximum expiry. Capacity exhaustion refuses issuance rather than evicting a live/tombstoned entry into a replayable state; traffic still follows the bounded fail-open deadline and critical-alert path. |
| `GateStatus/CriticalAlert` | State, reason code, affected scope, timestamps, dropped/overflow counts and whether traffic failed open. Never includes content, packet payload or raw path. |

All messages are versioned, length-limited and authenticated. Driver communication must use ACLs that exclude unprivileged mutation, validate every length/enum/count, copy untrusted buffers before use, and use bounded tables with explicit eviction. UI requests continue through the Policy Service; the UI never receives a driver handle with mutation authority.

## Trust boundaries and threat review

| Boundary/threat | Required control | Residual risk / honest claim |
|---|---|---|
| User-mode process → minifilter | Kernel-derived requestor identity and file metadata; ignore user-supplied PID/path claims. | Injection into a trusted browser can act within that browser's authority. |
| Minifilter/WFP ↔ Policy Service | Mutual endpoint identity, protected device/port ACL, version and bounds validation, boot-scoped authenticated messages. | Local administrators and kernel attackers remain trusted/out of scope. |
| UI → Policy Service | Impersonated caller authorization, anti-CSRF-equivalent correlation IDs, freshness and exact scope confirmation. | A compromised authorized desktop session can approve a prompt. |
| PID reuse/group confusion | Exact start time plus kernel generation; lifecycle-based bounded group membership. | Complex broker processes can create conservative collateral gates. |
| Ticket theft/replay | Random nonce, service authenticator, exact bindings, boot/policy epochs, atomic outstanding-entry removal, tombstone retained through maximum expiry, and refusal on replay-table capacity exhaustion. | A compromised kernel or service can bypass the design. |
| File swap/rename/hard link | Stable file identity plus version revalidation; invalidate on mismatch. | Unsupported filesystems can provide weaker identity and must be labeled/fail open. |
| Queue exhaustion/prompt flood | Per-subject/global hard bounds, coalescing, rate limits and deadlines; no task/thread per event. | Fail-open under exhaustion is visible but does not prevent exfiltration. |
| Browser multiplexing | Disclose group/connection scope; keep grant short and destination-bound. | No TLS-free method proves which HTTP/2 or HTTP/3 stream contains the file. |
| Forged Always allow | Admin-authorized mutation, narrow canonical scope, protected persistence, audit and revocation. | Persistent policy is an intentional bypass within its displayed scope. |
| Driver/service rollback or downgrade | Version handshake, minimum-compatible policy version, atomic policy swap and last-known-good recovery. | Emergency rollback may restore fail-open monitoring only. |

### Threat-review refinement

The first design pass proposed one-time authorization directly over packets. Review found that this either reuses a “one-time” token multiple times or cannot carry a normal flow. The refined model consumes the ticket exactly once and creates a separate, bounded ephemeral flow grant.

The review also rejected three unsafe shortcuts: PID-only binding, treating a path hash as a content hash, and relying only on ALE for already-established connections. Those conditions now invalidate enforcement or require explicit 5C/5D lab evidence.

## Privacy

- No component reads, copies, hashes, logs or persists file content.
- WFP does not log packet payload. TLS remains opaque.
- Raw paths stay in the minifilter only as long as needed to form a protected identity; they are not placed in tickets, alerts, telemetry or persistent policy by default.
- The service and UI receive an opaque file token, a redacted display label and only the minimum metadata needed for a decision.
- Tickets, group membership, replay state and ephemeral grants are RAM-only, bounded and erased on service/driver stop or reboot.
- Persistent Always allow rules store canonical protected selectors and audit metadata locally; no cloud telemetry is introduced.
- Logs use stable reason codes and counts, never command lines, credentials, cookies, file bytes, packet bytes or full paths.
- Clear-history and policy-revocation behavior must cover all Phase 5 user-mode evidence before 5E acceptance.

## Failure, reboot and rollback behavior

Phase 5 prototype enforcement is **fail-open with a critical alert**:

- Minifilter cannot reach service, WFP gate cannot arm, any bounded table overflows, identity/file version is uncertain, decision times out, or a driver reports an incompatible version: release the read/traffic after a short documented deadline, mark the intent `FailedOpen`, increment a monotonic counter and publish a critical alert.
- Policy Service crashes: minifilter deadlines release reads, dynamic WFP filters retain unavailable-callout permit semantics, volatile gates/grants expire, and the recovered service reports the fail-open interval. A watchdog is defense in depth, not the primary WFP fail-open control.
- Minifilter crashes/unloads: WFP gates expire; service reports that file provenance is unavailable.
- WFP callout unloads, becomes unregistered or enters a recoverable unavailable state: `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` allows traffic, minifilter deadlines release pending reads, and service reports that network gating is unavailable. A kernel bugcheck remains a critical test failure and is handled by reboot/rollback, not described as live fail-open traffic.
- BFE restart or filter-install transaction failure: dynamic/non-persistent owned filters disappear or roll back; traffic remains permitted and exact ownership reconciliation must find zero stale EgressGuard filters before a later re-arm.
- Reboot: boot nonce changes, all tickets/replay entries/groups/gates/grants become invalid, and drivers start pass-through until the authenticated service completes version/policy reconciliation.
- Rollback: remove only EgressGuard-owned filters/instances, atomically load the previous compatible policy, and otherwise remain pass-through with a critical alert. Never disable Windows Firewall or other vendors' filters.

An alert path must not depend solely on the failed component. The service persists a sanitized critical event when available; the UI displays live status and the next successful handshake reports missed fail-open counters.

## Phase boundaries

- **5A (this branch):** architecture and executable plan only; no Phase 5 source, project, driver, installer or Windows mutation.
- **5B:** pure user-mode simulator and contracts. Fake file intents, gate challenges and driver acknowledgements exercise the state machine, ticket redemption, expiry, replay, bounds, crash and privacy behavior. It performs no real enforcement.
- **5C:** isolated-VM minifilter lab only after WDK/signing/lab approval. Prove pre-read ordering, exact process/file identity, mutation handling, bounded pending operations and fail-open. No WFP enforcement yet.
- **5D:** isolated-VM WFP callout lab only after 5C evidence and signing/lab approval. Prove ALE new-flow gating and bounded established TCP/UDP behavior. No claim of HTTP/2 or HTTP/3 file recognition.
- **5E:** integrated authorized prototype, UI decision workflow, browser-group experiments, abuse/failure/performance/privacy acceptance and rollback drills.
- **5F:** production-readiness decision: independent driver security review, production signing, WDK/toolchain provenance, Application Control policy, installer/update/rollback and support criteria. These prerequisites are separate from functional success.

No phase may automatically enable test-signing, disable Secure Boot, weaken driver-signature enforcement, bypass Application Control, or install a driver on the developer workstation. Kernel work requires an explicitly authorized, disposable and recoverable lab environment.

## Windows capability references

- Microsoft documents that minifilters can register pre-operation callbacks and pend an operation, with strict IRQL and completion requirements: [Writing Pre-operation Callback Routines](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/writing-preoperation-callback-routines) and [Processing I/O Operations](https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/processing-i-o-operations).
- File metadata queries have filesystem and IRQL constraints: [FltQueryInformationFile](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fltkernel/nf-fltkernel-fltqueryinformationfile).
- ALE is connection/socket stateful filtering, while non-ALE layers classify per packet: [Application Layer Enforcement](https://learn.microsoft.com/en-us/windows/win32/fwp/application-layer-enforcement--ale-).
- Microsoft states that only initial ALE authorization can be pended and reauthorization cannot: [FwpsPendOperation0](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/fwpsk/nf-fwpsk-fwpspendoperation0) and [ALE Reauthorization](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-re-authorization).
- WFP exposes TCP stream processing after flow establishment, but this is network data rather than file provenance: [TCP Packet Flows](https://learn.microsoft.com/en-us/windows/win32/fwp/tcp-packet-flows) and the [WFP Traffic Inspection Sample](https://learn.microsoft.com/en-us/samples/microsoft/windows-driver-samples/windows-filtering-platform-traffic-inspection-sample/).
- Microsoft documents QUIC as UDP-based, TLS 1.3 protected and multiplexed: [QUIC protocol](https://learn.microsoft.com/en-us/dotnet/fundamentals/networking/quic/quic-overview).
- Windows requires signed kernel-mode code; production signing is a separate release prerequisite: [Windows Driver Signing Tutorial](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/windows-driver-signing-tutorial) and [Kernel-Mode Code Signing Requirements](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/kernel-mode-code-signing-requirements--windows-vista-and-later-).

## Decisions fixed for Phase 5B

1. **Filesystem:** initial prototype enforcement supports NTFS only. ReFS, remote, removable and any unsupported volume fail open with a critical warning.
2. **Remembered decision:** `Always allow` binds exact file-version identity, application identity and destination/protocol for 30 days. File mutation invalidates it immediately; it is revocable, and the UI says `Remember for 30 days`.
3. **Browser grouping:** Phase 5B simulates process-tree membership using exact process generations plus executable/signature evidence. It makes no real browser-group enforcement claim; that requires Phase 5E evidence.
4. **Existing multiplexed flows:** Phase 5B defaults to `ReconnectRequired`. A group-wide stream/datagram hold is a 5D lab experiment only; failure to prove safety results in fail-open and no protection claim.
5. **Frozen simulation limits:** gate-arm/read deadline 2 seconds; user-decision/network-hold deadline 15 seconds; ticket validity 5 seconds; ephemeral grant one flow with a maximum of 5 minutes or 512 MiB; pending reads 4 per subject/64 global; active challenges 4 per subject/128 global; held network data 256 KiB per flow/4 MiB global; outstanding tickets 8 per subject/256 global; replay tombstones 2,048 global; browser group 32 exact members. Phase 5C/5D may choose different lab limits, but must freeze them before testing and never revise them after seeing results.
6. **Hashing:** cryptographic content hashing remains excluded because it requires a trusted component to read file content. Phase 5 uses only a file-version metadata digest/HMAC token and never calls it a content hash.
