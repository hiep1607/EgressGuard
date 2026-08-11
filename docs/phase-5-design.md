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
3. **Gate arming.** The service asks WFP to arm a volatile gate for that subject before instructing the minifilter to release the file read. The acknowledgement must prove that both new-flow interception and the selected established-flow strategy are active; a partial acknowledgement is a fail-open condition. Arming is scoped to the subject and intent, not the whole host. The first matching outbound attempt supplies a normalized destination and protocol and transitions the intent to `AwaitingDecision`.
4. **Network hold.** New TCP/UDP authorization can be postponed only where WFP supports an initial ALE pend. Existing TCP flows require a separately validated stream-layer hold; UDP/QUIC requires a separately validated datagram/transport hold. Each hold has hard limits for time, bytes/packets, entries and memory. If a safe hold cannot be established, the prototype fails open and emits a critical alert.
5. **Decision.** The UI shows application/group, protected file label, destination IP/domain evidence, port, TCP/UDP, whether the flow pre-existed, collateral browser impact and decision expiry. The service rejects stale or mismatched replies.
6. **Ticket.** `Allow once` mints one short-lived ticket bound to the exact intent, subject, file version, destination, protocol, flow generation, boot instance and policy epoch. `Always allow` first creates a narrow persistent policy and then mints a ticket for the current hold. `Block` releases the hold as blocked; it does not create a host-wide firewall rule.
7. **Atomic redemption.** WFP accepts one valid ticket nonce exactly once and creates one ephemeral grant. Duplicate, expired, wrong-boot, wrong-generation, wrong-flow or altered tickets are rejected. The grant, not the ticket, covers the bounded packets/stream activity needed for the one authorized flow.

The minifilter must not release a protected read merely because the service received the intent. It releases only after WFP acknowledges the gate as armed, or after the explicit fail-open deadline. This ordering is the only intended protection against an application reading the file and immediately writing it to an already-open connection.

## Identity model

### Process identity and PID reuse

The protocol-visible identity remains `(PID, ProcessStartTime)` to match the existing Core model. Kernel implementations should additionally retain a non-user-controlled process-generation value, such as a process start key/object-derived generation, and map it to the protocol identity. Every lookup is revalidated at the point of minifilter intent creation, gate installation and ticket redemption. A PID with a different start time or kernel generation is a different subject; stale group membership, gates and tickets are discarded.

If exact identity cannot be obtained, enforcement is not guessed from PID alone. The prototype follows its fail-open rule and raises a critical alert.

### Browser process groups

Browsers commonly separate renderer, utility and network-service processes. A read may occur in one process while the socket belongs to another. The Policy Service therefore maintains a bounded, expiring `ProcessGroup`:

- a random `ProcessGroupId` rooted in one verified browser instance;
- exact member identities, executable identity/signature evidence and lifecycle timestamps;
- parent/child creation evidence plus platform sandbox identity when available;
- a maximum member count, idle TTL and teardown when the root exits.

Parent PID, executable name or publisher alone is insufficient. A network-service process shared by several tabs creates unavoidable collateral: a conservative group gate can pause unrelated traffic in that browser instance. The UI must disclose that scope. Unknown browsers remain exact-process only and may not achieve cross-process association.

### File identity, hash and mutation

`FileVersionIdentity` is metadata, not file content:

- volume identity plus filesystem file ID;
- creation/change evidence available from the filesystem, including USN when supported;
- end-of-file size and last-write/change timestamp;
- an HMAC-protected display token and optional extension.

A salted path hash identifies a path, not file contents. A cryptographic content hash cannot be produced while also promising that EgressGuard never reads file content. Phase 5A therefore does not require or claim a content hash. Filesystems without a stable file ID/version signal are lower assurance and fail open with a critical alert in the prototype unless explicitly excluded by policy.

The minifilter revalidates the file version immediately before releasing the read. The service revalidates it before ticket issuance where the platform permits. Delete/recreate, rename across identity, truncation or any version mismatch invalidates the intent and ticket and requires a new decision. Hard links share the underlying file identity. A ticket never authorizes a later version merely because its path is unchanged.

## Network semantics

### Destination and protocol binding

A destination binding contains address family, normalized remote IP, remote port, transport (`TCP` or `UDP`), direction, compartment/interface evidence when available, and domain evidence with its provenance and observation time. DNS names are display/policy evidence only unless the current connection is cryptographically or platform-authoritatively bound to that name. An IP change does not inherit authorization silently.

`Allow once` is one ticket redemption for one exact flow generation. The redeemed grant has a short expiry and hard byte/packet/time limits. Opening another connection, changing destination/protocol, migrating beyond the validated QUIC tuple policy, or exceeding a grant bound requires a new decision.

`Always allow` is persistent but narrow: application identity, optional browser-group profile, file selector/class, destination selector, protocol/port, creation time, policy version and revocation state. It is never PID-based and never means “this application may send any file anywhere.” The UI must preview the exact scope. Policy changes increment `PolicyEpoch`, invalidating outstanding tickets.

`Block` applies to the current intent/flow. A persistent deny is a separate, explicit future action. The gate must not convert a single Block response into a blanket Windows Firewall rule.

### Existing connections, HTTP/2, HTTP/3 and QUIC

- **New connections:** ALE authorization is the preferred decision point. WFP permits pending an initial authorization, but not a reauthorization. The implementation must treat that distinction as a hard constraint.
- **Existing TCP/TLS/HTTP/2:** ALE has already allowed the flow. A 5D lab must prove that a stream-layer callout can hold bounded outbound stream data for the scoped process while a decision is pending. Because HTTP/2 streams are multiplexed inside TLS, the hold is at connection/process scope and cannot prove which logical request carries the file.
- **UDP/QUIC/HTTP/3:** QUIC runs over UDP, encrypts its traffic and multiplexes streams. A transport/datagram hold can gate datagrams for a scoped flow, but cannot identify HTTP/3 stream semantics. Connection migration must invalidate or conservatively reauthorize the destination binding. No QUIC-specific enforcement claim is allowed until the 5D lab proves bounded behavior.
- **Unsupported or unsafe hold:** traffic is permitted after the bounded deadline, the intent becomes `FailedOpen`, and the service/UI publish a critical alert. The product must not imply that the file was protected.

The design deliberately accepts false positives and collateral delay within one scoped process/group rather than inspecting content. It does not accept an unbounded queue, an indefinite kernel wait, or a machine-wide Internet outage.

## Protocol and data contracts

These are design contracts for Phase 5B simulation, not additions to the current protocol yet.

| Contract | Required fields and invariants |
|---|---|
| `FileReadIntent` | Version, `IntentId`, exact process identity, optional authenticated `ProcessGroupId`, `FileVersionIdentity`, operation, observed time, kernel deadline, boot instance, monotonic sequence. No content or raw path. |
| `GateArmRequest/Ack` | `IntentId`, exact subject, maximum hold time/bytes/packets, policy epoch, request nonce; acknowledgement includes driver generation and armed time. Duplicate requests are idempotent. |
| `NetworkGateChallenge` | `ChallengeId`, `IntentId`, subject, normalized destination binding, flow generation, new/existing-flow indicator, protocol limitations and decision deadline. Bounded one active challenge per intent/flow. |
| `UserDecision` | Challenge ID, decision enum, requested persistent scope only for Always allow, UI timestamp and authenticated caller. Service validates authorization and freshness. |
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
- Policy Service crashes: driver watchdog expires volatile gates and grants, traffic/read operations resume, and the recovered service reports the fail-open interval.
- Minifilter crashes/unloads: WFP gates expire; service reports that file provenance is unavailable.
- WFP callout crashes/unloads: minifilter deadlines release pending reads; service reports that network gating is unavailable.
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

## Open decisions for independent review

1. Whether the first supported filesystem set is NTFS-only, or whether lower-assurance ReFS/remote/removable volumes should fail open with a warning.
2. Whether `Always allow` may target one protected file identity only, or also a user-selected protected directory/class without storing a raw path.
3. The browser-group authority: process tree plus executable/sandbox identity, or an explicit browser-integration component in a later phase.
4. For an established multiplexed browser connection, whether to accept a short group-wide connection hold or require reconnect/new-flow authorization and accept application-visible failure.
5. Exact prototype ceilings for pending reads, held bytes/packets, prompt lifetime, ephemeral grant duration and per-subject/global entries.
6. Whether any future cryptographic content digest is acceptable. It is excluded here because producing it would require a trusted component to read file content.
