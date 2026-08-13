# Phase 5B-04 deterministic driver simulator design lock

Status: **locked for implementation**

Base: `1410e6b843c482d0e2d2fee4b6846e90678d1d47`

Scope: ticket `5B-04` only
Implementation owner after this design-lock: Luna

This document is normative for Phase 5B-04. “Must”, exact type and method names,
limits, reason codes, ownership rules, and acceptance rows are frozen. A required
change to a Core contract or to `OutboundGateStateMachine` is a blocker and must
return to design review; it is not part of 5B-04 implementation.

## Scope

5B-04 adds a deterministic, user-mode-only executable that simulates the two
driver endpoints around the existing Phase 5B Core state machine:

- a fake minifilter that represents a metadata-only pre-read pending operation;
- a fake WFP endpoint that represents gate arming, new TCP/UDP flow challenge,
  held-byte accounting, and installation of a returned ephemeral grant;
- a single-threaded host, manual clock, deterministic scheduler, bounded endpoint
  channels, scripted fault injection, snapshots, and an acceptance-suite command;
- end-to-end tests that execute the simulator and verify its redacted JSON result.

The simulator is evidence for contract and state-machine behavior. It is not an
enforcement claim.

### Explicit exclusions

- No WDK, kernel driver, minifilter, WFP callout, filter registration, firewall
  mutation, Administrator requirement, packet capture, or driver installation.
- No real filesystem read, network connection, packet, stream, or payload.
- No UI and no Phase 5B-05 work.
- No persistent policy implementation and no expansion of an `AlwaysAllow`
  decision beyond what the existing Core state machine already returns.
- No change to `src/EgressGuard.Core/OutboundGateModels.cs`,
  `src/EgressGuard.Core/OutboundGateStateMachine.cs`, or
  `src/EgressGuard.Core/OneTimeGateTicketService.cs`.
- No claim that an existing stream or datagram was blocked. Existing multiplexed
  TCP, UDP, and QUIC observations return `ReconnectRequired` only.

## Existing Core contract is sufficient

The implementation must compose, not replace, these existing APIs:

| Core API/type | Simulator use |
|---|---|
| `IOutboundGateMonotonicClock` | Implemented by the manual simulation clock. All authorization deadlines use it. |
| `IOutboundGateAuditClock` | Implemented from a fixed UTC epoch plus manual elapsed time; audit only. |
| `IOutboundGateNonceProvider` | Deterministic, scripted unique identifiers for acceptance scenarios. |
| `OutboundGateStateMachine.ReceiveIntent` | Converts the minifilter `FileReadIntent` into a `GateArmRequest`. |
| `ReceiveGateArmAck` | Validates full coverage, policy, nonce, WFP generation, and deadline. |
| `ReleaseAfterGateArmed(Guid)` | Creates the exact disposition that can release the pending read. |
| `AcceptCompletion` | Validates the minifilter completion and generation. |
| `ReceiveChallenge` / `ReceiveDecision` | Own the new-flow challenge and decision transition. |
| `RedeemTicket` | Atomically consumes a one-time ticket and returns a separate ephemeral grant. |
| `ProcessExpired` | Performs deterministic timeout/grant-expiry processing after manual time advances. |
| `HandleServiceRestart(OutboundGateTrustedRuntimeState)` | Invalidates all volatile authority after service or endpoint failure/generation change. |
| `ApplyPolicyEpoch` | Invalidates old policy authority without simulator-specific policy logic. |
| `Counters`, `Storage`, `CriticalAlerts` | Core-authoritative evidence for operations that entered the state machine. |
| `OneTimeGateTicketService.Snapshot` | Ticket, tombstone, and active-grant reservation evidence. |

Individual endpoint crash/restart is implementable without a new Core API. The
host marks the endpoint unavailable, releases its endpoint-owned state, advances
the affected endpoint generation, and calls the existing full volatile-authority
invalidation API. This is deliberately conservative: unrelated live simulator
operations may also fail open, but no stale ticket, grant, read, or held flow can
survive. Core alert reason codes remain unchanged; the simulator also records the
specific endpoint fault reason defined below.

## Component and API map

All types below are `internal` in namespace
`EgressGuard.OutboundGateSimulator` and live in the new simulator project. The
names and signatures are locked; splitting `Program.cs` is outside the allowed
file set for this ticket.

```csharp
internal sealed class ManualSimulationClock :
    IOutboundGateMonotonicClock, IOutboundGateAuditClock
{
    ServiceMonotonicTimestamp Now();
    DateTimeOffset NowUtc();
    void AdvanceBy(long milliseconds);
    void Restart(Guid clockInstanceId);
}

internal interface IDeterministicSimulationScheduler
{
    bool TrySchedule(SimulationEnvelope envelope, long delayMilliseconds);
    int PumpReady();
    int AdvanceBy(long milliseconds);
    void CancelOwned(Guid operationId);
    int Count { get; }
}

internal interface IFakeMinifilterEndpoint
{
    SimulationStepResult TryPendRead(SimulatedReadMetadata read);
    SimulationStepResult AcceptDisposition(FileReadDisposition disposition);
    void Crash();
    void Restart(Guid generation);
    MinifilterSnapshot Snapshot { get; }
}

internal interface IFakeWfpEndpoint
{
    SimulationStepResult AcceptArmRequest(GateArmRequest request);
    SimulationStepResult ObserveFlow(SimulatedFlowMetadata flow);
    SimulationStepResult InstallGrant(EphemeralFlowGrant grant);
    void Crash();
    void Restart(Guid generation);
    WfpSnapshot Snapshot { get; }
}

internal sealed class OutboundGateSimulatorHost : IDisposable
{
    SimulationStepResult SubmitRead(SimulatedReadMetadata read);
    SimulationStepResult SubmitFlow(SimulatedFlowMetadata flow);
    SimulationStepResult SubmitDecision(UserDecision decision);
    SimulationStepResult Redeem(OneTimeTicket ticket);
    SimulationStepResult Inject(SimulationFault fault);
    int PumpReady();
    int AdvanceBy(long milliseconds);
    SimulationSnapshot Snapshot { get; }
}
```

The simulator-private data vocabulary is locked as follows:

- `SimulatedReadMetadata`: `OperationId`, `GateSubject`,
  `FileVersionIdentity`, `Sequence`, and `RequestedByteCount` (`long`). It has no
  path and no data-bearing field.
- `SimulatedFlowMetadata`: `OperationId`, `IntentId`, `GateSubject`,
  `DestinationBinding`, `FlowGeneration`, `SimulatedTransportKind`,
  `SimulatedFlowShape`, and `ObservedByteCount` (`long`).
- `SimulatedTransportKind`: `Tcp`, `Udp`, `Quic`.
- `SimulatedFlowShape`: `NewFlow`, `ExistingMultiplexed`.
- `SimulatedFlowOutcome`: `Pending`, `Granted`, `Blocked`, `FailedOpen`,
  `ReconnectRequired`.
- `SimulationEnvelopeKind`: `FileReadIntent`, `GateArmRequest`, `GateArmAck`,
  `FileReadDisposition`, `FileReadCompletionAck`, `NetworkGateChallenge`,
  `Decision`, `TicketRedemption`, `ExpirySweep`, `Fault`.
- `SimulationFaultKind`: `DelayNext`, `DropNext`, `MinifilterCrash`,
  `MinifilterRestart`, `WfpCrash`, `WfpRestart`, `ServiceRestart`,
  `StaleGeneration`, `PartialCoverage`, `DegradedCoverage`.
- `SimulationFault`: `Kind`, `EnvelopeKind`, optional `OperationId`, and
  `DelayMilliseconds`. It contains metadata only.
- `SimulationStepResult`: outcome, stable reason code, and optional existing Core
  contract objects. It is not serialized directly.
- `SimulationSnapshot`: redacted current counts, capacities, cumulative counters,
  endpoint generations/availability, current manual timestamp, and terminal
  outcome summaries. It must not contain a ticket proof or a data-bearing object.

`Program.Main` is synchronous and supports exactly these entry modes:

- no arguments: construct the default Disabled host, print one redacted Disabled
  snapshot, and exit zero;
- `--scenario <locked-name> --json`: run one named deterministic scenario and
  print one redacted JSON result;
- `--acceptance-suite --json`: run every acceptance scenario, print one redacted
  JSON aggregate, and exit nonzero if any row fails.

No mode accepts a raw path, payload, packet, host name, arbitrary script, or live
endpoint. Simulation mode is selected only inside a named scenario; there is no
ambient environment-variable opt-in.

## State ownership

| State | Sole owner | Release rule |
|---|---|---|
| Mode, runtime generations, fault plan, simulator counters | `OutboundGateSimulatorHost` | Dispose or service restart clears it. |
| Core intent/challenge/decision/ticket/grant phase | `OutboundGateStateMachine` | Core terminal transition, expiry, policy change, or runtime invalidation. Host must invalidate live state before disposing Core. |
| Outstanding tickets, tombstones, active grant-ID reservations | `OneTimeGateTicketService` through Core | Existing expiry, policy, restart, and dispose rules only. |
| Pending read metadata and per-subject count | `FakeMinifilterEndpoint` | Matching disposition, fail-open, crash/restart, timeout cleanup, or dispose. |
| Arm request/Ack endpoint envelopes | `FakeWfpEndpoint` | Delivery, fault cleanup, crash/restart, or dispose. |
| Held-flow metadata, held-byte count, installed-grant metadata | `FakeWfpEndpoint` | Grant/block/fail-open, crash/restart, grant expiry/byte exhaustion, or dispose. |
| Scheduled envelopes and owner index | `DeterministicSimulationScheduler` | Dispatch, owner cancellation, global cleanup, or dispose. |
| Critical-alert and transition diagnostic rings | host diagnostics | Oldest terminal diagnostic may be evicted at the ring cap; authority is never stored here. |

An operation has one `OperationId` across endpoint and scheduler ownership. Core
continues to use its existing `IntentId` and `ChallengeId`. A component may hold a
reference to an existing immutable Core contract, but may not copy authority into
a second mutable state machine. Ticket proof bytes are opaque Core-owned data and
must never be inspected, copied, logged, or emitted by the simulator.

### Lock order

The simulator is a single-threaded deterministic pump. Endpoint and scheduler
types have no independent locks and are called only while the host transition
lock is held. The only permitted nesting is:

1. `OutboundGateSimulatorHost` transition lock;
2. `OutboundGateStateMachine` transition lock (inside a public Core call);
3. `OneTimeGateTicketService` lock (inside the state-machine transition);
4. mutation of endpoint/scheduler/diagnostic structures after the Core call has
   returned, still under the host lock.

No endpoint or scheduled callback may call back into the host. The host dequeues
an immutable envelope and dispatches it. Code must never acquire an endpoint,
scheduler, or diagnostic lock before calling Core. This preserves the existing
state-machine-before-ticket-service order.

## Frozen limits

### Existing Phase 5B limits

| Resource/window | Frozen limit |
|---|---:|
| Gate-arm and original pending-read window | 2 seconds |
| User-decision and network-hold window | 15 seconds |
| One-time ticket validity | 5 seconds |
| Ephemeral grant duration | 5 minutes |
| Ephemeral grant byte count | 512 MiB, one exact flow |
| Pending reads | 4 per subject; 64 global |
| Active challenges | 4 per subject; 128 global |
| Held network byte count | 256 KiB per flow; 4 MiB global |
| Outstanding tickets | 8 per subject; 256 global |
| Replay tombstones | 2,048 global |
| Active grant-ID reservations | 256 global |
| Exact browser/process group members | 32 |
| Core active contexts | 256 global |
| Core terminal history | 256 terminal records |
| Core critical-alert history | 256 terminal alerts |

### New simulator limits

| New queue/map/budget | Hard cap |
|---|---:|
| Minifilter pending-read map | 4 per subject; 64 global |
| Minifilter intent outbox | 64 envelopes |
| Minifilter disposition inbox | 64 envelopes |
| Minifilter completion-Ack outbox | 64 envelopes |
| WFP gate-arm inbox | 64 envelopes |
| WFP gate-Ack outbox | 64 envelopes |
| WFP flow-observation inbox | 128 envelopes |
| WFP held-flow map | 4 per subject; 128 global |
| WFP challenge outbox | 128 envelopes |
| WFP installed-grant map | 256 entries |
| Host operation ownership map | 256 entries |
| Deterministic scheduler heap | 512 envelopes |
| Scheduler owner index | 256 operation keys |
| Fault plan | 256 entries |
| Dispatches in one pump call | 1,024 dispatches |
| Simulator critical-alert ring | 256 terminal alerts |
| Simulator transition-trace ring | 1,024 terminal entries |
| Acceptance-result vector | 64 terminal scenario results |

No live entry is evicted to admit a new live entry. A failed reservation rejects
the new operation/envelope, fails open any affected operation, emits a Critical
Alert, and leaves all prior live entries intact. Diagnostic rings contain only
terminal, non-authoritative metadata; their oldest entry may be evicted and that
eviction has its own exact counter.

`RequestedByteCount`, `ObservedByteCount`, held-byte totals, and grant-used-byte
totals use checked `long` arithmetic. A new held flow must have an observed count
from 1 through 256 KiB. The global sum must remain at or below 4 MiB. The fake WFP
stores only the number; it does not allocate that number of bytes.

## Deterministic scheduling model

- The host and pump use one caller thread. There is no worker, timer, background
  service, per-event `Task`, or per-event thread.
- `ManualSimulationClock` begins at a fixture `ClockInstanceId`, elapsed `0`, and
  a fixed UTC audit epoch. Only `AdvanceBy` changes time. Negative advances and
  arithmetic overflow are rejected before state changes.
- The scheduler is a bounded min-heap ordered by
  `(DueElapsedMilliseconds, InsertionSequence)`. Equal-due events therefore have
  deterministic FIFO order.
- `PumpReady` dispatches only events whose due time is less than or equal to the
  manual clock. `AdvanceBy(n)` advances once, pumps due envelopes, calls
  `OutboundGateStateMachine.ProcessExpired`, then reconciles endpoint ownership.
- Deadline equality is expired, matching Core. Gate-arm/read work may never move
  beyond the original two-second read deadline. Challenge holding uses at most
  fifteen seconds from its manual start.
- `DelayNext` changes only the selected envelope due time. `DropNext` removes only
  that selected envelope, increments `DroppedEnvelopeCount`, and leaves the
  affected operation to its existing manual deadline. At that deadline Core
  fails open and cleanup proves zero ownership.
- The 1,024-dispatch budget prevents a zero-time self-scheduling loop. Exhaustion
  triggers `sim-pump-budget-exhausted`, fail-opens all owned work through runtime
  invalidation, clears scheduled work, and returns control to the caller.
- `Thread.Sleep`, `Task.Delay`, `DateTimeOffset.UtcNow`, `Stopwatch`, timers, and
  wall-clock timeout decisions are forbidden in the simulator and its 5B-04
  tests. Process launch in the existing test harness is not an event scheduler.

## End-to-end transition contract

| Step | Required transition and ownership effect |
|---|---|
| 0. Disabled | Default construction returns `outbound-gate-disabled`; it creates no simulation ticket service, pending read, scheduled envelope, held flow, challenge, or grant. All owned counts remain zero. |
| 1. Pre-read pending | The minifilter reserves one bounded metadata record before emitting `FileReadIntent`. Reservation failure releases this read fail-open without entering Core. |
| 2. Gate arm | Host calls `ReceiveIntent`; an accepted result schedules the exact `GateArmRequest` for fake WFP. |
| 3. Full-coverage Ack | Fake WFP accepts only its current generation and returns exact required coverage: new TCP, new UDP, existing TCP stream, existing UDP/datagram, and reconnect-required simulation. Partial/degraded/stale Ack is delivered unchanged so Core rejects it and alerts. |
| 4. Matching disposition | Only after Core accepts the Ack may host call `ReleaseAfterGateArmed(IntentId)`. Fake minifilter releases only on exact intent/process/file/Ack/disposition/sequence binding. |
| 5. Completion Ack | Fake minifilter removes its pending record exactly once and emits `Released` with its current generation. Host passes the exact Ack to `AcceptCompletion`. |
| 6. New TCP/UDP challenge | Fake WFP reserves a held-flow entry and checked byte count before creating an exact, non-existing-flow `NetworkGateChallenge`; Core validates subject, coverage, generation, and 15-second window. |
| 7. Decision | `Block` terminates and releases held ownership. `AllowOnce` is passed to Core and may return a one-time ticket. No UI or persistent-policy side effect is added. |
| 8. One-time redemption | Host calls `RedeemTicket` once. Any rejected or fail-open result releases held ownership. A replay never creates a grant. |
| 9. Ephemeral grant | Fake WFP installs only the exact returned grant, releases the held-flow reservation, and tracks metadata plus used-byte count for that one flow until duration/byte expiry, policy change, runtime invalidation, or dispose. |

If a post-admission simulator infrastructure failure cannot be targeted through a
public Core transition, the host performs conservative global volatile-authority
invalidation with fresh endpoint generations. It then reconciles every endpoint
and scheduler owner to zero. This rule is required; adding a Core “force fail
open” API is not permitted in 5B-04.

### Existing multiplexed flow rule

`ExistingMultiplexed` is valid only for TCP, UDP, or QUIC. QUIC is simulator-only
metadata and requires a UDP `DestinationBinding`. Such an observation:

1. returns `SimulatedFlowOutcome.ReconnectRequired` immediately;
2. uses one of the exact reason codes
   `sim-reconnect-required-existing-tcp`,
   `sim-reconnect-required-existing-udp`, or
   `sim-reconnect-required-existing-quic`;
3. creates no Core challenge, ticket, grant, held-flow entry, or held-byte count;
4. never reports the established stream/datagram as blocked or held.

New QUIC admission is outside 5B-04. New-flow challenges are TCP or UDP only.

## Fault and cleanup matrix

| Fault | Deterministic injection | Required result |
|---|---|---|
| Delay below deadline | `DelayNext` for a selected envelope | Pump does nothing before due time; exact transition succeeds when manually advanced below deadline. |
| Delay to/after deadline | Delay selected envelope to deadline or later | Core expiry wins at equality; fail open, Critical Alert, cancel late envelope, zero affected ownership. |
| Drop | `DropNext` selected by kind and optional operation ID | Envelope is never dispatched; exact drop counter increments once; manual deadline later fails open and cleans ownership. |
| Minifilter crash | Scheduled `MinifilterCrash` | Mark unavailable, release every pending read, clear its channels, advance minifilter generation, invalidate volatile authority, alert, zero pending state. |
| Minifilter restart | Scheduled `MinifilterRestart` | Use a second fresh generation, keep endpoint empty, invalidate stale volatile authority, then accept new work only. |
| WFP crash | Scheduled `WfpCrash` | Mark unavailable, release all held flows/byte counts, clear channels/grants, advance WFP generation, invalidate authority, alert, zero held state. |
| WFP restart | Scheduled `WfpRestart` | Use a second fresh generation, empty maps, invalidate stale authority, then accept new work only. |
| Service restart | Scheduled `ServiceRestart` | Fresh boot, WFP, minifilter, and clock instances; invalidate tickets/grants/contexts; clear every endpoint, scheduler, and owner; preserve terminal counters/alerts only. |
| Stale WFP generation | `StaleGeneration` on gate Ack/challenge | Deliver stale contract to Core; Core fails open and alerts; no read/held owner remains. |
| Stale minifilter generation | `StaleGeneration` on completion Ack | Core fails open and alerts; pending metadata is removed exactly once. |
| Partial coverage | `PartialCoverage` on next gate Ack | Core reason `gate-ack-invalid-or-expired`; fail open, Critical Alert, no later capability. |
| Degraded coverage | `DegradedCoverage` plus non-null limitation reason | Same terminal fail-open behavior; never release as gate-armed. |
| Endpoint queue overflow | Fill a channel without pumping, then submit one more | Reject only the new reservation, preserve prior live entries, fail open affected traffic, emit exact capacity reason, increment overflow once. |
| Pending/challenge map overflow | Reach exact per-subject or global cap, then submit one more | Core/simulator cap refusal is fail-open; live state is not evicted; count never exceeds cap. |
| Held-flow entry overflow | Reach 4/subject or 128/global | Current flow fails open; prior holds remain; after cleanup all owned held state is zero. |
| Per-flow byte overflow | Submit more than 256 KiB for one new flow | Do not reserve bytes or allocate content; fail open with Critical Alert. |
| Global byte overflow | Make accepted held counts total 4 MiB, then add one byte | Reject current flow; held total never exceeds 4 MiB; later cleanup reaches zero. |
| Scheduler/fault-plan overflow | Reach exact cap, then schedule one more | Reject new item, increment overflow once, alert; post-admission impact invokes conservative invalidation. |
| Pump budget overflow | Script a zero-time chain that attempts dispatch 1,025 | Dispatch at most 1,024, fail open all live work, clear scheduler, alert, return synchronously. |

At the end of every crash, restart, timeout, and overflow acceptance scenario:

- minifilter pending count is zero;
- WFP held-flow count and held-byte count are zero;
- scheduler count and owner index are zero;
- host owned-operation count is zero;
- Core active intent/challenge counts are zero;
- outstanding ticket and active-grant reservation counts are zero where the fault
  invalidates runtime authority.

## Stable reason codes

The simulator must emit these exact codes. Existing Core reason codes are passed
through without translation.

### Simulator outcomes and faults

| Reason code | Meaning |
|---|---|
| `sim-disabled` | Default host is disabled; no authority or pending state exists. |
| `sim-read-pended` | Metadata-only read reservation accepted. |
| `sim-full-coverage-armed` | Current WFP generation acknowledged every required coverage flag. |
| `sim-read-released` | Exact disposition released one pending read. |
| `sim-read-completion-accepted` | Exact completion Ack was accepted by Core. |
| `sim-challenge-created` | New TCP/UDP flow is held by count and challenged. |
| `sim-ticket-issued` | Core returned an opaque one-time ticket. |
| `sim-ticket-redeemed` | Core returned a separate ephemeral grant. |
| `sim-reconnect-required-existing-tcp` | Existing multiplexed TCP is not held. |
| `sim-reconnect-required-existing-udp` | Existing multiplexed UDP is not held. |
| `sim-reconnect-required-existing-quic` | Existing multiplexed QUIC is not held. |
| `sim-envelope-dropped` | Scripted selected envelope was dropped once. |
| `sim-minifilter-crashed` / `sim-minifilter-restarted` | Minifilter endpoint health/generation fault. |
| `sim-wfp-crashed` / `sim-wfp-restarted` | WFP endpoint health/generation fault. |
| `sim-service-restarted` | Service runtime, endpoints, and manual clock restarted. |
| `sim-stale-wfp-generation` | WFP-origin contract used a stale generation. |
| `sim-stale-minifilter-generation` | Completion used a stale minifilter generation. |
| `sim-coverage-partial` | Armed coverage omitted at least one required flag. |
| `sim-coverage-degraded` | Endpoint reported degraded/unsupported coverage. |
| `sim-minifilter-channel-capacity-exhausted` | A minifilter channel rejected its next envelope. |
| `sim-wfp-channel-capacity-exhausted` | A WFP channel rejected its next envelope. |
| `sim-pending-read-capacity-exhausted` | Minifilter pending reservation cap was reached. |
| `sim-held-flow-capacity-exhausted` | WFP held-flow entry cap was reached. |
| `sim-held-data-flow-capacity-exhausted` | One flow requested more than 256 KiB held count. |
| `sim-held-data-global-capacity-exhausted` | Accepted held counts would exceed 4 MiB. |
| `sim-scheduler-capacity-exhausted` | Scheduler rejected envelope 513. |
| `sim-fault-plan-capacity-exhausted` | Fault plan rejected entry 257. |
| `sim-pump-budget-exhausted` | One pump attempted dispatch 1,025. |

For a Core-owned operation, expected Core fault reasons include
`gate-ack-invalid-or-expired`, `completion-binding-or-generation-invalid`,
`active-challenge-capacity-exhausted`, `monotonic-deadline-expired`,
`service-restart-invalidated-state`, `service-restart-revoked-grant`, and the
existing `ticket-*` codes. Simulator-specific endpoint alerts supplement, but do
not rewrite, those Core records.

## Exact counter semantics

`SimulationSnapshot` exposes current count/capacity pairs for every table in the
new simulator-limit table and these cumulative checked counters:

- `AcceptedReadCount`: increment once only after the minifilter pending reservation
  succeeds.
- `ReleasedReadCount`: increment once when a pending read leaves minifilter
  ownership, whether normally or fail-open. Duplicate dispositions do not count.
- `AcceptedFlowCount`: increment once after held-flow entry and byte reservations
  both succeed. Existing reconnect-required observations do not count.
- `ReleasedFlowCount`: increment once when an accepted held flow leaves WFP
  ownership by grant, block, fail-open, crash, or timeout.
- `FailedOpenOperationCount`: increment once per unique `OperationId` that had an
  accepted read and/or held flow and transitions from live to fail-open. A linked
  read and flow with the same `OperationId` cannot count twice. One global
  invalidation may increment it by the number of unique live operation IDs;
  later cleanup cannot increment it again.
- `OverflowCount`: increment once per failed queue/map/scheduler/byte reservation.
  Failing open multiple operations because of that one reservation does not add
  overflow events.
- `DroppedEnvelopeCount`: increment once when a scripted drop consumes its exact
  target. Timeout cleanup is not another drop.
- `CriticalAlertCount`: increment once per simulator Critical Alert emitted. Core
  alerts remain separately countable through Core snapshots.
- `MinifilterCrashCount`, `MinifilterRestartCount`, `WfpCrashCount`,
  `WfpRestartCount`, `ServiceRestartCount`: increment once when the scheduled fault
  executes, not when it is planned.
- `DiagnosticAlertEvictionCount` and `TransitionTraceEvictionCount`: increment once
  per terminal diagnostic evicted from a full ring. These evictions never affect
  authority or the other counters.
- `CurrentHeldByteCount`: exact sum of the `long` counts in live held-flow records;
  increment and decrement occur in the same host transition as entry ownership.
- `InstalledGrantCount`: current WFP grant metadata entries, never greater than
  the Core active-grant reservation count or 256.

All cumulative counters start at zero for a new host. A service restart preserves
cumulative diagnostic counters but clears current counts. A new process/scenario
starts a new host and therefore resets them. Counters use checked arithmetic and
must not be clamped or inferred from ring length. A simulator-created
`CriticalAlert` captures the cumulative failed-open and overflow values after the
fault transition has completed.

## Privacy assertions

The following are acceptance requirements, not documentation guidance:

- Simulator-declared records/classes must have no field or property of type
  `byte[]`, `Stream`, `Memory<byte>`, `ReadOnlyMemory<byte>`, or
  `ArraySegment<byte>`.
- Simulator source and serialized names must not contain `Content`, `Payload`,
  `RawPath`, `FilePath`, `Packet`, `Buffer`, or `TicketSecret` as data fields.
- The simulator stores `FileVersionIdentity`, destination/subject metadata, exact
  identifiers, generations, timestamps, and checked `long` byte counts only.
- It never opens a user file, creates a socket, captures a packet, allocates a
  byte-count-sized buffer, or serializes/logs `OneTimeTicket.AuthenticatorProof`.
- JSON output exposes counts, capacities, outcome/reason, redacted logical IDs,
  and endpoint availability only. It does not serialize `SimulationStepResult` or
  an entire ticket/grant contract.
- Tests include reflection over simulator-declared DTO properties and source-text
  checks for forbidden data-bearing types/APIs. Referenced Core cryptographic
  implementation is outside that reflection set and remains opaque.

## Acceptance-test matrix

The new tool's `--acceptance-suite --json` must report every locked name below.
`tests/EgressGuard.Tests/Program.cs` launches that suite once, verifies every row
is present and passed, verifies the final aggregate counters, and fails if stderr
or output claims real enforcement.

| Locked scenario name | Acceptance contract |
|---|---|
| `disabled-default-zero-state` | No-argument/default host is Disabled and every authority, pending, held, scheduler, ticket, and grant count is zero. |
| `happy-new-tcp` | Full pre-read → arm → full Ack → disposition → completion → TCP challenge → AllowOnce → ticket → redemption → grant path succeeds in exact order. |
| `happy-new-udp` | Same path for UDP, with exact destination/protocol binding. |
| `release-requires-full-ack` | Read cannot release before full Ack; partial and degraded Ack fail open and alert. |
| `completion-requires-exact-binding` | Wrong disposition identity/sequence/Ack or stale minifilter generation cannot advance. |
| `existing-tcp-reconnect-required` | Immediate reconnect outcome; no challenge/hold/ticket/grant. |
| `existing-udp-reconnect-required` | Immediate reconnect outcome; no challenge/hold/ticket/grant. |
| `existing-quic-reconnect-required` | UDP-bound QUIC metadata returns reconnect only; no false stream blocking. |
| `delay-before-deadline-succeeds` | Manual time before deadline preserves pending state; due event then succeeds. |
| `delay-at-deadline-fails-open` | Equality expires, alerts, cancels late event, and reaches zero ownership. |
| `drop-times-out-deterministically` | One exact envelope is dropped; no sleep; manual deadline fails open and cleans all state. |
| `minifilter-crash-restart-cleans` | Crash/restart use fresh generations, alert, release all reads, invalidate authority, and accept only new-generation work. |
| `wfp-crash-restart-cleans` | Crash/restart release held counts/grants, alert, invalidate authority, and accept only new-generation work. |
| `service-restart-cleans` | Fresh boot/endpoints/clock invalidate ticket and grant; every owned live count ends zero. |
| `stale-wfp-generation-rejected` | Stale Ack/challenge fails open with Core plus simulator evidence. |
| `stale-minifilter-generation-rejected` | Stale completion fails open; pending metadata removed exactly once. |
| `pending-read-subject-cap` | Four live reads for one subject remain; fifth fails open; map count remains four. |
| `pending-read-global-cap` | Sixty-four live reads remain; sixty-fifth fails open; map count remains 64. |
| `challenge-subject-cap` | Four live challenges for one subject remain; fifth fails open; held/challenge counts do not exceed four. |
| `challenge-global-cap` | 128 live challenges remain; 129th fails open; count remains 128. |
| `endpoint-channel-boundaries` | Every 64/128-sized endpoint channel accepts exactly its cap and rejects the next without live eviction. |
| `held-flow-entry-boundaries` | Per-subject/global held maps accept exact caps and reject the next. |
| `held-data-flow-cap` | 256 KiB is accepted; 256 KiB + 1 fails open with no byte allocation. |
| `held-data-global-cap` | 4 MiB total is accepted; one additional byte fails open; total never exceeds cap. |
| `scheduler-cap` | 512 events are retained; event 513 fails open/alerts; live entries are not evicted. |
| `fault-plan-cap` | 256 faults are retained; fault 257 is rejected and counted exactly once. |
| `pump-dispatch-budget` | Attempt 1,025 processes at most 1,024, fails open, alerts, clears ownership, and returns. |
| `ticket-replay-through-endpoint` | First redemption installs one grant; exact replay never installs another and held state is zero. |
| `ticket-capacity-through-endpoint` | Core ticket/grant capacity failure propagates fail-open/alert and releases the held flow. |
| `grant-expiry-and-byte-count` | Manual duration expiry or exact 512 MiB used count removes WFP grant metadata; no payload exists. |
| `policy-change-cleans-endpoints` | Policy epoch change reconciles Core terminal results and removes held/grant endpoint state. |
| `privacy-metadata-only` | Reflection/source/output assertions prove metadata and byte-count-only storage and opaque ticket proof. |
| `no-wall-clock-or-event-workers` | Source contains no sleep/delay/timer/stopwatch/wall-clock authorization or per-event task/thread. |
| `all-faults-finish-zero-owned-state` | Every crash, restart, timeout, and overflow scenario satisfies the common zero-state postcondition. |

All pre-existing tests must continue to pass. New tests must not use
`Thread.Sleep` or `Task.Delay`; process completion uses the existing test harness
with a bounded cancellation token only as a harness safety net, never as a
simulation decision clock.

## Files Luna may change for 5B-04

Only these paths are permitted:

- `tools/EgressGuard.OutboundGateSimulator/EgressGuard.OutboundGateSimulator.csproj`
  (new);
- `tools/EgressGuard.OutboundGateSimulator/Program.cs` (new; contains the locked
  internal components above);
- `tools/EgressGuard.OutboundGateSimulator/packages.lock.json` (new, only if
  generated by locked restore);
- `tests/EgressGuard.Tests/Program.cs` (register and validate the acceptance suite);
- `EgressGuard.sln` (add the new project only);
- solution/project lock files only if `dotnet restore --locked-mode` demonstrably
  requires them and they contain no dependency unrelated to the new project.

`tests/EgressGuard.Tests/EgressGuard.Tests.csproj` is not expected to change. The
test harness invokes the built simulator executable, matching existing tool-test
patterns. Any need to change a Core, protocol, service, Windows, persistence, UI,
driver, or documentation file is a stop condition and requires review before
editing.

## Stop conditions

Stop 5B-04 implementation and report a blocker if any of the following occurs:

- a required scenario cannot be expressed through the existing Core public API;
- implementation would require changing a Core contract/state machine/ticket
  service, weakening replay protection, or creating a second authority engine;
- a read can release normally before a current full-coverage Ack and exact
  disposition, or a held flow can receive a grant without ticket redemption;
- a queue/map/scheduler has no hard cap, evicts live state, exceeds its count, or
  cannot prove zero ownership after fault cleanup;
- Disabled mode creates any pending operation, held flow, ticket, grant, scheduler
  event, or other authority;
- deterministic behavior requires wall-clock time, sleep/delay, timer, background
  worker, per-event task/thread, real file I/O, or real network I/O;
- any simulator DTO or output contains content, packet payload, raw path, a
  data-bearing byte container/stream, or ticket proof;
- existing TCP/UDP/QUIC is described as blocked/held instead of
  `ReconnectRequired`;
- implementation requires Administrator, WDK, driver installation, WFP/filter
  mutation, UI changes, or work from 5B-05 or later;
- a new required file falls outside the allowed list;
- baseline or existing tests regress.

## Design-lock baseline

On the required base, before this documentation-only change:

- `dotnet restore EgressGuard.sln --locked-mode`: passed;
- `dotnet build EgressGuard.sln -c Release --no-restore`: passed with 0 warnings
  and 0 errors;
- `dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c Release --no-build`:
  93/93 tests passed.

No simulator source, project, test implementation, UI work, driver work, or
Phase 5B-05 work is part of this design-lock commit.
