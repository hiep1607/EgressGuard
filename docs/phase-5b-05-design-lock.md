# Phase 5B-05 simulated decision UI design lock

Status: **design locked with one explicit Core transaction prerequisite;
implementation blocked pending approval**

Base: `838bae471263a73187d5723998339b357754be6b`

Base branch: `feature/phase-5b-04-driver-simulators`

Implementation branch: `feature/phase-5b-05-simulated-decision-ui`

Scope: ticket `5B-05` only

This document is normative for the Phase 5B-05 implementation. “Must”, exact
message names, ownership, bounds, reason codes, authorization rules, transition
rules, acceptance rows, allowed files, and stop conditions below are frozen.
This commit adds no UI, Service, Protocol, Core, simulator, persistence, test, or
driver behavior.

## Scope

5B-05 adds a single, bounded WPF presentation surface for the already simulated
outbound-gate decision flow. It displays Service-projected metadata and lets an
authorized caller choose exactly one of:

- `Allow once` for the current challenge;
- `Remember for 30 days` for the exact file version, application identity, and
  destination/protocol represented by the current challenge;
- `Block` for the current intent/flow only.

The UI also displays reconnect-required notices, gate status, remembered-rule
state, and Critical fail-open alerts. Every Phase 5B-05 surface carries the
literal visible label `Simulation`. It is evidence for user-mode contract and UI
behavior only; it is not an enforcement claim.

### Explicit exclusions

- No WDK, driver, minifilter, WFP callout, driver handle, firewall mutation,
  Administrator elevation flow, kernel install, packet capture, or real network
  enforcement.
- No file content, packet payload, TLS plaintext, content hash, raw path, command
  line, ticket authenticator, ticket, or grant is sent to or stored by the UI.
- No durable database policy in Phase 5B-05. Remembered simulation rules are
  Service-owned, RAM-only, and deliberately disappear on service restart.
- No persistent deny. `Block` never creates a Windows Firewall rule or a
  remembered rule.
- No reuse, relabeling, or wiring of the existing Alerts/Rules-tab firewall
  commands as Phase 5B decisions. Their existing `Always allow`, `Block`, and
  rule-reset behavior remains a separate Phase 4 firewall workflow.
- This design-only commit changes no Core or simulator code. The later
  implementation is blocked on the single minimal atomic policy/decision Core
  amendment specified below; no other Core or 5B-04 change is permitted.
- No task, thread, timer, window, or dialog per prompt. No wall-clock time grants
  authority or extends a decision/rule lifetime.
- No Phase 5B-06, 5C, 5D, or 5E work.

## Current-code gap and minimal safe composition

`NetworkGateChallenge` has the exact challenge, subject, destination, flow, and
decision-window bindings, but it intentionally does not contain the protected
file version or a redacted display label. Sending it directly to the UI cannot
produce an honest `Remember for 30 days` preview. The UI must not infer those
fields from a selected Phase 4 flow, file correlation, executable path, or any
client-supplied value.

5B-05 therefore does **not** amend `NetworkGateChallenge`. The Service-side
simulation coordinator retains the trusted `FileReadIntent` that preceded the
challenge and joins these server-owned values:

```text
trusted FileReadIntent
+ trusted redacted ProtectedFileDisplayMetadata
+ accepted NetworkGateChallenge
+ current GateStatus and service-monotonic receipt
→ validated SimulatedDecisionPromptProjection
→ UI
```

`ProtectedFileDisplayMetadata` is a Service-boundary value supplied only by the
trusted simulation source, never by Named Pipe input. Its only field is
`RedactedFileLabel`, from 1 through 96 UTF-16 code units. It rejects control
characters, `:`, `/`, and `\`, and any rooted/path-shaped value. It may contain a
synthetic redacted basename and extension; it contains no directory. A missing or
invalid label cannot enable `Remember for 30 days` and is a stop condition for
the fixture that produced it.

The Service retains the full `FileVersionIdentity` for exact matching. The UI
receives only a safe display selector: the opaque metadata `VersionToken`, size,
last-write/change audit times, and optional USN. `VolumeId` and `FileId` are not
serialized to the UI. The token is a file-version metadata token, never called a
content hash.

This composition requires new Protocol DTOs and a Service coordinator. The
existing `UserDecision.UiTimestampUtc` property is populated with the Service
audit clock at receipt; despite its legacy name, 5B-05 does not accept a client
timestamp. `AuthenticatedCaller` is populated by the Service from Named Pipe
impersonation.

## Open DESIGN BLOCKER: atomic remembered-policy transition

The current Core public API cannot safely implement `Remember for 30 days`:

1. `ReceiveDecision(AlwaysAllow)` issues the current ticket using the current
   `PolicyEpoch`.
2. `ApplyPolicyEpoch(newEpoch)` invalidates every context whose immutable
   `GateArmRequest.PolicyEpoch` differs, including the current challenge, and
   clears outstanding ticket/grant authority.
3. Calling `ApplyPolicyEpoch` before `ReceiveDecision` terminally fails the
   current challenge, so it can no longer receive the decision.
4. Calling it after `ReceiveDecision` invalidates the ticket just issued for the
   remembered decision.
5. Omitting the epoch change would allow outstanding authority from before a
   persistent policy mutation to survive, contradicting the frozen Phase 5
   policy-epoch rule.

Service-side ordering, rollback, or a test fixture cannot repair this without
either weakening PolicyEpoch or duplicating Core authority. Implementation must
not choose either shortcut.

### Minimum Core amendment requiring independent approval

The only proposed Core addition is:

```csharp
public sealed record PersistentDecisionTransitionResult
{
    public int Version { get; }
    public GateTransitionResult DecisionResult { get; }
    public IReadOnlyList<GateStatus> InvalidatedStatuses { get; }
    public long PolicyEpoch { get; }
}

public PersistentDecisionTransitionResult ReceivePersistentDecision(
    UserDecision decision,
    long nextPolicyEpoch);
```

It is a Simulation-only transition. `decision` must be `AlwaysAllow` with the
existing exact `RequestedPersistentScope`; `nextPolicyEpoch` must equal the
current epoch plus one with checked arithmetic. Under the existing state-machine
transition lock it must:

1. validate the exact active `AwaitingDecision` context, monotonic deadline,
   subject/challenge, and persistent scope before mutation;
2. advance the ticket service and state machine to `nextPolicyEpoch`;
3. fail open/revoke every **other** old-epoch context and return their bounded
   `GateStatus` values;
4. carry the selected context forward at `nextPolicyEpoch` through an internal
   effective-epoch field rather than mutating its immutable `GateArmRequest`;
5. process the selected decision and issue its ticket at `nextPolicyEpoch`;
6. preserve existing ticket-capacity fail-open behavior and never create a rule,
   ticket, or grant outside Core.

The result constructor requires version `1`, a non-null decision result, a
copied list of at most 255 invalidated statuses (all old-epoch contexts other
than the selected one), and a non-negative epoch. While the selected context
remains active, an exact repeat of the same decision/epoch returns the same
result with the nested decision result marked duplicate and changes no
epoch/counter/alert; a different binding is rejected. The Service's bounded
receipt remains the terminal replay authority after the Core active context
leaves.

If validation fails, epoch and all state remain unchanged. Once epoch advancement
succeeds, the Service commits the pre-reserved in-memory rule even if current
ticket issuance later fails open from bounded ticket capacity: the persistent
policy mutation was accepted, while the current traffic honestly failed open.
The Service reconciles every returned invalidated status before publishing UI
events. No persistence or UI type enters Core.

The amendment also changes ordinary `ApplyPolicyEpoch` comparison to the
context's internal effective epoch. It must retain the current state-machine →
ticket-service lock order and add deterministic tests for prevalidation rollback,
other-context invalidation, current-context carry-forward, ticket epoch binding,
capacity failure, active exact duplicate, mismatched/concurrent calls, overflow,
and later epoch invalidation.

Proposed amendment file ceiling, in a separately reviewed commit, is only:

- `src/EgressGuard.Core/OutboundGateModels.cs`;
- `src/EgressGuard.Core/OutboundGateStateMachine.cs`;
- `tests/EgressGuard.Tests/Program.cs`.

Until this exact amendment is independently approved, 5B-05 implementation must
stop after this design artifact. `Allow once` and `Block` being implementable via
the existing API do not justify shipping a partial three-decision UI.

## Component and API map

| Component | 5B-05 responsibility | Must not do |
|---|---|---|
| `SimulatedDecisionCoordinator` in Service | Own trusted prompt projections, remembered simulation rules, decision receipts, monotonic expiry, exact Core/authority forwarding, and snapshot construction. | Duplicate Core authority, trust UI scope/time/caller, persist raw data, or mint a ticket/grant itself. |
| `ISimulatedDecisionAuthority` Service boundary | Expose the current simulation clock/audit clock, accept a Service-built `UserDecision`, apply policy epoch, and return only the authoritative transition result to the coordinator. Default implementation is Disabled. | Accept a decision from the pipe directly or expose ticket/grant material to UI code. |
| Trusted simulation fixture/source | Supply paired `FileReadIntent`, redacted display metadata, accepted challenge/status/alert, mutation events, and deterministic manual-clock pumping through an in-process Service boundary. | Listen on a UI-writable seed message, accept raw paths, or create a second mutable authority engine. |
| `PipeServer` | Authorize the impersonated caller, dispatch snapshot/decision/revoke/subscription messages, preserve correlation IDs, and translate stable errors. | Trust handshake client name, payload caller/time/scope, or open a driver handle for UI. |
| `SimulatedDecisionEventHub` | One bounded, non-blocking event stream for decision UI state with sequence, overflow marker, subscriber cap, and resync. | Store authority or block a publisher on a slow UI. |
| Protocol DTOs/clients | Carry only bounded UI projections, `ChallengeId + choice`, `RuleId`, snapshot sequence, and typed events. | Carry `UserDecision`, `RequestedPersistentScope`, `OneTimeTicket`, `EphemeralFlowGrant`, proof bytes, or arbitrary reason/scope strings from UI. |
| `SimulatedDecisionViewModel` | Maintain bounded presentation collections, one shared display timer/batch, reconnect/resync, commands, focus state, and accessibility text. | Construct Core contracts, decide freshness, create firewall rules, or retain terminal authority. |
| `SimulatedDecisionPanel` | One responsive, scrollable, keyboard-accessible WPF surface inside `MainWindow`. | Open one window/dialog/task per prompt or use coordinate-based interaction. |

The default Service registers a Disabled `ISimulatedDecisionAuthority`. Tests
inject a deterministic in-process authority through the same coordinator API;
there is no Named Pipe message that can enable simulation or seed a challenge.
No environment variable silently enables authority.

After the prerequisite is approved, the narrow authority boundary exposes only
`ReceiveDecision(UserDecision)`,
`ReceivePersistentDecision(UserDecision, long)`, `ApplyPolicyEpoch(long)`, the
current policy epoch/manual clocks, and read-only projection of authoritative
results. It does not expose ticket issuance/redemption methods to PipeServer or
UI types.

## Protocol contract

All new contracts are immutable, version `1`, constructor-validated, and live in
`EgressGuard.Protocol`. Existing framing remains version `1` with a 1 MiB maximum.
Every collection is copied and validated at construction.

### Exact message type names

```text
Phase5B.Ui.GetSnapshot
Phase5B.Ui.Snapshot
Phase5B.Ui.Subscribe
Phase5B.Ui.Event
Phase5B.Ui.SubmitDecision
Phase5B.Ui.DecisionResult
Phase5B.Ui.RevokeRememberedRule
Phase5B.Ui.RuleMutationResult
```

These constants are added beside the existing Phase 5B vocabulary. They do not
replace or repurpose `CreateRule`, `DeleteRule`, `NetworkGateChallenge`, or
`UserDecision` messages.

### Request contracts

```csharp
public enum SimulatedDecisionChoice
{
    Unspecified,
    AllowOnce,
    RememberFor30Days,
    BlockCurrent
}

public sealed record GetSimulatedDecisionSnapshotMessage(int Version);

public sealed record SubscribeSimulatedDecisionEventsMessage(
    int Version,
    long LastSequence);

public sealed record SubmitSimulatedDecisionMessage(
    int Version,
    Guid ChallengeId,
    SimulatedDecisionChoice Choice);

public sealed record RevokeSimulatedRememberedRuleMessage(
    int Version,
    Guid RuleId);
```

`Unspecified`, unknown enum values, empty identifiers, negative sequences, extra
scope, time, caller, decision ID, nonce, ticket, or grant fields are rejected.
The envelope correlation ID is transport correlation only; it is not authority
and is not the business dedupe key.

### Projection contracts

The exact projection vocabulary is:

```csharp
public enum SimulatedDecisionSubjectKind
{
    ExactProcess,
    ExactProcessGroup
}

public enum SimulatedDecisionItemState
{
    AwaitingDecision,
    AllowedOnce,
    Remembered,
    BlockedCurrent,
    Expired,
    FailedOpen,
    ReconnectRequired,
    Revoked,
    FileVersionInvalidated,
    PolicyInvalidated
}

public sealed record SimulatedFileVersionProjection(
    int Version,
    string VersionToken,
    long SizeBytes,
    DateTimeOffset LastWriteTimeUtc,
    DateTimeOffset ChangeTimeUtc,
    long? Usn);

public sealed record SimulatedSubjectProjection(
    int Version,
    SimulatedDecisionSubjectKind Kind,
    ProcessIdentity PrimaryProcess,
    Guid? ProcessGroupId,
    IReadOnlyList<ProcessIdentity> ExactMembers,
    bool HasCollateralScope,
    string? CollateralWarning);

public sealed record SimulatedDestinationProjection(
    int Version,
    IPAddress Address,
    IpVersion IpVersion,
    int RemotePort,
    TransportProtocol Protocol,
    string? DomainEvidence,
    DomainEvidenceProvenance DomainProvenance,
    DateTimeOffset? DomainObservedAtUtc);

public sealed record SimulatedDecisionExpiryProjection(
    int Version,
    long RemainingMilliseconds,
    DateTimeOffset ProjectedAtUtc,
    bool AcceptingDecisions);

public sealed record SimulatedDecisionPromptProjection(
    int Version,
    Guid ChallengeId,
    Guid IntentId,
    string RedactedFileLabel,
    SimulatedFileVersionProjection FileVersion,
    string ApplicationIdentity,
    SimulatedSubjectProjection Subject,
    SimulatedDestinationProjection Destination,
    bool ExistingFlow,
    GateRuntimeState State,
    string ReasonCode,
    string? LimitationReason,
    SimulatedDecisionExpiryProjection Expiry,
    long Revision);
```

Prompt invariants are:

- `ChallengeId` and `IntentId` are non-empty and match the retained trusted
  context.
- `RedactedFileLabel` satisfies the 96-code-unit/path-separator rule above.
- `VersionToken` and `ApplicationIdentity` are 1 through 128 code units;
  limitation/reason fields use the existing 256-code-unit bound; domain evidence
  uses 253.
- Exact-process scope contains only `PrimaryProcess`, no group ID, no collateral
  warning, and `HasCollateralScope == false`.
- Exact-group scope has a non-empty group ID, 2 through 32 unique canonical exact
  process generations including the primary process, `HasCollateralScope ==
  true`, and the fixed warning: `This decision affects the displayed browser
  process group and may delay unrelated activity in that group.`
- `ExistingFlow` is always `false` for a decision prompt in Phase 5B. Existing
  multiplexed flows never receive a fabricated challenge.
- Only `AwaitingDecision` has `Expiry.AcceptingDecisions == true` and remaining
  time from 1 through 15,000 ms. Equality with the deadline is expired.
- The visible environment label is not caller-provided. The WPF surface renders
  the literal `Simulation` for every prompt and notice.

The remaining projection types are exactly:

```csharp
public sealed record SimulatedReconnectRequiredProjection(
    int Version,
    Guid IntentId,
    string RedactedFileLabel,
    SimulatedFileVersionProjection FileVersion,
    string ApplicationIdentity,
    SimulatedSubjectProjection Subject,
    SimulatedDestinationProjection Destination,
    string ReasonCode,
    string? LimitationReason,
    DateTimeOffset AuditTimeUtc,
    long Revision);

public sealed record SimulatedRememberedRuleProjection(
    int Version,
    Guid RuleId,
    string RedactedFileLabel,
    SimulatedFileVersionProjection FileVersion,
    string ApplicationIdentity,
    SimulatedDestinationProjection Destination,
    DateTimeOffset CreatedAtUtc,
    DateTimeOffset ExpiresAtUtc,
    SimulatedDecisionItemState State,
    string ReasonCode,
    long Revision);

public sealed record SimulatedGateStatusProjection(
    int Version,
    Guid? IntentId,
    GateRuntimeState State,
    string ReasonCode,
    DateTimeOffset AuditTimeUtc,
    bool TrafficFailedOpen,
    long DroppedCount,
    long OverflowCount,
    long Revision);

public sealed record SimulatedCriticalAlertProjection(
    int Version,
    Guid AlertId,
    Guid? IntentId,
    SimulatedSubjectProjection? Subject,
    string ReasonCode,
    DateTimeOffset AuditTimeUtc,
    long DroppedCount,
    long OverflowCount,
    bool TrafficFailedOpen,
    string PresentationText,
    long Revision);
```

`SimulatedReconnectRequiredProjection` deliberately has **no ChallengeId**.
This split is mandatory because 5B-04 creates no `NetworkGateChallenge` for an
existing TCP/UDP/QUIC observation. It renders `ReconnectRequired`, has no
decision buttons, creates no ticket/grant, and makes no blocked/held claim.
`SimulatedRememberedRuleProjection` never contains the Service's hidden full
`FileVersionIdentity`.

A failed-open alert must render:

```text
Traffic was allowed (fail-open). This operation is no longer protected.
```

It must not say “upload blocked”, “upload prevented”, “file secured”, or any
equivalent enforcement claim.

### Snapshot, events, and results

```csharp
public sealed record SimulatedDecisionAuthorizationProjection(
    bool CanView,
    bool CanAllowOnce,
    bool CanRememberFor30Days,
    bool CanBlockCurrent,
    bool CanRevoke,
    string ReasonCode);

public sealed record SimulatedDecisionSnapshotMessage(
    int Version,
    long Sequence,
    bool SimulationEnabled,
    SimulatedDecisionAuthorizationProjection Authorization,
    IReadOnlyList<SimulatedDecisionPromptProjection> ActivePrompts,
    IReadOnlyList<SimulatedReconnectRequiredProjection> ReconnectNotices,
    IReadOnlyList<SimulatedRememberedRuleProjection> RememberedRules,
    IReadOnlyList<SimulatedGateStatusProjection> RecentStatuses,
    IReadOnlyList<SimulatedCriticalAlertProjection> CriticalAlerts);

public enum SimulatedDecisionEventKind
{
    PromptUpserted,
    PromptRemoved,
    ReconnectRequired,
    RememberedRuleUpserted,
    RememberedRuleRemoved,
    StatusChanged,
    CriticalAlertRaised,
    ResyncRequired
}

public sealed record SimulatedDecisionEventMessage(
    int Version,
    long Sequence,
    SimulatedDecisionEventKind Kind,
    SimulatedDecisionPromptProjection? Prompt,
    Guid? RemovedChallengeId,
    SimulatedReconnectRequiredProjection? ReconnectNotice,
    SimulatedRememberedRuleProjection? RememberedRule,
    Guid? RemovedRuleId,
    SimulatedGateStatusProjection? Status,
    SimulatedCriticalAlertProjection? CriticalAlert,
    bool RequiresResync);

public sealed record SimulatedDecisionResultMessage(
    int Version,
    long Sequence,
    Guid ChallengeId,
    SimulatedDecisionChoice Choice,
    SimulatedDecisionItemState State,
    string ReasonCode,
    bool IsDuplicate,
    long Revision);

public enum SimulatedRuleMutationKind
{
    Revoke
}

public sealed record SimulatedRuleMutationResultMessage(
    int Version,
    long Sequence,
    Guid RuleId,
    SimulatedRuleMutationKind Mutation,
    SimulatedDecisionItemState State,
    string ReasonCode,
    bool IsDuplicate,
    long Revision);
```

`SimulatedDecisionEventMessage` one-of validation rejects an event whose
populated member does not match its kind. All sequences/revisions are
non-negative and monotonically increase under Service ownership. Snapshot and
projection constructors enforce the collection caps below.

Decision/rule responses contain only the requested identifier, typed choice or
mutation, resulting presentation state, stable reason code, and `IsDuplicate`.
They never serialize Core transition objects, tickets, grants, persistent scope,
or caller identity.

Every successful response uses its exact Phase5B response message type and the
request envelope correlation ID. Validation/authorization/terminal failures use
the existing `MessageTypes.Error` envelope with `ErrorMessage.Code` equal to one
stable reason code from this document and a bounded sanitized display message.
Unknown message types remain `REQUEST_REJECTED`; they never fall back to a
firewall or Core message handler.

`GetSnapshot` returns `Phase5B.Ui.Snapshot`; `SubmitDecision` returns
`Phase5B.Ui.DecisionResult`; `RevokeRememberedRule` returns
`Phase5B.Ui.RuleMutationResult`. An accepted `Subscribe` first receives the
existing `MessageTypes.Success` response with its request correlation ID, then
only `Phase5B.Ui.Event` envelopes until disconnect or resync.

## Trust boundary and authorization model

The UI is untrusted. Named Pipe ACL access is necessary but not sufficient.
Phase 5B-05 uses these distinct rights:

| Operation | Required caller | Authority effect |
|---|---|---|
| General Phase 4 flow/status reads | Existing pipe policy; unchanged | None. |
| View decision snapshot | Impersonated local Administrator | Reads redacted simulation metadata only. |
| Subscribe to decision events | Impersonated local Administrator | Reads redacted simulation metadata only. |
| `Allow once` | Impersonated local Administrator | One current challenge; Service-built `UserDecision.AllowOnce`. |
| `Remember for 30 days` | Impersonated local Administrator | One current challenge plus one narrow RAM-only rule reservation. |
| `Block` | Impersonated local Administrator | Current intent/flow only; no persistent deny/firewall rule. |
| Revoke remembered rule | Impersonated local Administrator | Exact Service-owned simulation rule only. |

Restricting prompt reads as well as mutations avoids exposing even redacted file
labels to another interactive logon session; current Core subjects contain no
Windows user/session SID with which to filter prompts safely. A later relaxation
requires a separately reviewed trusted recipient-SID contract and is outside
5B-05.

For every authorized request, `PipeServer` calls `RunAsClient` before acquiring
the coordinator lock, captures the Windows SID and Administrator membership,
then returns to the service identity. Handshake `ClientName`, payload fields,
environment variables, and UI process identity are never caller evidence. The
Service formats `AuthenticatedCaller` as `sid:<Windows SID>` (maximum 128 code
units) and never accepts this string from the UI.

### Exact decision construction

Under the coordinator transition lock, the Service:

1. Finds one active retained context by exact `ChallengeId`.
2. Rechecks Simulation enabled, caller permission, phase, revision, trusted
   subject/challenge binding, and the Service monotonic deadline.
3. Generates `DecisionId` through the authority's nonce provider.
4. Sets `UiTimestampUtc` from the injected Service audit clock at receipt.
5. Sets `AuthenticatedCaller` from the impersonated SID.
6. For `RememberFor30Days`, constructs `RequestedPersistentScope` from the
   retained full `FileReadIntent.File`,
   `NetworkGateChallenge.Subject.ApplicationIdentity`, and exact
   `NetworkGateChallenge.Destination`. No UI scope value participates.
7. Sends Allow/Block through existing `ReceiveDecision`; sends Remember only
   through the approved `ReceivePersistentDecision` amendment with a checked
   next policy epoch.
8. Publishes only a projection/result after validating the authoritative return.

The coordinator never invokes the public ticket constructor and never calls the
ticket service directly. Ticket issuance/redemption and ephemeral grant remain
inside the existing Core/simulator authority. UI code and UI Protocol clients
must not reference `OneTimeTicketMessage`, `EphemeralFlowGrantMessage`,
`UserDecisionMessage`, or `RequestedPersistentScope`.

## Decision and state transitions

### Allow once

`AwaitingDecision → AllowedOnce` is accepted once for the exact challenge. It
creates no remembered rule. A ticket/grant, if returned and redeemed by the
simulation authority, remains opaque to the coordinator and UI. A second flow or
different destination/protocol requires another challenge.

### Remember for 30 days

Before calling authority, the coordinator reserves capacity for the exact
canonical rule under the same transition lock. An exact existing live rule is an
idempotent match; a different rule at cap is rejected without evicting live
state or calling Core. The UI remains on the current active prompt and may choose
`Allow once` or `Block` before its deadline.

For a new rule, the coordinator calls the approved atomic
`ReceivePersistentDecision` with the checked next epoch. On authoritative epoch
acceptance, it commits the already reserved rule at the returned epoch and
reconciles all returned invalidated statuses. An exact live-rule match does not
change the policy table or epoch; it sends a Service-built `AlwaysAllow` decision
through ordinary `ReceiveDecision` using that current rule/epoch. The coordinator
renders a preview equal to the hidden canonical selector:

```text
exact FileVersionIdentity
+ exact ApplicationIdentity
+ exact DestinationBinding, including transport protocol
```

The preview never replaces exact Service matching. Browser/group collateral is
shown for the current prompt but the remembered selector remains the fixed
Phase 5B file-version/application/destination/protocol scope; it is never a
publisher-wide or browser-wide permission.

### Block

`AwaitingDecision → BlockedCurrent` sends `UserDecision.Block`, removes the
current prompt/held-flow state through authority, and creates no rule, ticket, or
grant. It does not call `CreateRule`, `IFirewallRuleManager`, PowerShell, or
Windows Firewall. The UI label is `Block current flow`, with help text stating
that it is not a persistent firewall block.

### Timeout, failed open, and reconnect required

At monotonic deadline equality, authority wins: the prompt becomes Expired or
FailedOpen, all decision buttons are disabled, and any later request returns the
same terminal reason or a stable expired result. UI wall-clock countdown is
display-only and may disable early; it can never extend or re-enable authority.

Existing multiplexed TCP/UDP/QUIC produces a reconnect notice, not a prompt. The
notice says the existing flow was not held and a new connection is required for
the simulation. No Block/Allow/Remember control is present.

## Persistent simulation model

The Service's `SimulatedDecisionCoordinator` solely owns a RAM-only
`SimulatedRememberedRule` table. Each record contains:

- random `RuleId`;
- full exact `FileVersionIdentity`;
- the already-redacted label;
- exact canonical `ApplicationIdentity`;
- exact `DestinationBinding`, including protocol;
- creating caller SID for local audit only;
- service-monotonic creation/deadline;
- Service audit display creation/expiry;
- current `PolicyEpoch` and revision.

It contains no raw path, file content, path hash presented as a content hash,
process PID authority, ticket, grant, authenticator, payload, or packet data.

The lifetime is exactly `30 * 24 * 60 * 60 * 1000` monotonic milliseconds.
Deadline equality is expired. Early removal is mandatory on explicit revoke,
file-version mutation, policy-epoch invalidation, service restart, or dispose.
Service restart clears all remembered rules rather than reconstructing a 30-day
deadline from wall clock. The UI states: `Remembered for up to 30 days in this
simulation; service restart, mutation, revocation, or policy change clears it.`

### Mutation, revoke, expiry, and policy epoch

- Trusted mutation input identifies the stable hidden volume/file identity and a
  changed full file version. It is never a UI/Named Pipe mutation message.
- Mutation removes every rule for the old exact version immediately, marks its
  projection `FileVersionInvalidated`, and prevents it matching a later prompt.
- Revoke accepts only a `RuleId`; Service looks up and removes the hidden scope.
- One manual expiry sweep removes every rule at or beyond deadline.
- New-rule creation advances PolicyEpoch through the approved atomic persistent
  decision transition. Revoke, mutation invalidation, expiry batch, or explicit
  policy change increments PolicyEpoch exactly once for that batch and calls the
  existing authority policy-epoch transition so outstanding tickets/grants
  cannot outlive the change. Surviving rules are atomically restamped to the new
  epoch under the coordinator lock; the removed/invalid rule never survives.
- An exact remembered match may auto-submit only a Service-built
  `AlwaysAllow/RememberFor30Days` decision for a later exact challenge. A stale
  file, application, destination, protocol, epoch, or expired rule cannot match.

No rule is evicted to admit another live rule. Terminal UI history may evict its
oldest non-authoritative item at its documented cap.

## State ownership and lock order

| State | Owner | Release rule |
|---|---|---|
| Core intent/challenge/ticket/grant | Existing simulation authority | Existing terminal, expiry, restart, policy, and dispose transitions. |
| Trusted intent/challenge join | `SimulatedDecisionCoordinator` | Challenge terminal, timeout, failed open, restart, policy invalidation, or dispose. |
| Active prompt projection map | Coordinator | Same exact challenge terminal transition; never independently authorizes. |
| Remembered simulation rules | Coordinator | 30-day monotonic expiry, revoke, mutation, epoch change, restart, or dispose. |
| Decision receipt dedupe | Coordinator terminal diagnostics | Five-minute monotonic diagnostic retention, cap eviction, restart, or dispose. Never authority. |
| Event subscribers/channels | `SimulatedDecisionEventHub` | Disconnect, overflow/resync, service stop, or dispose. |
| UI active collections/event buffer | `SimulatedDecisionViewModel` | Terminal event, resync snapshot replacement, window close, or dispose. |

Lock order is:

1. Pipe impersonation/caller capture with no coordinator/Core/UI lock held;
2. `SimulatedDecisionCoordinator` transition lock;
3. existing `OutboundGateStateMachine` transition lock through the authority;
4. existing `OneTimeGateTicketService` lock inside Core;
5. non-blocking event-hub `TryWrite` after the authoritative transition result is
   reconciled, while ordering remains serialized by the coordinator;
6. UI Dispatcher mutation after IPC callback returns, with no Service lock.

No event callback enters the coordinator. No PipeServer, event hub, or UI lock is
held while impersonating a client. No endpoint lock is acquired before Core.

## Frozen bounds

Existing Phase 5B bounds remain unchanged: 2-second read/gate-arm, 15-second
decision/network hold, 5-second ticket, one-flow grant up to 5 minutes/512 MiB,
pending reads 4/subject and 64/global, active challenges 4/subject and 128/global,
held data 256 KiB/flow and 4 MiB/global, tickets 8/subject and 256/global,
tombstones 2,048, active grant IDs 256, and process groups 32 exact members.

New 5B-05 bounds are:

| Resource | Hard cap |
|---|---:|
| Service active prompt projections | 4 per subject; 128 global |
| Service trusted intent/challenge joins | 128 global |
| Remembered simulation rules | 8 per application; 64 global |
| Decision terminal receipt dedupe | 256 global; five-minute monotonic retention |
| Reconnect-required presentation history | 64 terminal notices |
| Recent gate-status presentation history | 64 terminal/current rows |
| Critical-alert presentation history | 64 terminal alerts; Core/Service authoritative history remains 256 |
| Decision event subscribers | 4 connections; existing PipeServer remains 8 total instances |
| Per-subscriber event channel | 256 events |
| UI sequenced decision event buffer | 512 events |
| UI event dispatch per 250 ms batch | 128 events |
| UI active prompts | 128 rows |
| UI remembered rules | 64 rows |
| UI reconnect/status/alert presentation | 64 rows for each kind |
| Exact group members in one projection | 32 |

The 64-rule global cap is intentionally lower than the 1 MiB framing limit and
keeps a worst-case snapshot containing 128 prompts with 32-member scopes,
64 rules, and bounded status/alert histories testably below the frame maximum.
Acceptance serializes the maximum synthetic snapshot and requires it to remain
below `ProtocolConstants.MaximumMessageBytes`.

No live prompt, rule, or subscriber is evicted to admit new live state. A full
subscriber channel is drained, receives one `ResyncRequired` marker, and skips
further events until reconnect. A full UI buffer clears and requests a snapshot.
Only terminal presentation/receipt history uses oldest-first eviction, with an
exact eviction counter where exposed.

The prompt/join maps are a one-to-one projection of Core's active challenge
authority and are reconciled synchronously under the coordinator lock. A Core
cap refusal creates no projection. If a projection reservation nevertheless
fails for an already accepted challenge, the coordinator treats this as an
invariant failure: it performs the existing conservative service-runtime
invalidation through the authority, emits `sim-ui-projection-capacity-exhausted`,
disables every prompt, reconciles all owned state to zero, and never hides a live
hold from the UI.

## IPC, reconnect, dedupe, and resync

Decision metadata uses a dedicated authorized subscription request on the same
Named Pipe endpoint. It is not broadcast through the existing general
interactive-user event subscription.

The specialized decision event client requests
`TokenImpersonationLevel.Impersonation`, matching the request client, so
PipeServer can capture and authorize the exact Windows caller before accepting
the subscription. The existing general event client remains at Identification
and cannot subscribe to the decision stream.

Connection order is:

```text
authorized request connection → GetSnapshot
snapshot carries Sequence N
authorized event connection → Subscribe(lastSequence: N)
→ events N+1...
```

All decision-state mutations and their sequence allocation occur under the
coordinator transition lock. Snapshot state and its sequence are captured under
that same lock, so a decision event cannot be skipped between the snapshot and
sequence boundary. Unrelated Phase 4 flow events do not share this decision
sequence.

On disconnect, sequence gap, duplicate/out-of-order sequence, subscriber
overflow, UI buffer overflow, or explicit resync marker, the client:

1. disables all decision commands;
2. disconnects the decision event stream;
3. obtains a complete authorized snapshot;
4. atomically replaces bounded collections;
5. subscribes from the returned sequence;
6. enables only prompts whose snapshot state and expiry permit decisions.

Event dedupe uses sequence plus object ID/revision. Business request dedupe uses
`ChallengeId + accepted choice` and a bounded terminal receipt. An exact replay
returns the prior result with `IsDuplicate = true` and never calls authority
again. A different choice for a terminal challenge returns
`sim-ui-decision-conflict`. After receipt eviction, Core/coordinator terminal
state still rejects revival; eviction can never recreate authority.

## Stable reason codes

The Service/Protocol layer uses these exact codes:

| Reason | Meaning |
|---|---|
| `sim-ui-disabled` | Default authority is disabled and owns no prompt/rule state. |
| `sim-ui-prompt-active` | Exact projected challenge awaits a decision. |
| `sim-ui-allow-once-accepted` | Current exact challenge accepted Allow once. |
| `sim-ui-remember-30-days-accepted` | Current exact challenge and canonical remembered scope accepted. |
| `sim-ui-block-current-accepted` | Current intent/flow blocked without persistent deny. |
| `sim-ui-rule-revoked` | Exact remembered simulation rule revoked. |
| `sim-ui-rule-file-version-invalidated` | Trusted file mutation invalidated the rule. |
| `sim-ui-rule-policy-invalidated` | Policy epoch invalidated the rule. |
| `sim-ui-rule-expired` | Exact 30-day monotonic deadline reached. |
| `sim-ui-reconnect-required` | Existing multiplexed flow was not held; new connection required. |
| `sim-ui-critical-fail-open` | Traffic was allowed and no longer protected. |
| `sim-ui-administrator-required` | Impersonated caller lacks the locked permission. |
| `sim-ui-request-invalid` | Version, enum, ID, one-of, or bound validation failed. |
| `sim-ui-challenge-not-found` | No live or retained terminal challenge matches. |
| `sim-ui-challenge-expired` | Monotonic deadline was reached before acceptance. |
| `sim-ui-challenge-terminal` | Challenge is terminal and cannot accept new authority. |
| `sim-ui-decision-conflict` | A different choice attempted to reuse a terminal challenge. |
| `sim-ui-remembered-rule-capacity-exhausted` | Rule reservation cap rejected the new rule without eviction. |
| `sim-ui-projection-capacity-exhausted` | An accepted challenge could not obtain its required bounded UI projection; all simulation authority fails open and is reconciled. |
| `sim-ui-subscriber-capacity-exhausted` | A fifth decision event subscription is rejected without evicting the four live subscribers. |
| `sim-ui-remembered-rule-not-found` | Revoke target is unknown or already removed. |
| `sim-ui-file-version-stale` | Retained full file version no longer matches. |
| `sim-ui-policy-epoch-stale` | Context/rule epoch is no longer current. |
| `sim-ui-resync-required` | Event continuity cannot be proven. |
| `sim-ui-authority-result-invalid` | Authority returned a result that violates the requested transition; UI remains disabled and a Critical Alert is emitted. |

Core reason codes remain unchanged and may be included as read-only status
evidence; they are never replaced with a more optimistic UI reason.

## UI and accessibility contract

One `Simulation Decisions` tab is added to `MainWindow`. Its content is a single
`SimulatedDecisionPanel` with:

- persistent visible `Simulation` badge and explanatory non-enforcement copy;
- active prompt list and selected-prompt detail;
- redacted file/version, application, exact process/group, destination,
  domain-provenance, limitation, reconnect, and expiry sections;
- exact remembered-scope preview before the Remember command;
- separate `Allow once`, `Remember for 30 days`, and `Block current flow`
  commands;
- remembered-rule list with a separate Revoke command;
- Critical fail-open live region and status history.

The panel is responsive and contains one vertical `ScrollViewer`. It has no
fixed content width, does not clip commands, and preserves logical tab order.
Long labels/domain/reasons wrap; member lists virtualize/scroll. Button text is
never shortened to an ambiguous firewall action.

`MainWindow` changes its minimum client size from 900 × 560 DIP to 640 × 480 DIP.
The simulation tab uses a stacked narrow layout below 900 DIP; its command area
wraps in logical order. Existing tabs retain their behavior and must remain
scrollable/reachable rather than being clipped at the new minimum.

Required Automation IDs are:

```text
SimulationDecisionTab
SimulationModeLabel
SimulationStatus
DecisionPromptList
DecisionFileLabel
DecisionFileVersion
DecisionApplication
DecisionSubjectScope
DecisionCollateralWarning
DecisionDestination
DecisionDomainProvenance
DecisionExistingFlowWarning
DecisionLimitation
DecisionExpiry
DecisionScopePreview
AllowOnceButton
Remember30DaysButton
BlockCurrentFlowButton
RememberedRuleList
RevokeRememberedRuleButton
ReconnectRequiredNotice
CriticalFailOpenBanner
SimulationRefreshButton
```

Every actionable control has an accessible name/help text. Group collateral,
limitation, expiry, and critical fail-open text are exposed to screen readers.
Critical fail-open uses an assertive live region; ordinary status uses polite.
Keyboard-only users can reach every row, detail, decision, revoke, refresh, and
scroll region. On prompt removal, focus moves to the next prompt or the panel
heading, never to a stale disabled button.

One shared Dispatcher timer may update display countdowns and drain at most 128
events per 250 ms. It is presentation only. No prompt creates a timer, task,
thread, window, or dialog.

### Small-window and DPI acceptance

The panel must measure/arrange without horizontal clipping at a 640 × 480 DIP
host and remain fully reachable by vertical scrolling. Windows CI validates the
same physical viewport model at 100%, 150%, and 200% by arranging at the
corresponding logical widths/heights and checking focusable bounds, wrapping,
scroll extent, and button reachability. WPF remains Per-Monitor DPI aware; this
deterministic layout test is not a claim of testing every physical monitor.

## Privacy assertions

Acceptance must prove:

- no new UI/Protocol/Service projection field is named or typed as `RawPath`,
  `FilePath`, `Content`, `Payload`, `Packet`, `Buffer`, `TicketSecret`,
  `AuthenticatorProof`, `OneTimeTicket`, or `EphemeralFlowGrant`;
- serialized prompt/snapshot/event/result output contains no `VolumeId`, `FileId`,
  caller SID, full executable path, ticket/grant, proof bytes, or raw path;
- redacted labels reject directory separators, drive prefixes, and controls;
- file-version tokens are described only as metadata selectors, never content
  hashes;
- UI copy contains no “upload blocked”, “upload prevented”, “file protected”, or
  real-enforcement claim;
- fail-open copy explicitly says traffic was allowed and is no longer protected;
- no driver handle, filesystem read, socket capture, packet payload, or byte
  count-sized allocation exists in the Phase 5B-05 path.

## Deterministic test architecture

The existing executable test project remains the test runner. No UI test package,
screen recorder, screenshot artifact, physical display, mouse-coordinate click,
human action, Administrator elevation prompt, or external test service is used.

### Service/Named Pipe fixture

- Construct real `PipeServer`, coordinator, and decision event hub in-process
  with a unique pipe name and temporary synthetic state.
- Inject one deterministic manual monotonic/audit clock and scripted nonce
  provider shared with the fake authority.
- Seed trusted challenge/label/mutation events only through the coordinator's
  internal trusted-source API, never through the pipe.
- Exercise the real request framing, pipe impersonation, authorization dispatch,
  event subscription, sequence, overflow, disconnect, reconnect, and resync.
- Use a hard 30-second timeout per integration case and a 90-second ceiling for
  the UI suite. Timeout is a harness safety net, not an authorization clock.
- Finally close clients, complete subscriptions, dispose coordinator/hub/server,
  close every WPF window, shut down the Dispatcher, wait for owned tasks/processes,
  and prove zero prompt/rule/subscriber/pipe ownership.

### WPF Automation on Windows CI

- Create one dedicated STA thread and one WPF Dispatcher for the UI suite; do not
  rely on the async console runner's apartment state.
- Host the real `SimulatedDecisionPanel` and view model with the real Protocol
  clients against the fixture pipe.
- Use `AutomationId`, `FrameworkElementAutomationPeer`, selection/value peers,
  and `IInvokeProvider`; never use screen coordinates or a physical mouse.
- Drive Tab/Shift+Tab/Enter/Space semantics, inspect accessible names/help text,
  and verify focus after prompt terminalization.
- Measure/arrange synthetic maximum-length data at the locked small-window/DPI
  viewports; assert controls stay in bounds or are reachable by scroll.
- Close the window/Dispatcher in `finally`; any remaining window, dispatcher,
  subscriber, service task, or pipe fails the test.

The existing CI job already uses `windows-latest` and builds WPF through
`net8.0-windows`. UI tests must pass in that job without an interactive desktop
or display-specific assumptions.

## Acceptance-test matrix

| Locked case | Required evidence |
|---|---|
| `sim-ui-disabled-default` | Default Service snapshot says disabled; zero prompts, rules, subscribers, tickets, grants, or authority; commands disabled. |
| `sim-ui-projection-exact-and-redacted` | Service joins trusted intent/challenge/label; UI sees exact IDs, safe label/version selector, application, exact subject, destination/protocol/domain provenance, limitation, expiry, and Simulation label; no hidden selectors leak. |
| `sim-ui-allow-once` | UI invokes by AutomationId; pipe contains only ChallengeId + AllowOnce; Service supplies nonce/audit/caller; authority called once; UI receives no ticket/grant. |
| `sim-ui-remember-scope-preview` | Preview equals Service canonical file-version/application/destination/protocol projection and displays group collateral; request carries no scope. |
| `sim-ui-remember-policy-transaction` | Approved atomic Core transition advances epoch once, invalidates every other old-epoch context, carries only the selected context forward, and binds its ticket to the new epoch; failed prevalidation changes nothing. |
| `sim-ui-remember-and-auto-match` | Exact rule reservation/commit succeeds, later exact challenge auto-matches through Service-built decision, and any selector mismatch prompts again. |
| `sim-ui-revoke` | Admin sends RuleId only; exact rule removed; epoch advances once; old rule/ticket/grant cannot revive. |
| `sim-ui-file-mutation-invalidates` | Trusted metadata mutation immediately removes old-version rule, advances epoch once, and a later version requires a prompt. |
| `sim-ui-policy-epoch-invalidates` | Epoch change clears stale rules/prompts/authority and publishes exact state. |
| `sim-ui-block-current-only` | Current intent/flow terminates Blocked; no remembered deny, firewall request/rule, ticket, or grant. |
| `sim-ui-timeout-at-equality` | Manual deadline equality disables all choices; late request is rejected; Critical fail-open copy says traffic was allowed/no longer protected. |
| `sim-ui-reconnect-required` | Existing TCP, UDP, and QUIC render non-decision notices with no ChallengeId/buttons/hold/block claim. |
| `sim-ui-critical-fail-open` | Alert is assertive, exact counters/reason shown, all stale decisions disabled, and zero false enforcement text. |
| `sim-ui-exact-duplicate` | Exact ChallengeId + choice replay returns prior receipt with `IsDuplicate`; authority/counters/alerts/rules do not increase. |
| `sim-ui-conflicting-replay` | Different choice for terminal ChallengeId returns conflict without mutation or authority. |
| `sim-ui-caller-forgery-rejected` | DTO has no caller/time/scope fields; non-admin policy is rejected; handshake name cannot grant rights; Service-built caller is impersonated SID. |
| `sim-ui-disconnect-reconnect-resync` | Lost connection, sequence gap, server/UI buffer overflow, and explicit marker disable commands, replace from snapshot, and resume at exact sequence without duplicate authority. |
| `sim-ui-bounds-and-framing` | 4/subject and 128/global prompts preserved; cap+1 rejected without live eviction; rules stop at 8/application/64 global; maximum snapshot stays below 1 MiB. |
| `sim-ui-small-window-dpi` | MainWindow and every tab remain reachable at the new 640 × 480 DIP minimum; deterministic 100/150/200% viewport models preserve wrapping, scrolling, focus, and reachable simulation commands. |
| `sim-ui-keyboard-screen-reader` | Required AutomationIds, accessible names/help/live regions, tab order, invoke peers, and terminal focus behavior pass without coordinate clicks. |
| `sim-ui-privacy-scan` | Reflection/source/serialized JSON find no raw path, hidden file IDs, caller SID, content/payload, ticket/grant/proof, or prohibited field type. |
| `sim-ui-zero-false-enforcement-claims` | Source/resources/rendered text contain no upload-blocked/real-enforcement claim; all surfaces visibly say Simulation. |
| `sim-ui-cleanup-zero-owned-state` | Every test closes windows/dispatcher/pipe/subscribers and disposes prompts/rules/receipts; all owned counts end zero. |

All existing tests, including all 34 5B-04 scenarios and current Named Pipe/UI
tests, must continue to pass. Authorization and expiry tests use manual time and
events/barriers, not `Thread.Sleep` or `Task.Delay` to decide behavior.

## Files allowed in the later implementation

Only these paths may change in the separately reviewed implementation:

- `src/EgressGuard.Protocol/OutboundGateMessages.cs`;
- `src/EgressGuard.Protocol/Messages.cs`;
- `src/EgressGuard.Protocol/EgressGuardEventClient.cs`, or one new narrowly named
  `src/EgressGuard.Protocol/EgressGuardSimulatedDecisionEventClient.cs` instead;
- `src/EgressGuard.Service/PipeServer.cs`;
- `src/EgressGuard.Service/Program.cs` for Disabled coordinator registration only;
- `src/EgressGuard.Service/SimulatedDecisionCoordinator.cs` (new; includes the
  authority/source boundary, RAM store, and snapshots);
- `src/EgressGuard.Service/SimulatedDecisionEventHub.cs` (new);
- `src/EgressGuard.UI/MainWindow.xaml`;
- `src/EgressGuard.UI/MainWindow.xaml.cs` only for one panel/view-model lifecycle;
- `src/EgressGuard.UI/MainWindowViewModel.cs` only if needed to surface the new
  panel without changing existing firewall commands;
- `src/EgressGuard.UI/SimulatedDecisionPanel.xaml` (new);
- `src/EgressGuard.UI/SimulatedDecisionPanel.xaml.cs` (new, presentation only);
- `src/EgressGuard.UI/SimulatedDecisionViewModel.cs` (new);
- `src/EgressGuard.UI/App.xaml` only for panel styles/accessibility resources;
- `tests/EgressGuard.Tests/Program.cs`;
- `docs/phase-5b-report.md` for final implementation evidence only.

SDK project files and package locks are not expected to change because the
projects use default compile/page globs and required WPF/AutomationPeer APIs are
already in the Windows target. If a package/project/solution change becomes
necessary, stop for review rather than adding it opportunistically.

## Forbidden implementation files and actions

- Every file under `src/EgressGuard.Core` during the UI/Service implementation.
  The separately approved prerequisite may touch only the two Core files and
  tests named in the blocker section; `OneTimeGateTicketService.cs` remains
  forbidden.
- `tools/EgressGuard.OutboundGateSimulator/**` and all 5B-04 design/evidence.
- Existing persistence/database/migration code.
- `src/EgressGuard.Windows/**`, firewall managers, PowerShell, service installer,
  drivers, solution/project/lock files, and CI workflow.
- Changing current Alerts/Rules firewall commands to masquerade as Phase 5B
  decisions.
- Driver handles, firewall changes, real file/network I/O, raw-path collection,
  payload/content inspection, or enabling simulation by untrusted IPC/environment.

## Stop conditions

Stop implementation and report a DESIGN BLOCKER if any of these becomes true:

- a redacted label and full file-version context cannot be supplied together by
  a trusted in-process source without raw path/content;
- the Service cannot retain the trusted intent/challenge join and would require
  the UI to construct exact persistent scope;
- UI input can supply caller, time, nonce, decision ID, persistent selector,
  ticket, or grant;
- a ticket/grant or authenticator would cross into UI/Protocol projection code;
- a Core change beyond the separately approved atomic prerequisite, or any
  5B-04 simulator change, is needed;
- safe behavior would require a second authority state machine or a test-only
  IPC backdoor that production dispatch does not use;
- remembered rules cannot be bounded, revoked, expired monotonically, cleared on
  service restart, or invalidated on exact file mutation/policy epoch;
- `Block` or `Remember` would invoke existing firewall commands or broaden
  application/file/destination/protocol scope;
- prompt metadata cannot be restricted to the impersonated authorization policy;
- event loss cannot force an atomic snapshot resync before decisions re-enable;
- UI Automation cannot run deterministically on Windows CI with peers,
  AutomationIds, hard timeout, and zero owned cleanup;
- any DTO/persistence/log contains a raw path, file content, packet payload,
  hidden ticket material, caller SID in UI output, or an unbounded collection;
- small-window/DPI/accessibility acceptance requires coordinate clicks, a real
  display, or human input;
- the implementation needs a file outside the allowlist, modifies PR #8, starts
  5B-06/later work, or regresses existing tests.

## Design self-review checklist

- Projection gap: closed by Service join projection; no fake file scope and no
  change to `NetworkGateChallenge`.
- Policy transaction gap: isolated as the single minimal Core prerequisite;
  implementation remains blocked until independent approval.
- Trust boundary: UI sends only ChallengeId + typed choice or RuleId; Service
  impersonates, builds caller/nonce/time/scope, and revalidates monotonic state.
- Authority: UI/coordinator never mint ticket/grant; existing authority remains
  sole owner.
- Persistent simulation: exact, RAM-only, 30-day monotonic, revocable,
  mutation/epoch/restart invalidated, and hard bounded.
- IPC: dedicated authorized stream, bounded channels, exact sequence, dedupe,
  reconnect, and snapshot resync.
- Privacy: no raw path/content/payload/hidden file IDs/ticket proof in UI output.
- UX: Simulation label, honest reconnect/fail-open copy, group collateral,
  timeout disabling, small-window/DPI, keyboard, screen reader, AutomationIds.
- Semantics: Allow once is one current challenge; Remember is exact narrow scope;
  Block is current-only and never firewall persistence.
- Testing: real framing/PipeServer path, deterministic authority/clock, one STA
  Dispatcher, no coordinate click/display dependency, hard timeout/cleanup.
- Scope: documentation-only now; later allowed files are explicit; 5B-06 is not
  started.

No other P0/P1/P2 design finding remains after this self-review. The one explicit
DESIGN BLOCKER above is unresolved by design and prevents implementation until
its exact minimal amendment is independently approved. The later implementation
must stop rather than weaken any contract above.

## Design-only baseline validation

On base `838bae471263a73187d5723998339b357754be6b`, with only this untracked
design artifact present:

- `dotnet restore EgressGuard.sln --locked-mode`: passed; all projects up to date;
- `dotnet format EgressGuard.sln --verify-no-changes --no-restore`: passed;
- `dotnet build EgressGuard.sln -c Release --no-restore`: passed with 0 warnings
  and 0 errors;
- `dotnet run --project tests\EgressGuard.Tests\EgressGuard.Tests.csproj -c
  Release --no-build`: 95/95 tests passed, including the 34-case 5B-04 suite;
- `dotnet list EgressGuard.sln package --vulnerable --include-transitive`:
  passed; no vulnerable package was reported;
- `git diff --check`: passed.

No Phase 5B-05 source, Protocol, Service, UI, test, simulator, persistence, or
Core implementation is included in this design-lock commit.
