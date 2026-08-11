# Phase 5 execution plan

Status: Phase 5A design only. Every ticket below is intentionally bounded so Luna can complete it in one focused turn using the named inputs. A ticket must stop when its prerequisite, acceptance criterion or safety boundary is not met.

## Global rules

- Preserve Phase 4 behavior and keep all Phase 5 functionality disabled by default.
- Never claim that WFP identifies every file upload. No TLS decryption, packet payload capture or file-content read/storage is permitted by this plan.
- No blanket Internet block. Every gate is limited to an exact process/process group, intent, destination/protocol and deadline.
- All queues, maps, replay sets, pending operations and grants require hard bounds and deterministic expiry.
- No driver install or host mutation without a separate explicit authorization for a disposable/recoverable lab VM.
- Production signing, WDK provenance and Application Control approval are independent prerequisites. Never enable test-signing, disable Secure Boot or weaken Windows security automatically.
- Every EgressGuard terminating/unknown-callout WFP filter sets `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED`; prototype filters are dynamic/non-persistent and never boot-time enforcement filters.
- WFP callout registration precedes the transaction that installs exact-owned provider/sublayer/filter objects; normal shutdown removes/disables those filters before callout unregister.
- Each implementation ticket gets its own commit and evidence. A failed stop condition is recorded rather than bypassed.

### Frozen Phase 5B simulation limits

| Resource | Fixed default |
|---|---|
| Gate-arm/read deadline | 2 seconds |
| User-decision/network-hold deadline | 15 seconds |
| Ticket validity | 5 seconds |
| Ephemeral grant | One flow; at most 5 minutes or 512 MiB |
| Pending reads | 4 per subject; 64 global |
| Active challenges | 4 per subject; 128 global |
| Held network data | 256 KiB per flow; 4 MiB global |
| Outstanding tickets | 8 per subject; 256 global |
| Replay tombstones | 2,048 global |
| Browser group | 32 exact members |

Phase 5C/5D may select different lab limits, but each limit set must be frozen before its test run and must not be changed after results are observed.

## Dependency map

```text
5B-01 → 5B-02 → 5B-03 → 5B-04 → 5B-05
                                  ├─→ 5C-01 → 5C-02 → 5C-03 → 5C-04
                                  └─→ 5D-01
5C-04 + 5D-01 → 5D-02 → 5D-03 → 5D-04 → 5D-05
5C-04 + 5D-05 → 5E-01 → 5E-02 → 5E-03 → 5E-04
5E-04 → 5F-01 → 5F-02 → 5F-03
```

The `drivers/...` paths below are forecasts only. Phase 5A does not create them.

## Phase 5B — user-mode simulation only

### 5B-01: Freeze protocol vocabulary

- **Inputs:** `docs/phase-5-design.md`, current `ProcessIdentity`, protocol framing limits.
- **Work:** Add immutable, versioned design-domain records for file identity, `GateCoverage`, gate subject, destination, intent, arm request/ack, read disposition/completion ack, challenge, decision, ticket and grant. Keep them independent of WDK types. Treat UI time as audit data and define service-monotonic freshness.
- **Acceptance:** Serialization round trips; coverage flags include new TCP/UDP, existing TCP stream, existing UDP/datagram and reconnect-required simulation; every string/count/time field has validation and a documented bound; unknown required coverage fails explicitly; existing protocol remains compatible; no driver project or Windows mutation.
- **Stop:** Any contract requires content, raw path persistence, unbounded collections or PID-only authorization.
- **Model:** Luna; request Sol High review only if a trust-boundary field must change.
- **Expected files:** `src/EgressGuard.Core/OutboundGateModels.cs`, `src/EgressGuard.Protocol/OutboundGateMessages.cs`, `tests/EgressGuard.Tests/Program.cs`.
- **Depends on:** the fixed Phase 5B decisions in `docs/phase-5-design.md`.

### 5B-02: Implement the pure gate state machine

- **Inputs:** 5B-01 contracts and the ordered state machine in the design.
- **Work:** Pure in-memory transitions for intent receipt, full-coverage gate acknowledgement, file-read disposition/completion, challenge, decision, ticket issuance/redemption, expiry and terminal fail-open/block states. Inject monotonic service clock and nonce provider.
- **Acceptance:** Deterministic tests reject partial/mismatched/stale gate acknowledgements, wrong request/ack nonce, intent/subject/policy/driver-generation mismatch, `ReleaseAfterGateArmed` without the accepted Ack ID, stale UI-clock manipulation and decisions received after the service-monotonic deadline. Duplicate dispositions/completion acknowledgements are idempotent. Timeout, service restart and policy-epoch tests produce explicit fail-open/critical evidence; no I/O or per-event tasks; all state uses the frozen bounds.
- **Stop:** A transition can release a protected read before a full-coverage current Ack, trusts UI time for freshness, or can hang indefinitely.
- **Model:** Luna.
- **Expected files:** `src/EgressGuard.Core/OutboundGateStateMachine.cs`, `tests/EgressGuard.Tests/Program.cs`.
- **Depends on:** 5B-01.

### 5B-03: Implement one-time ticket simulation

- **Inputs:** ticket contract and pure state machine.
- **Work:** Boot-scoped authenticator abstraction, exact binding validation, atomic nonce consumption, bounded replay cache and creation of a separate ephemeral grant.
- **Acceptance:** Tests reject replay, expiry, future not-before, altered field, PID reuse, file mutation, destination/protocol/flow mismatch, boot change and policy change; consumed tombstones outlive every valid ticket; capacity pressure refuses issuance and takes the explicit fail-open/critical-alert path rather than making an old ticket replayable.
- **Stop:** Ticket material is logged/persisted, a ticket itself is reusable, or eviction permits a consumed nonce to authorize traffic.
- **Model:** Luna with Sol High security review.
- **Expected files:** `src/EgressGuard.Core/OneTimeGateTicketService.cs`, `tests/EgressGuard.Tests/Program.cs`.
- **Depends on:** 5B-02.

### 5B-04: Add deterministic driver simulators

- **Inputs:** 5B contracts/state machine; no WDK.
- **Work:** Fake minifilter and WFP endpoints with bounded channels. Simulate pre-read pending, coverage negotiation, disposition/completion acknowledgement, new TCP/UDP, `ReconnectRequired` for existing multiplexed flows, delay, drop, crash and restart using the frozen limits.
- **Acceptance:** End-to-end tests show read release only after a full-coverage Ack plus matching disposition or the explicit two-second fail-open deadline; partial/degraded coverage publishes a critical alert; no content/payload field exists; overflow and final counters are exact; disabled remains the default.
- **Stop:** Simulator is presented as real enforcement, or requires Administrator/driver installation.
- **Model:** Luna.
- **Expected files:** `tools/EgressGuard.OutboundGateSimulator/EgressGuard.OutboundGateSimulator.csproj`, `tools/EgressGuard.OutboundGateSimulator/Program.cs`, `tests/EgressGuard.Tests/Program.cs`, solution/lock files only as required.
- **Depends on:** 5B-02 and 5B-03.

### 5B-05: Add simulated decision UI

- **Inputs:** simulated challenge/status stream and current Named Pipe/UI patterns.
- **Work:** Show redacted file label, exact app/group scope, destination/protocol, existing-flow warning, expiry and three decisions. Label the 30-day exact-file-version action `Remember for 30 days`, clearly mark the feature `Simulation`, and show fail-open critical alerts.
- **Acceptance:** UI Automation covers Allow once, exact file-version/application/destination/protocol 30-day scope preview, revoke/mutation invalidation, Block, timeout, `ReconnectRequired`, and small-window/DPI layouts; no raw path, ticket secret or false “upload blocked” claim.
- **Stop:** UI can mint tickets, widen Always allow silently, or hides browser collateral scope.
- **Model:** Luna.
- **Expected files:** `src/EgressGuard.UI/MainWindow.xaml`, `src/EgressGuard.UI/MainWindow.xaml.cs`, protocol client files directly required, `tests/EgressGuard.Tests/Program.cs`, `docs/phase-5b-report.md`.
- **Depends on:** 5B-04.

## Phase 5C — minifilter lab, no network enforcement

### 5C-01: Approve isolated kernel lab prerequisites

- **Inputs:** organizational signing/Application Control policy and disposable VM specification.
- **Work:** Document approved WDK version, VM snapshot/rollback, signing route, crash-dump collection and install/uninstall ownership. This ticket installs nothing.
- **Acceptance:** Independent Windows security reviewer signs off; host remains unchanged; production and test signing paths are not conflated.
- **Stop:** Work would require disabling Secure Boot, enabling host test-signing, bypassing Application Control, or using an unreviewed shared workstation.
- **Model:** Sol High plus human security owner.
- **Expected files:** `docs/phase-5c-lab-prerequisites.md`.
- **Depends on:** 5B-04.

### 5C-02: Implement metadata-only minifilter registration

- **Inputs:** approved 5C lab and 5B-01 wire contract.
- **Work:** Minimal minifilter for selected create/read callbacks, exact kernel-derived process generation and bounded metadata emission. Pass through all I/O; do not pend yet.
- **Acceptance:** Driver Verifier/lab smoke passes; no content read/copy/hash; no raw path outside the driver channel; queue overflow is bounded and observable; uninstall removes only owned artifacts.
- **Stop:** Identity is PID-only, callback performs unbounded/blocking work, or production workstation installation is required.
- **Model:** Sol High; Luna may implement bounded user-mode tests separately.
- **Expected files:** `drivers/EgressGuard.Minifilter/*`, `tests/EgressGuard.DriverContracts/*`, `docs/phase-5c-report.md`.
- **Depends on:** 5C-01.

### 5C-03: Prove file identity and mutation semantics

- **Inputs:** observe-only 5C-02 driver.
- **Work:** Lab fixtures for NTFS file ID/version, rename, hard link, truncate, delete/recreate, PID reuse, process exit, plus ReFS/remote/removable/unsupported volume rejection.
- **Acceptance:** Exact generations never cross; stale identity invalidates; no content read; only NTFS enters prototype enforcement; every unsupported volume fails open with an exact critical warning; file-version metadata digest/HMAC is never described as a content hash; coverage names excluded paging/memory-mapped cases.
- **Stop:** Path equality is treated as file identity or path hash as content hash.
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.Minifilter/*` only if a correctness fix is required, `tests/EgressGuard.DriverContracts/*`, `docs/phase-5c-report.md`.
- **Depends on:** 5C-02.

### 5C-04: Add bounded pre-read pending in the lab

- **Inputs:** proven identity behavior and simulator state transitions.
- **Work:** Pend only eligible IRP-based, non-paging reads in a bounded cancel-safe queue following the `FltCbdq` model. Never pend Fast I/O, paging I/O or an unsafe callback context; do not flood the system worker queue. Complete idempotently on full-coverage disposition, cancellation, teardown, process exit, shutdown or watchdog deadline.
- **Acceptance:** Tests cover cancellation races, instance teardown, process exit, service/driver stop and the two-second watchdog; every pending operation completes and final queue depth is zero. The 4-per-subject/64-global simulation bounds are enforced; lab bounds are frozen before measurement. Queue overflow fails open and produces an exact critical counter.
- **Stop:** Any read can remain indefinite, ineligible I/O is pended, system/boot-critical paths can be pended, deadlock/bugcheck occurs, worker work is unbounded, or cleanup cannot prove zero owned pending operations.
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.Minifilter/*`, `tests/EgressGuard.DriverContracts/*`, `docs/phase-5c-report.md`.
- **Depends on:** 5C-03.

## Phase 5D — WFP gate lab

### 5D-01: Validate WFP layer strategy without enforcement

- **Inputs:** Microsoft WFP documentation, target Windows builds and 5B contracts.
- **Work:** Observe/classify lab for ALE connect, TCP stream and UDP transport/datagram metadata. Record availability of app/process/flow identity and reauthorization behavior.
- **Acceptance:** Evidence distinguishes new from established flows, TCP from UDP and exact process generation from WFP app identity; no packet payload persisted; all filters are narrowly owned and removed.
- **Stop:** WFP data cannot be safely bound to the service's exact process generation, or cleanup affects non-EgressGuard filters.
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.WfpCallout/*`, `tests/EgressGuard.WfpContracts/*`, `docs/phase-5d-report.md`.
- **Depends on:** 5B-04 and 5C-01.

### 5D-02: Prove WFP fail-open filter lifecycle

- **Inputs:** 5D-01 layer evidence and the fail-open lifecycle in the design.
- **Work:** In an authorized VM, register the runtime callout before a transactional install of exact-owned provider/sublayer/dynamic non-persistent filters. Set `FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED` on every terminating/unknown-callout filter. Remove/disable filters before normal unregister and reconcile only exact ownership IDs.
- **Acceptance:** Separate tests cover callout not registered, driver unload, recoverable crash/fault-injected unavailable-callout behavior, service crash, BFE restart and filter-install rollback. In every live-OS unavailable-callout case targeted and unrelated traffic still pass, critical fail-open evidence is exact, and final inspection finds zero stale owned filters. Any actual kernel bugcheck is a failed test followed by reboot/rollback inspection, not counted as live fail-open success. Tests prove the result without relying solely on a watchdog.
- **Stop:** Any unavailable callout blocks traffic, any filter is boot-time/persistent, startup/shutdown ordering is reversed, rollback is incomplete, or cleanup touches a foreign object.
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.WfpCallout/*`, service driver-client boundary files, `tests/EgressGuard.WfpContracts/*`, `docs/phase-5d-report.md`.
- **Depends on:** 5C-04 and 5D-01.

### 5D-03: Gate new flows at initial ALE authorization

- **Inputs:** accepted 5D-02 fail-open lifecycle evidence and the one-time ticket simulator.
- **Work:** Implement bounded initial ALE pend/complete, service challenge, atomic ticket redemption and exact cleanup for new TCP/UDP flow authorization.
- **Acceptance:** Allow once/Block/timeout/replay/PID-reuse/destination mismatch pass in the VM; full required/armed coverage and exact Ack bindings are enforced; reauthorization is never pended; failure opens after the frozen deadline with a critical alert.
- **Stop:** Gate can affect another process or whole host, or pended operations survive driver/service stop.
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.WfpCallout/*`, service driver-client boundary files, `tests/EgressGuard.WfpContracts/*`, `docs/phase-5d-report.md`.
- **Depends on:** 5D-02.

### 5D-04: Spike established TCP stream gating

- **Inputs:** 5D-03 and the fixed `ReconnectRequired` default.
- **Work:** Keep `ReconnectRequired` as the product default and prove or reject an optional hard-bounded outbound TCP stream hold on an already-established TLS/HTTP/2 connection. Treat the entire scoped connection as opaque.
- **Acceptance:** Same-process isolation, fixed byte/time/memory ceilings, responsive unrelated processes, exact release/block behavior and zero retained payload. Report collateral effects honestly.
- **Stop:** Safe bounded holding is not demonstrable, payload inspection becomes necessary, or reconnect is safer. If stopped, select the documented reconnect/new-flow strategy rather than expanding scope.
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.WfpCallout/*`, `tests/EgressGuard.WfpContracts/*`, `docs/phase-5d-report.md`.
- **Depends on:** 5D-03.

### 5D-05: Spike UDP/QUIC gating

- **Inputs:** 5D-03, the fixed `ReconnectRequired` default and Microsoft QUIC/WFP constraints.
- **Work:** Keep `ReconnectRequired` as the product default and test an optional bounded per-flow UDP datagram gate, retransmission behavior, destination tuple change and QUIC migration. Do not parse QUIC or claim HTTP/3 stream identity.
- **Acceptance:** Bounds and fail-open remain correct; ordinary non-target UDP stays responsive; results state exactly which Windows builds/flows work and which are unsupported.
- **Stop:** Isolation requires blocking unrelated UDP, buffering becomes unbounded, or reliable resume cannot be achieved. Unsupported QUIC must remain explicit, not silently “protected.”
- **Model:** Sol High.
- **Expected files:** `drivers/EgressGuard.WfpCallout/*`, `tests/EgressGuard.WfpContracts/*`, `docs/phase-5d-report.md`.
- **Depends on:** 5D-04.

## Phase 5E — authorized integration and acceptance

### 5E-01: Integrate service orchestration behind a feature flag

- **Inputs:** accepted 5C/5D contracts and evidence.
- **Work:** Connect the Policy Service to both drivers using authenticated, bounded channels and boot/policy epochs. Default off; native WFP unavailable-callout permit behavior is mandatory and the fail-open watchdog remains defense in depth.
- **Acceptance:** Cold start, service crash, each-driver unavailable/recoverable-fault path, reconnect, BFE restart, reboot simulation and version mismatch tests pass; exact-owned dynamic filters leave no stale enforcement; Phase 4 observe-only behavior is unchanged when disabled.
- **Stop:** A component failure can leave an unexplained block or stale grant.
- **Model:** Sol High for boundary review; Luna for bounded service implementation/tests.
- **Expected files:** directly related files under `src/EgressGuard.Service`, `src/EgressGuard.Protocol`, `src/EgressGuard.Core`, driver clients, tests, `docs/phase-5e-report.md`.
- **Depends on:** 5C-04 and 5D-05.

### 5E-02: Integrate user decisions and persistent policy

- **Inputs:** 5B-05 UI and 5E-01 service orchestration.
- **Work:** Replace simulator endpoints with service-backed challenges; implement admin-authorized narrow Always allow persistence, revocation and audit.
- **Acceptance:** Scope preview equals stored canonical policy; non-admin mutation fails; policy epoch invalidates tickets; Clear history/privacy requirements pass; UI never talks to drivers.
- **Stop:** Always allow can broaden to any file/destination implicitly or stores raw paths/ticket secrets.
- **Model:** Luna with Sol High policy review.
- **Expected files:** directly related Core/Protocol/Service/Persistence/UI files, migration and tests, `docs/phase-5e-report.md`.
- **Depends on:** 5E-01.

### 5E-03: Validate browser process groups

- **Inputs:** selected browser-group authority and integrated prototype.
- **Work:** Bounded Chrome/Edge fixtures for renderer-to-network-service association, multiple tabs, profile/root restart, PID reuse and unrelated browser instance.
- **Acceptance:** Only authenticated exact members share a group; group expires; collateral gate scope is displayed; unknown layouts fail open critically; no publisher-wide grouping.
- **Stop:** A process can join by spoofing name/parent alone, or one browser instance gates another.
- **Model:** Sol High.
- **Expected files:** process-group service/Core files, safe fixtures/tests, `docs/phase-5e-report.md`.
- **Depends on:** 5E-02.

### 5E-04: Run failure, privacy and performance acceptance

- **Inputs:** exact candidate artifact and fixed budgets approved before measurement.
- **Work:** Driver Verifier, crash/reboot/rollback, queue/prompt floods, TCP/UDP/IPv4/IPv6, HTTP/2/HTTP/3 limitation cases, long-duration bounded stress, UI/IPC responsiveness and privacy inspection.
- **Acceptance:** No bugcheck/deadlock/leak, no stale block after failure/reboot, fail-open alerts exact, no raw path/content/payload leakage, fixed CPU/memory/latency budgets met, and unsupported cases labeled Not verified/Blocked.
- **Stop:** Any critical cleanup/security/privacy failure, missing exact-artifact evidence, or pressure to change budgets after results.
- **Model:** Sol High plus independent human reviewer.
- **Expected files:** bounded acceptance scripts/fixtures, `docs/phase-5e-report.md`, sanitized evidence only; never `.etl`, dumps, databases, screenshots with personal data or binaries.
- **Depends on:** 5E-03.

## Phase 5F — production-readiness decision

### 5F-01: Independent kernel security review

- **Inputs:** exact 5E candidate source/artifact/evidence.
- **Work:** Review memory safety, IRQL, cancellation, lock ordering, buffer validation, device ACLs, WFP/minifilter ownership, ticket cryptography, downgrade and rollback.
- **Acceptance:** All high/critical findings fixed and independently rechecked on the same source; residual risks recorded.
- **Stop:** Reviewer independence is unavailable or artifact/source provenance differs.
- **Model:** Sol High for preparation; independent qualified Windows driver reviewer for verdict.
- **Expected files:** `docs/phase-5f-security-review.md` and narrow fixes/tests only when separately approved.
- **Depends on:** 5E-04.

### 5F-02: Approve signing, Application Control and delivery

- **Inputs:** clean 5F-01 verdict, organizational PKI/Partner Center and Application Control owners.
- **Work:** Define production signing, attestation/WHQL choice, SBOM/provenance, WDAC compatibility, installer/update/uninstall/rollback and key custody. Do not sign in this ticket unless separately authorized.
- **Acceptance:** Named owners approve each prerequisite; no test certificate or security bypass appears in production flow; rollback preserves network recovery.
- **Stop:** Production key custody, Microsoft signing route or Application Control approval is absent.
- **Model:** Sol High plus human release/security owners.
- **Expected files:** `docs/phase-5f-release-readiness.md`, release workflow/config only in a later authorized ticket.
- **Depends on:** 5F-01.

### 5F-03: Issue final release verdict

- **Inputs:** 5F-01 and 5F-02 approvals plus exact-artifact acceptance.
- **Work:** Reconcile claims, threat model, privacy, support/rollback and blocked limitations into a go/no-go record.
- **Acceptance:** Verdict identifies exact commit/artifact, verified gates, blockers, recovery procedure and support owner. Documentation never upgrades Not verified/Blocked evidence.
- **Stop:** Any prerequisite is unresolved. Verdict remains `Blocked`; no release or merge-by-bypass.
- **Model:** Sol High plus independent human approver.
- **Expected files:** `docs/phase-5f-release-verdict.md`, and existing top-level documentation only after an approved release decision.
- **Depends on:** 5F-02.

## Phase-level acceptance and stop conditions

| Phase | Exit criteria | Mandatory stop |
|---|---|---|
| 5B | Deterministic simulator proves contracts, state, replay protection, bounds, failure and privacy; clearly labeled non-enforcing. | Any design requires content inspection, unbounded state or Windows mutation. |
| 5C | Isolated minifilter lab proves exact pre-read identity/order, mutation invalidation and bounded fail-open. | No approved lab/signing route; bugcheck, deadlock, identity ambiguity or host security weakening. |
| 5D | Isolated WFP lab proves scoped new-flow behavior and records honest established TCP/QUIC results. | Unrelated traffic is gated, cleanup is uncertain, or claims exceed observable WFP metadata. |
| 5E | Exact integrated artifact passes security, privacy, recovery, performance and UI acceptance. | Critical finding, stale enforcement, hidden fail-open, privacy leak or missed fixed budget. |
| 5F | Independent review plus signing/Application Control/release owners approve exact artifact. | Any prerequisite remains Blocked; no production release claim. |

## Decisions fixed for Phase 5B implementation

1. NTFS only; ReFS, remote, removable and unsupported volumes fail open with a critical warning.
2. `Remember for 30 days` binds exact file-version identity, application identity and destination/protocol; it is revocable and mutation invalidates it immediately.
3. Browser grouping is simulation-only process tree plus exact generations and executable/signature evidence; real enforcement is not claimed before Phase 5E.
4. Existing multiplexed connections default to `ReconnectRequired`; group-wide holds remain optional 5D experiments.
5. The table at the start of this plan is the frozen Phase 5B limit set. Phase 5C/5D limits are frozen before their tests and never tuned after results.
6. Cryptographic content hashing is excluded. Only a file-version metadata digest/HMAC token is permitted and it is never called a content hash.
