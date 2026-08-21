# Phase 5B-05 implementation evidence

## Scope and lineage

- Implementation branch: `feature/phase-5b-05-end-to-end`.
- Exact parent: Protocol PR #12 head `403d16c58194a3508ef031545ebdcbccb3e7cadf`.
- Locked design reviewed from PR #9 head `70b884a41e85b00e0e815ab0ab1d85487b34425e`.
- Core prerequisite remains PR #10 head `150d7ee21e18ee879187394198932b8a43e3a4bb`.
- Production registration uses `DisabledSimulatedDecisionAuthority`; no IPC or environment switch enables the trusted test authority.
- No Core, persistence, Windows/firewall, simulator, project, lock, configuration, workflow, or design-lock file is changed.

## Delivered behavior

The Service now owns trusted intent/challenge joins, redacted prompt projections,
RAM-only remembered rules, receipts, the bounded RuleId registry, snapshot
construction, and stable result/error translation. The UI sends only the locked
request DTOs. It cannot supply caller identity, time, nonce, scope, ticket, grant,
raw path, or file content. Caller authorization is taken from the impersonated
Named Pipe identity.

New rules use the approved atomic persistent-decision transition. Exact live-rule
reuse uses ordinary `AlwaysAllow` at the current epoch. Rule and current-traffic
outcomes remain independent, including committed-rule/current-traffic fail-open.
The event hub is bounded and non-blocking, has two subscribers, and disables UI
commands before resync work starts after any gap or overflow. Snapshot sequence
validation and subscriber admission are atomic under the Coordinator lock. Its
channel explicitly permits the PipeServer reader and overflow drain reader.
Each MainWindow owns one request connection shared by both view models plus two
event connections, so two real sessions use 6/8 pipe instances and leave the
locked two-instance request/reconnect reserve.

The WPF surface is one lifecycle-owned, scrollable Simulation tab. It uses one
shared 250 ms presentation timer, drains at most 128 events per tick, restores
focus after terminalization, and exposes the locked Automation IDs, names, help
text, and polite/assertive live regions. It makes no real-enforcement claim.

## Acceptance matrix evidence

Each locked row maps one-to-one to a deterministic test with the same name:

| Acceptance row | Evidence exercised |
|---|---|
| `sim-ui-disabled-default` | Production Disabled snapshot, zero owned authority, disabled commands. |
| `sim-ui-projection-exact-and-redacted` | Trusted join and exact projection; hidden selectors absent. |
| `sim-ui-allow-once` | Service-built nonce/audit/caller, one authority call, no rule/ticket/grant DTO. |
| `sim-ui-remember-scope-preview` | Preview equals canonical projected file/application/destination/protocol selector. |
| `sim-ui-remember-policy-transaction` | One epoch advance, old-context invalidation, selected transition retained. |
| `sim-ui-rule-id-collision` | Empty, active-entry, and retained-entry collisions; no retry/Core/epoch mutation and one diagnostic. |
| `sim-ui-remember-rule-committed-ticket-failed-open` | Remembered and failed-open outcomes coexist. |
| `sim-ui-remember-and-auto-match` | Exact ordinary-decision reuse at current epoch; selector mismatch prompts. |
| `sim-ui-revoke` | Exact RuleId/revision, stale conflict non-mutating, replay idempotent. |
| `sim-ui-file-mutation-invalidates` | Trusted version mutation removes rule and advances epoch once. |
| `sim-ui-policy-epoch-invalidates` | Rules, prompts, and authority state invalidate together. |
| `sim-ui-block-current-only` | Current flow terminates without remembered deny/firewall state. |
| `sim-ui-timeout-at-equality` | Equality is terminal fail-open and exact replay is idempotent. |
| `sim-ui-reconnect-required` | Distinct TCP, UDP, and QUIC notices have no challenge/buttons. |
| `sim-ui-critical-fail-open` | Stable reason/counter and fail-open presentation evidence. |
| `sim-ui-exact-duplicate` | Original receipt returns with `IsDuplicate`; authority is not called again. |
| `sim-ui-conflicting-replay` | Different terminal choice returns conflict without mutation. |
| `sim-ui-caller-forgery-rejected` | Non-admin rejected; DTO/handshake cannot supply authority fields. |
| `sim-ui-disconnect-reconnect-resync` | Atomic exact-sequence admission plus gap, overflow, disconnect, snapshot replace, and exact sequence resume. |
| `sim-ui-projection-capacity-recovery` | Independent non-zero owner snapshots become proven all-zero before stable alert/counter. |
| `sim-ui-rule-id-prevalidation-rollback` | Pending entry rolls back to baseline; malformed authority result disables reconciliation. |
| `sim-ui-rule-id-registry-capacity` | 256-entry refusal preserves prompt/state and emits one non-fail-open diagnostic. |
| `sim-ui-rule-id-exact-reuse-at-registry-cap` | Exact reuse takes neither RuleId nonce nor slot and does not advance epoch. |
| `sim-ui-rule-id-promotion-count-stable` | One pending entry promotes in place, including traffic fail-open. |
| `sim-ui-rule-id-tombstone-lifecycle` | Revoke, rule expiry, file invalidation, and policy invalidation retain tombstones through the locked window and release them at equality. |
| `sim-ui-expired-rule-terminalizes-prompt` | Rule expiry sweeps before prompt lookup, advances epoch once, terminalizes the prompt, and creates no nonce, pending RuleId, receipt, or post-terminal Core decision. |
| `sim-ui-bounds-and-framing` | Structural 4-prompt/subject and 128-prompt global bounds plus all locked maxima; the envelope serializes to exactly 908,824 UTF-8 bytes. |
| `sim-ui-service-capacity-bounds` | Live Service state reaches 8 rules/application, 64 rules/global, and every history cap; cap+1 preserves live state and takes no new authority. |
| `sim-ui-pipe-subscriber-capacity` | Real PipeServer, production clients, real MainWindow/view models/panel on STA: a snapshot/subscribe mutation barrier keeps commands disabled until resync; two windows use 6/8; the exact 8-instance limit releases and accepts a replacement connection; subscriber-cap rejection leaves requests alive; Allow/Remember/Block/Revoke run through Automation peers. |
| `sim-ui-small-window-dpi` | 640x480 DIP at 100/150/200% remains wrapped, scrollable, reachable. |
| `sim-ui-keyboard-screen-reader` | Real STA WPF tree, IDs, peers, tab/reverse-tab, live regions, terminal focus. |
| `sim-ui-privacy-scan` | Reflection, source, and serialized JSON reject prohibited data/types. |
| `sim-ui-zero-false-enforcement-claims` | Source/rendered copy says Simulation and makes no upload-blocked claim. |
| `sim-ui-cleanup-zero-owned-state` | Authority, Coordinator, pipes, subscribers, WPF lifecycle end at zero. |

The canonical maximum snapshot envelope is **908,824 UTF-8 bytes**, leaving
**139,752 bytes** below the unchanged 1,048,576-byte framing limit. This exceeds
the locked 131,072-byte reserve by 8,680 bytes.

## Local validation

The final pre-commit validation ran the locked commands on Windows with the
Release configuration. All **142/142** deterministic tests passed, including the
real local-Administrator PipeServer branch (`6/8` normal instances, exact 8/8
limit, then successful replacement accept). Restore and format verification
passed; Release build completed with zero warnings and zero errors; the
transitive vulnerability scan reported no vulnerable package; and
`git diff --check` passed. GitHub `workflow_dispatch` evidence is recorded in the
Draft PR checks and final implementation handoff.

## Review posture

This implementation remains Simulation-only and the PR remains Draft. It is not
a merge verdict. A different Sol High reviewer must inspect the actual diff,
local evidence, framing proof, ownership cleanup, and GitHub CI result before the
stack may advance.
