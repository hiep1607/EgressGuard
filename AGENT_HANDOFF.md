# Agent handoff

This file is a static guide. It never records session logs or per-PR working state.

The single shared handoff log lives in one GitHub issue that every agent reads and updates:

- Coordination issue: https://github.com/hiep1607/EgressGuard/issues/19

Git history and the current GitHub state always outrank anything written in the issue or here.

## Handoff rules

- Read this file first, then open the coordination issue linked above.
- Re-verify every claim against Git/GitHub before acting; entries can be stale or wrong.
- Sessions with GitHub write access must update the coordination issue before finishing.
- Read-only sessions must not modify the issue or this file; report results in the conversation.
- Ordinary work is owned by Ox Alpha. Escalate to Sol only for genuine architecture/safety blockers, or when Ox cannot finish within a reasonable fix loop.
- Never add session logs to per-branch copies of this file; validators enforce this structure.

## Limits

The coordination issue body must stay within:

- 12,288 bytes UTF-8 and at most 180 lines.
- Only the 5 most recent completed sessions; delete the oldest when adding the sixth.
- No secrets, long logs, dumps, personal data or machine-local paths.

Removed sessions are not relied upon afterwards; the current Git/GitHub state remains the authoritative evidence.

## Report template

Add one block at the top of "Recent sessions" in the coordination issue:

### Session — <UTC time> — <agent> — <status>

- Goal:
- Result:
- Evidence:
- Remaining:
- Next:

Status is IN_PROGRESS, READY_FOR_REVIEW or BLOCKED.

## Concurrent changes

Before writing to the coordination issue:

1. At session start, read the issue once and record its GitHub `updated_at` timestamp as your baseline.
2. Immediately before saving, re-read the issue from GitHub and compare the fresh `updated_at` with your baseline: identical means it is safe to update; different means someone else wrote in between, so read their changes and merge them into your update instead of overwriting.
3. The `Updated UTC` line inside the body is for human readers only and is never compared with `updated_at`; still set a fresh `Updated UTC` (current UTC) every time you save.
4. Append only your own session entry; never rewrite other agents' entries.
5. Never force-push branches to erase another agent's records.

GitHub tooling offers no conditional-update primitive, so this baseline-and-recheck procedure mitigates overwrite risk but is not fully atomic.
