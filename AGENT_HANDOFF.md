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

Git keeps the full history of removed sessions.

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

1. Reload its body and note the newest "Updated UTC" you find there.
2. If another agent changed it during your session and the change contradicts your plan, stop and coordinate instead of overwriting.
3. Append only your own session entry; never rewrite other agents' entries.
4. Never force-push branches to erase another agent's records.
