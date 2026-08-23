# Coding agent instructions

Read `docs/threat-model.md` and `docs/architecture.md` before modifying behavior.

- At session start read `AGENT_HANDOFF.md`, then the coordination issue it links to; re-verify both against Git/GitHub before acting.
- Sessions with GitHub write access must update the coordination issue before finishing; read-only sessions report results in conversation only.
- Ordinary work is owned by Ox Alpha. Escalate to Sol only for genuine architecture or safety blockers, or when Ox cannot complete the work within a reasonable fix loop.
- Never edit per-branch `AGENT_HANDOFF.md` copies to record session logs; they are static guides pointing to the coordination issue.

- Keep implementations minimal and within the phase explicitly requested.
- Do not implement ETW, a driver, kernel code, payload inspection, or unrelated security features without explicit scope.
- Never run real malware or access real user documents for testing.
- Never change firewall profiles, disable Windows security controls, or apply a blanket outbound block.
- Never commit secrets, runtime databases, logs, dumps, traces, certificates, keys, build output, or personal test data.
- Run restore/build/test/format appropriate to each change.
- Report Windows/admin scenarios that could not be verified; do not claim completion without evidence.
- Do not automatically commit or push unless the user explicitly requests it.
- Driver work must use a dedicated VM and separate safety process, never the primary workstation.
