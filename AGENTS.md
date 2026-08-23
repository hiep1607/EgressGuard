# Coding agent instructions

Read `docs/threat-model.md` and `docs/architecture.md` before modifying behavior.

- Read `AGENT_HANDOFF.md` at the start of every session and re-verify its claims against Git/GitHub state; do not trust stale entries blindly.
- Sessions with repository write access must update `AGENT_HANDOFF.md` before finishing; read-only sessions must not modify it and report results in conversation instead.

- Keep implementations minimal and within the phase explicitly requested.
- Do not implement ETW, a driver, kernel code, payload inspection, or unrelated security features without explicit scope.
- Never run real malware or access real user documents for testing.
- Never change firewall profiles, disable Windows security controls, or apply a blanket outbound block.
- Never commit secrets, runtime databases, logs, dumps, traces, certificates, keys, build output, or personal test data.
- Run restore/build/test/format appropriate to each change.
- Report Windows/admin scenarios that could not be verified; do not claim completion without evidence.
- Do not automatically commit or push unless the user explicitly requests it.
- Driver work must use a dedicated VM and separate safety process, never the primary workstation.
