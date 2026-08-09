# Coding agent instructions

Read `docs/threat-model.md` and `docs/architecture.md` before modifying behavior.

- Keep implementations minimal and within the phase explicitly requested.
- Do not implement ETW, a driver, kernel code, payload inspection, or unrelated security features without explicit scope.
- Never run real malware or access real user documents for testing.
- Never change firewall profiles, disable Windows security controls, or apply a blanket outbound block.
- Never commit secrets, runtime databases, logs, dumps, traces, certificates, keys, build output, or personal test data.
- Run restore/build/test/format appropriate to each change.
- Report Windows/admin scenarios that could not be verified; do not claim completion without evidence.
- Do not automatically commit or push unless the user explicitly requests it.
- Driver work must use a dedicated VM and separate safety process, never the primary workstation.
