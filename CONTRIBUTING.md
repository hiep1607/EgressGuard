# Contributing

`main` must always build. After the initial repository baseline, do not push feature work directly to `main`.

Use branches:

- `feature/<description>` for features
- `fix/<description>` for fixes
- `agent/<description>` for coding-agent work

Open a pull request for material changes. Before a PR, run tool restore, locked NuGet restore, Release build, the executable test runner, and format verification documented in README.

## Safety rules

- Never commit secrets, user data, runtime databases, logs, dumps, ETL traces, certificates, or private keys.
- Never use real malware. Tests must use synthetic data and the included Simulator/Test Server.
- Explain every new dependency and avoid unnecessary packages.
- Firewall tests require exact EgressGuard ownership matching and unconditional cleanup.
- Do not disable firewall profiles or set a blanket outbound block.
- State clearly when a Windows/admin scenario was not tested.
- Driver or kernel work requires a dedicated branch, a disposable Windows VM, signing planning, and a separate review process. Never install an experimental driver on the primary workstation.

Release work begins only after signing, installer QA, rollback, reboot and security acceptance. Use semantic versioning only when releases actually begin.
