# Privacy

EgressGuard is local-first. Interactive data defaults to LocalAppData and Windows Service data defaults to `C:\ProgramData\EgressGuard`.

Stored data includes process name, PID/start time, parent PID, executable path/SHA-256/size/time, Authenticode status, publisher display metadata, endpoint metadata, state/timestamps, risk reasons, baselines, settings and owned-rule records.

EgressGuard does not collect packet payload, TLS content, documents, browser profiles, cookies, passwords, command lines, credentials, cloud telemetry or threat-intelligence queries. The public firewall acceptance probe uses TCP connect-only mode and sends no payload.

Publisher subject is not treated as proof of trust. Signature verification uses Windows trust APIs; cache-only trust evaluation avoids sensor/UI network revocation traffic. Offline or inaccessible verification becomes `VerificationUnavailable`, not `Unsigned`, and does not by itself trigger blocking.

Flow retention defaults to 30 days. Clear History and Reset Baseline are explicit confirmed UI actions. Uninstall removes only owned firewall rules and leaves the database to avoid unexpected data loss.
