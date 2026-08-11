# Privacy

EgressGuard is local-first. Interactive data defaults to LocalAppData and Windows Service data defaults to `C:\ProgramData\EgressGuard`.

Stored data includes process name, PID/start time, parent PID, executable path/SHA-256/size/time, Authenticode status, publisher display metadata, endpoint metadata, state/timestamps, risk reasons, baselines, settings and owned-rule records.

EgressGuard does not collect packet payload, TLS content, documents, browser profiles, cookies, passwords, command lines, credentials, cloud telemetry or threat-intelligence queries. The public firewall acceptance probe uses TCP connect-only mode and sends no payload.

Optional Phase 4 file correlation is disabled by default. When explicitly enabled, a normalized raw file path can exist briefly in bounded process memory so the service can correlate Windows File I/O metadata with an exact `(PID, ProcessStartTime)` network flow. EgressGuard does not open or read the file to analyze its contents, and the raw path is never persisted or returned over IPC.

The database stores only selected correlation evidence: a locally salted protected path identifier, a redacted display identifier, extension, operation, activity timestamp, signed time delta, confidence and reason. Evidence remains local. Its default retention is 30 days, and Clear History deletes file correlations together with flow history. No correlation, path metadata or telemetry is sent to EgressGuard or another external service.

Publisher subject is not treated as proof of trust. Signature verification uses Windows trust APIs; cache-only trust evaluation avoids sensor/UI network revocation traffic. Offline or inaccessible verification becomes `VerificationUnavailable`, not `Unsigned`, and does not by itself trigger blocking.

Flow and file-correlation retention default to 30 days. Clear History and Reset Baseline are explicit confirmed UI actions. Uninstall removes only owned firewall rules and leaves the database to avoid unexpected data loss.
