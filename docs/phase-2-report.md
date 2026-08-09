# Phase 2 report

Implemented and tested: Worker Service lifetime, graceful cancellation, bounded persistence and event queues, versioned Named Pipe request/subscription paths, administrator impersonation for mutations, protection-mode persistence, owned firewall operations, semantic duplicate detection, SHA-256 pre-enforcement validation and rollback.

Verified on Windows: public IPv4 Simulator-only block, alternate-path isolation, duplicate prevention, Chrome unaffected evidence, external deletion, repeated reset, zero orphaned rule, initial SCM install/start, recovery configuration, UI-to-service connection, UI close independence, flow collection while UI was closed, and uninstall cleanup.

Not verified on the final rebuilt service: SCM stop/start/reconnect. Framework-dependent start failed because .NET 8 was not registered for LocalSystem. A later unsigned self-contained rebuild was blocked by Windows Application Control. The installer rolled back cleanly. No policy bypass was attempted.
