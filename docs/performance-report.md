# Performance report

Date: 2026-08-09. Tool: one-second `Process.TotalProcessorTime` deltas normalized by logical processor count; WorkingSet64; Release build. Each row is a 12–15 second sample.

| State | Process | CPU average | CPU peak | RAM average/observed | Traffic |
|---|---|---:|---:|---:|---|
| Before hardening | UI | 8.46% | not recorded | 167.5 MB | snapshot polling baseline, 6 s |
| Before hardening | Service | 1.50% | not recorded | 69.1 MB | baseline, 6 s |
| Idle open | UI | 0.017% | 0.130% | 177.2 MB | no significant synthetic traffic |
| Idle open | Service | 0.929% | 1.172% | 75.0 MB | same period |
| Normal | UI | 0.043% | 0.260% | 177.8 MB | 15 public connect-only flows |
| Normal | Service | 1.033% | 2.734% | 75.2 MB | same period |
| Burst | UI | 0.054% | 0.260% | 182.0 MB | 500 connect-only attempts |
| Burst | Service | 1.009% | 1.302% | 75.9 MB | same period |
| Minimized | UI | 0.026% | 0.130% | 182.0 MB | idle |
| UI closed | Service | 1.293% | 1.823% | 77.8 MB | UI process absent |
| 30-minute churn soak | Service | 2.876% | 8.000% | 56.4 MB initial; 78.9 MB final; 56.2–82.1 MB | 595 traffic/IPC cycles and 119 service restarts |
| 30-minute churn soak | UI | 2.846% | 7.000% | 134.8 MB initial; 154.4 MB final; 134.6–189.1 MB | 199 opens, 198 scheduled closes plus final cleanup |

The UI is below the 1–2% idle and 3% normal targets in all measured states. RAM increased about 5 MB after the burst and did not rise continuously during these short samples. Service CPU stayed near the earlier baseline.

The measured improvement comes from removing repeated snapshot/rules/alerts requests and full collection rebuilds from the realtime path. The UI now processes a bounded sequenced stream in 250 ms dispatcher batches. Snapshot/database queries occur only on initial connect, reconnect/resync or manual refresh.

Limitations: the pre-soak rows use short sample windows, event/s was inferred from synthetic workload rather than an exported production counter, and this is not an ETW/PerfView trace. Use `tools\run-performance-test.ps1` and the soak script for repeatable measurements.

## Phase 3.5 soak

The 30-minute Release soak on 2026-08-09 completed 595 normal, burst and beacon traffic runs, 595 successful IPC status checks and zero failures. The harness verified an exclusive database open after shutdown and found zero EgressGuard processes and zero owned firewall rules after cleanup.

The soak CPU samples are one-second-style process CPU deltas normalized by logical processor count. They represent active traffic, UI churn and reconnect work, not idle measurements. Both service and UI were intentionally restarted, so the initial/final working sets belong to different process instances and cannot by themselves prove or disprove a same-process memory leak. No monotonic runaway was observed within the recorded bounds.
