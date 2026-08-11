# Performance report

Status: `Failed` for the current post-pre-flow-redesign source. The current smoke is recorded below; the older table is historical Phase 3.5/previous-Phase-4 evidence only and must not be reused as acceptance evidence for this head. Tool: one-second `Process.TotalProcessorTime` deltas normalized by logical processor count; WorkingSet64; Release build.

## Current post-pre-flow smoke (2026-08-11)

The fresh 45-second phases ran on the same workstation (12 logical CPUs) after the pre-flow redesign. UI/IPC remained responsive and ETW sessions were zero after cleanup, but the normal service CPU budget failed.

| Phase | Service CPU avg/peak | UI CPU avg/peak | Service RAM avg/peak | UI RAM avg/peak | Result |
|---|---:|---:|---:|---:|---|
| Feature-disabled baseline | 3.938% / 8.854% | 1.641% / 8.333% | 65.9 / 74.2 MB | 166.9 / 171.2 MB | Baseline |
| Feature-enabled idle | 5.414% / 12.370% | 2.532% / 13.281% | 78.7 / 86.5 MB | 174.4 / 179.5 MB | Over normal budget |
| Normal traffic with pre-flow fixture | 3.166% / 4.818% | 0.055% / 0.521% | 83.1 / 89.2 MB | 172.9 / 174.2 MB | Over normal budget |
| Stress/churn (20 connect-only processes) | 6.152% / 14.453% | 1.143% / 8.073% | 79.2 / 91.8 MB | 159.3 / 164.8 MB | Stress-only, bounded |

The raw buffer (4,096 global/256 per PID), promoted handoff (4,096), and process-interest cache (4,096) stayed hard-bounded by construction. Dedicated dropped-count regression and IPC status tests verified coalescing plus the exact final flush; the real service fixture independently verified pre-flow redacted evidence. A separate per-phase dropped-count export was not captured. This evidence is `Failed` for the <3% normal service CPU acceptance and must not be presented as Phase 4 complete.

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
| 30-minute churn soak | Service | 3.312% | 9.000% | 55.5 MB initial; 79.1 MB final; 55.5–86.4 MB | 585 traffic/IPC cycles and 117 service restarts |
| 30-minute churn soak | UI | 2.449% | 6.000% | 135.3 MB initial; 157.9 MB final; 134.5–196.3 MB | 195 opens and 195 closes |

The UI is below the 1–2% idle and 3% normal targets in all measured states. RAM increased about 5 MB after the burst and did not rise continuously during these short samples. Service CPU stayed near the earlier baseline.

The measured improvement comes from removing repeated snapshot/rules/alerts requests and full collection rebuilds from the realtime path. The UI now processes a bounded sequenced stream in 250 ms dispatcher batches. Snapshot/database queries occur only on initial connect, reconnect/resync or manual refresh.

Limitations: the pre-soak rows use short sample windows, event/s was inferred from synthetic workload rather than an exported production counter, and this is not an ETW/PerfView trace. Use `tools\run-performance-test.ps1` and the soak script for repeatable measurements.

## Phase 3.5 soak

The fresh isolated 30-minute Release soak on 2026-08-09 completed 585 normal, burst and beacon traffic runs, 585 successful IPC status checks and zero failures. The harness verified an exclusive database open after shutdown. Both strict cleanup inspections succeeded and found zero owned soak processes and zero EgressGuard-owned firewall rules.

The soak CPU samples are one-second-style process CPU deltas normalized by logical processor count. They represent active traffic, UI churn and reconnect work, not idle measurements. Both service and UI were intentionally restarted, so the initial/final working sets belong to different process instances and cannot by themselves prove or disprove a same-process memory leak. No monotonic runaway was observed within the recorded bounds.
