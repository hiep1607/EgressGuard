# Performance report

Status: `Verified` for the current dual-index raw-buffer source. The final smoke below is the only CPU/RAM acceptance evidence for this head; older tables remain historical. Tool: one-second `Process.TotalProcessorTime` deltas normalized by 12 logical processors; `WorkingSet64`; Release build.

## Final warm steady-state smoke (2026-08-11)

Each phase used the same final artifact, an isolated pipe/database, a 25-second warm-up that excluded startup inventory, then 45 seconds of sampling. The installed artifact service was paused and restored. The UI had to report `Service online` before and after sampling; it produced zero not-responding samples. The disabled baseline was below the 2% noisy-run threshold, so no baseline retry was permitted or needed.

| Phase | Service CPU avg/peak | Delta vs baseline | UI CPU avg/peak | Service RAM start/end/peak | UI RAM start/end/peak | Result |
|---|---:|---:|---:|---:|---:|---|
| Feature-disabled baseline | 0.833% / 1.432% | — | 0.104% / 0.521% | 78.0 / 76.6 / 80.1 MB | 156.8 / 157.1 / 160.4 MB | Valid baseline |
| Feature-enabled idle | 0.894% / 1.693% | +0.061 pp | 0.104% / 0.521% | 87.8 / 82.9 / 90.5 MB | 158.4 / 156.2 / 158.7 MB | Pass |
| Normal traffic with pre-flow fixture | 1.100% / 2.214% | +0.267 pp | 0.098% / 0.521% | 88.5 / 86.2 / 93.0 MB | 157.9 / 158.3 / 159.4 MB | Pass (`<3%`) |
| Stress/churn (20 connect-only processes) | 0.833% / 1.823% | +0.000 pp | 0.087% / 0.781% | 81.7 / 86.8 / 91.8 MB | 158.1 / 157.2 / 158.9 MB | Bounded |

Every phase ended with zero test ETW session and zero ownership marker without recovery. RAM did not grow continuously. The separate real service integration on the same source verified the pre-flow `.egfixture`, negative delta, exact identity, zero transmitted bytes, redacted persistence, final dropped count behavior, and self-cleanup.

## Confirmed bottleneck and microbenchmark

Temporary instrumentation confirmed that the old buffer called a full-list expiration scan for nearly every raw event and linearly searched the global list for per-PID eviction. With 100,000 synthetic raw events it took 1,395.128 ms (71,678 events/s), visited 442,177,536 cleanup nodes, and spent 1,497.470 ms inside cleanup including warm-up. A hot-PID scenario took 502.188 ms, with 75,046,944 eviction-node visits and 239.400 ms in the linear search. The observed global peak briefly reached 4,097 before eviction.

The replacement links each entry into a global list and a PID-specific list. Global and per-PID eviction/removal are O(1), promotion visits only the target PID, and out-of-order-safe expiration scans the bounded global list at most once per second or immediately before promotion. Under the same instrumented workload, elapsed time fell to 43.279 ms (2,310,595 events/s), cleanup visits to 8,192/0.182 ms, and the hot-PID scenario to 10.125 ms with one indexed node per eviction (19,744 evictions/0.972 ms). Final no-instrumentation repeats took 40.505 and 46.127 ms (2.17–2.47 million events/s); global/per-PID peaks were exactly 4,096/256.

Allocation increased from about 21.0 MB to 29.6 MB per 100,000 synthetic events because the dual index stores two linked-list nodes. Retained state remains hard-bounded, and the final service RAM/CPU run showed no continuous growth. Temporary counters and machine-specific harnesses were removed before commit.

An instrumentation-only four-phase run recorded raw peaks of 1,042 idle, 1,671 normal and 1,550 stress; per-PID peak 256; process-identity-cache peaks 34/36/55; correlation buffer peaks 242/633/797; and dedupe peaks 205/478/691. Final dropped totals were 237,336/239,174/237,099 with 86/84/73 coalesced status publications over roughly 85 seconds per enabled phase. A harness double-dispose error occurred only after all four phase results and per-phase zero-session/zero-marker checks had printed; the installed service was restored manually. Those values are structural diagnostics, not the CPU acceptance table.

The earlier 3.938% disabled/3.166% normal table is a noisy startup/background run and is invalid for acceptance because its disabled baseline exceeded 2%. A later clean-source run before the pipe-client fix is also not acceptance evidence because the UI was not connected to the isolated pipe. Neither run was selected or hidden; the final table fixes both conditions.

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
