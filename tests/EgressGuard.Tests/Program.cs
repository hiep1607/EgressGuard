using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text.Json;
using System.Text.RegularExpressions;
using EgressGuard.Core;
using EgressGuard.Persistence;
using EgressGuard.Protocol;
using EgressGuard.Service;
using EgressGuard.UI;
using EgressGuard.Windows;
using Microsoft.Data.Sqlite;
using Microsoft.Diagnostics.Tracing.Session;
using Microsoft.Extensions.Logging;

namespace EgressGuard.Tests;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        if (args.Length == 1 && args[0] == "--firewall-cancellation-integration")
        {
            await TestRealFirewallCancellationIntegrationAsync().ConfigureAwait(false);
            Console.WriteLine("PASS  Real firewall cancellation reconciliation");
            return 0;
        }

        if (args.Length == 1 && args[0] == "--etw-file-integration")
        {
            await TestRealEtwFileIntegrationAsync().ConfigureAwait(false);
            Console.WriteLine("PASS  Real ETW file activity sensor");
            return 0;
        }

        if (args.Length == 1 && args[0] == "--etw-orphan-reclaim-integration")
        {
            await TestRealEtwOrphanReclaimIntegrationAsync().ConfigureAwait(false);
            Console.WriteLine("PASS  Real ETW orphan session reclaim");
            return 0;
        }

        if (args.Length == 1 && args[0] == "--etw-lifecycle-integration")
        {
            await TestRealEtwLifecycleIntegrationAsync(10).ConfigureAwait(false);
            Console.WriteLine("PASS  Real ETW ten-cycle lifecycle cleanup");
            return 0;
        }

        if (args.Length == 1 && args[0] == "--etw-lifecycle-smoke")
        {
            await TestRealEtwLifecycleIntegrationAsync(3).ConfigureAwait(false);
            Console.WriteLine("PASS  Real ETW three-cycle lifecycle smoke");
            return 0;
        }

        if (args.Length == 1 && args[0] == "--file-correlation-service-integration")
        {
            await TestRealFileCorrelationServiceIntegrationAsync().ConfigureAwait(false);
            Console.WriteLine("PASS  Real ETW file-to-network correlation through service IPC");
            return 0;
        }

        if (args.Length == 1 && args[0] == "--raw-buffer-benchmark")
        {
            await RunRawBufferBenchmarkAsync().ConfigureAwait(false);
            return 0;
        }

        if (args.Length == 2 && args[0] == "--etw-orphan-child")
        {
            return await RunEtwOrphanChildAsync(args[1]).ConfigureAwait(false);
        }

        var tests = new (string Name, Func<Task> Run)[]
        {
            ("Process identity includes start time", TestProcessIdentityAsync),
            ("File correlation matches exact identity inside configured window", TestFileCorrelationWindowAsync),
            ("File correlation rejects PID reuse and out-of-window events", TestFileCorrelationIdentityAsync),
            ("File correlation handles out-of-order, duplicate and multiple file events", TestFileCorrelationOrderingAsync),
            ("File correlation supports multiple flows and caps evidence", TestFileCorrelationCapacityAsync),
            ("File correlation buffer overflow and retention are bounded", TestFileCorrelationRetentionAsync),
            ("File correlation dedupe state has a hard bound", TestFileCorrelationDedupeBoundAsync),
            ("File correlation eviction preserves newer dedupe entries", TestFileCorrelationDedupeEvictionAsync),
            ("File correlation excludes EgressGuard-owned storage", TestFileCorrelationExclusionAsync),
            ("System path filtering uses normalized directory boundaries", TestSystemPathFilteringAsync),
            ("Pre-flow admission retains reads and gates unrelated mutation noise", TestPreFlowAdmissionAsync),
            ("ETW callback coalescing is bounded and expires deterministically", TestEtwCallbackAdmissionAsync),
            ("Disabled and degraded file sensors remain bounded", TestFileSensorStatesAsync),
            ("File sensor publishes coalesced final dropped count", TestFileSensorDroppedCountNotificationsAsync),
            ("File sensor rejects events older than resolved process identity", TestFileSensorPidReuseProjectionAsync),
            ("Process identity cache is bounded, expires, and rejects PID reuse", TestProcessIdentityCacheAsync),
            ("Pre-flow raw events promote through the production interest path", TestPreFlowRawPromotionAsync),
            ("Pre-flow repeated reads retain only the newest useful signal", TestPreFlowRawDedupeAsync),
            ("Pre-flow raw buffer retention and per-process bounds are enforced", TestPreFlowRawBufferBoundsAsync),
            ("PID reuse promotes only the current process generation", TestPidReuseRawPromotionAsync),
            ("Pending promotion is indexed by exact process identity", TestPendingPromotionIndexAsync),
            ("Promoted correlation cleanup work is bounded", TestPromotedCorrelationCleanupAsync),
            ("ETW ownership reclaims only an exact verified orphan", TestEtwOwnershipAsync),
            ("AccessDenied file sensor does not crash network service", TestFileSensorDegradedServiceAsync),
            ("Native port conversion", TestPortConversionAsync),
            ("Endpoint formatting", TestEndpointFormattingAsync),
            ("Executable metadata hashes and caches", TestExecutableMetadataAsync),
            ("Authenticode maps trust results and validates Windows binary", TestAuthenticodeAsync),
            ("Firewall path validation is simulator-only", TestFirewallPathValidationAsync),
            ("PowerShell pre-cancellation does not start a process", TestPowerShellPreCancellationAsync),
            ("PowerShell cancellation terminates only its owned process tree", TestPowerShellCancellationCleanupAsync),
            ("PowerShell timeout terminates its owned process tree", TestPowerShellTimeoutCleanupAsync),
            ("Indeterminate firewall creation reconciles the exact rule", TestFirewallCreateReconciliationAsync),
            ("Complete firewall semantics recognize an exact rule", TestCompleteFirewallSemanticsMatchAsync),
            ("Complete firewall semantics reject field mismatches", TestCompleteFirewallSemanticsMismatchAsync),
            ("Concurrent equivalent firewall requests serialize creation", TestConcurrentFirewallCreationAsync),
            ("Controlled TCP connection maps to current process", TestControlledTcpMappingAsync),
            ("Controlled IPv6 TCP maps to current process", TestControlledIPv6MappingAsync),
            ("Controlled UDP endpoint maps to current process", TestControlledUdpMappingAsync),
            ("Windows flow sensor preserves process identity", TestWindowsFlowSensorAsync),
            ("Risk score boundaries and determinism", TestRiskEngineAsync),
            ("Policy conflict priority", TestPolicyPriorityAsync),
            ("Baseline minimum samples and reset", TestBaselineAsync),
            ("SQLite migration and flow persistence", TestPersistenceAsync),
            ("SQLite persists every bounded correlation batch", TestCorrelationPersistenceBatchAsync),
            ("SQLite lock fails without unsafe fallback", TestDatabaseLockAsync),
            ("Service graceful cancellation completes without failure logs", TestGracefulCancellationAsync),
            ("Automatic firewall rule rolls back on persistence failure", TestAutomaticRuleRollbackAsync),
            ("Automatic firewall rule rolls back on cancellation", TestAutomaticRuleCancellationRollbackAsync),
            ("Automatic firewall rollback logs original and rollback failures", TestAutomaticRuleRollbackFailureLoggingAsync),
            ("Protocol frame roundtrip", TestProtocolRoundTripAsync),
            ("Phase 5B-05 Protocol request and projection contracts enforce bounds", TestSimulatedDecisionProtocolRequestAndProjectionValidationAsync),
            ("Phase 5B-05 Protocol event and result contracts enforce one-of outcomes", TestSimulatedDecisionProtocolEventAndResultValidationAsync),
            ("Phase 5B-05 Protocol contracts defensively copy and round-trip JSON", TestSimulatedDecisionProtocolJsonRoundTripAsync),
            ("Phase 5B-05 Protocol maximum snapshot stays below the frame limit", TestSimulatedDecisionProtocolMaximumSnapshotAsync),
            ("Phase 5B-01 contracts serialize and preserve exact identity", TestOutboundGateContractRoundTripAsync),
            ("Phase 5B-01 contracts enforce monotonic deadlines and generations", TestOutboundGateMonotonicValidationAsync),
            ("Phase 5B-01 contracts enforce decision and disposition invariants", TestOutboundGateDecisionValidationAsync),
            ("Phase 5B-01 contracts bind exact outbound network scope", TestOutboundGateNetworkScopeAsync),
            ("Phase 5B-01 contracts reject invalid versions bounds and status counters", TestOutboundGateContractValidationAsync),
            ("Phase 5B-01 contracts preserve compatibility and omit sensitive fields", TestOutboundGateContractCompatibilityAsync),
            ("Phase 5B-02 trusted endpoint generations bind the happy path", TestOutboundGateTrustedGenerationsAsync),
            ("Phase 5B-02 completion cannot self-verify minifilter generation", TestOutboundGateCompletionGenerationAsync),
            ("Phase 5B-02 terminal fail-open and block states cannot revive", TestOutboundGateTerminalInvariantAsync),
            ("Phase 5B-02 restart applies the new boot and revokes tickets and grants", TestOutboundGateRestartInvalidationAsync),
            ("Phase 5B-02 policy changes and grant expiry revoke old authority", TestOutboundGatePolicyAndGrantExpiryAsync),
            ("Phase 5B-02 arm and read phases share the original bounded deadline", TestOutboundGateReadDeadlineAsync),
            ("Phase 5B-02 every active phase expires on deadline or clock change", TestOutboundGateAllPhaseExpiryAsync),
            ("Phase 5B-02 invalid and overflow intent replay is idempotent", TestOutboundGateIntentReplayAsync),
            ("Phase 5B-02 active terminal challenge and alert storage is bounded", TestOutboundGateStorageBoundsAsync),
            ("Phase 5B-02 challenge limits preserve live state", TestOutboundGateChallengeBoundsAsync),
            ("Phase 5B-02 challenge coverage must equal trusted armed coverage", TestOutboundGateChallengeCoverageAsync),
            ("Phase 5B-02 pending-read caps include acknowledged dispositions and completions", TestOutboundGatePendingAfterAckBoundsAsync),
            ("Phase 5B-02 terminal disposition and completion duplicates remain idempotent", TestOutboundGateTerminalDuplicateAsync),
            ("Phase 5B-02 audit UTC is injected and cannot affect monotonic authorization", TestOutboundGateAuditClockAsync),
            ("Phase 5B-03 authenticator creates canonical one-time proof and separate grant", TestOneTimeTicketSuccessAsync),
            ("Phase 5B-03 exact binding rejects altered and replayed tickets", TestOneTimeTicketBindingAsync),
            ("Phase 5B-03 monotonic expiry ignores UTC jumps", TestOneTimeTicketExpiryAsync),
            ("Phase 5B-03 concurrent redemption consumes exactly once", TestOneTimeTicketConcurrentRedemptionAsync),
            ("Phase 5B-03 outstanding and tombstone reservations are bounded", TestOneTimeTicketCapacityAsync),
            ("Phase 5B-03 capacity failure fails open with a critical alert", TestOneTimeTicketCapacityFailOpenAsync),
            ("Phase 5B-03 restart and policy changes invalidate volatile authority", TestOneTimeTicketInvalidationAsync),
            ("Phase 5B-03 ticket identifiers cannot collide across authority reservations", TestOneTimeTicketIdentifierCollisionAsync),
            ("Phase 5B-03 authenticated ticket fields and grants remain distinct", TestOneTimeTicketAuthenticatedFieldsAsync),
            ("Phase 5B-03 active grant reservations are bounded and expire monotonically", TestOneTimeTicketActiveGrantCapacityAsync),
            ("Phase 5B-03 policy and restart transitions serialize with redemption", TestOneTimeTicketAuthorityRaceAsync),
            ("Phase 5B-04 challenge admission failure is targeted and bounded", TestChallengeAdmissionFailureAsync),
            ("Phase 5B-05 persistent result contracts are bounded and defensive", TestPersistentDecisionResultContractAsync),
            ("Phase 5B-05 persistent decision prevalidation is non-mutating", TestPersistentDecisionPrevalidationAsync),
            ("Phase 5B-05 persistent deadline failure is terminal and idempotent", TestPersistentDecisionDeadlineFailureAsync),
            ("Phase 5B-05 remembered decisions reuse the current policy epoch", TestRememberedDecisionCurrentEpochAsync),
            ("Phase 5B-05 persistent decision atomically advances policy", TestPersistentDecisionAtomicSuccessAsync),
            ("Phase 5B-05 effective epoch preserves selected authority only", TestPersistentDecisionEffectiveEpochAsync),
            ("Phase 5B-05 ticket capacity fails open after epoch acceptance", TestPersistentDecisionTicketCapacityAsync),
            ("Phase 5B-05 persistent decision duplicate and concurrency are idempotent", TestPersistentDecisionConcurrencyAsync),
            ("Phase 5B-05 persistent invalidation statuses reach the exact bound", TestPersistentDecisionInvalidationBoundAsync),
            ("Phase 5B-04 deterministic driver simulator acceptance suite", TestOutboundGateSimulatorAcceptanceAsync),
            ("Default UI clients honor configured pipe name", TestConfiguredPipeNameAsync),
            ("File correlation IPC stays compatible and bounded", TestFileCorrelationProtocolAsync),
            ("UI correlation refresh coalesces updates and cancels stale selection", TestUiCorrelationRefreshAsync),
            ("Protocol rejects oversized message", TestOversizedMessageAsync),
            ("Protocol handles disconnect", TestProtocolDisconnectAsync),
            ("Event buffer preserves order and detects gaps and overflow", TestEventBufferAsync),
            ("Slow event subscriber cannot block publisher", TestSlowSubscriberAsync),
            ("Flow state emits add update and remove transitions", TestFlowStateTransitionsAsync),
            ("Service pipe ACL permits interactive clients without broad access", TestServicePipeAclAsync),
            ("Service pipe reconnect and event subscription", TestServicePipeReconnectAsync),
            ("Process churn does not crash collector", TestProcessChurnAsync)
        };

        if (args.Length == 2 && args[0] == "--test")
        {
            tests = tests.Where(test => string.Equals(test.Name, args[1], StringComparison.Ordinal)).ToArray();
            if (tests.Length == 0)
            {
                Console.Error.WriteLine($"Unknown test: {args[1]}");
                return 2;
            }
        }
        else if (args.Length != 0)
        {
            Console.Error.WriteLine("Usage: EgressGuard.Tests [--test <exact-test-name>]");
            return 2;
        }

        var failures = 0;
        foreach (var test in tests)
        {
            try
            {
                await test.Run().ConfigureAwait(false);
                Console.WriteLine($"PASS  {test.Name}");
            }
            catch (Exception exception)
            {
                failures++;
                Console.Error.WriteLine($"FAIL  {test.Name}: {exception.Message}");
            }
        }

        Console.WriteLine($"{tests.Length - failures}/{tests.Length} tests passed.");
        return failures == 0 ? 0 : 1;
    }

    private static Task TestProcessIdentityAsync()
    {
        var startA = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var startB = startA.AddSeconds(1);
        AssertNotEqual(new ProcessIdentity(42, startA), new ProcessIdentity(42, startB));
        AssertEqual(new ProcessIdentity(42, startA), new ProcessIdentity(42, startA));
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationWindowAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine();
        AssertTrue(engine.Add(FileEvent(flow, 1, -2, FileActivityOperation.Read, "C:\\Synthetic\\report.pdf")), "Expected valid file event to be staged.");
        var result = engine.Correlate(flow, flow.FirstSeen.AddSeconds(1));
        AssertEqual(1, result.Count);
        AssertEqual(CorrelationConfidence.High, result[0].Confidence);
        AssertTrue(result[0].Reason.Contains("does not", StringComparison.OrdinalIgnoreCase) is false, "Reason should describe deterministic timing only.");
        AssertTrue(result[0].DisplayPath.StartsWith("file-", StringComparison.Ordinal) && result[0].DisplayPath.EndsWith(".pdf", StringComparison.Ordinal), "Display identifier was not redacted.");
        AssertTrue(!result[0].ProtectedFileIdentifier.Contains("Synthetic", StringComparison.OrdinalIgnoreCase), "Protected identifier leaked the path.");
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationIdentityAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine();
        var reused = FileEvent(flow, 1, -1, FileActivityOperation.Read, "C:\\Synthetic\\reuse.txt") with
        {
            ProcessIdentity = new ProcessIdentity(flow.ProcessIdentity!.Value.ProcessId, flow.ProcessIdentity.Value.StartTime.AddMinutes(1))
        };
        _ = engine.Add(reused);
        _ = engine.Add(FileEvent(flow, 2, -31, FileActivityOperation.Read, "C:\\Synthetic\\early.txt"));
        _ = engine.Add(FileEvent(flow, 3, 6, FileActivityOperation.Read, "C:\\Synthetic\\late.txt"));
        AssertEqual(0, engine.Correlate(flow, flow.FirstSeen).Count);
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationOrderingAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine();
        AssertTrue(engine.Add(FileEvent(flow, 3, 2, FileActivityOperation.Write, "C:\\Synthetic\\b.txt")), "First event was rejected.");
        AssertTrue(engine.Add(FileEvent(flow, 1, -3, FileActivityOperation.Read, "C:\\Synthetic\\a.txt")), "Out-of-order event was rejected.");
        AssertTrue(!engine.Add(FileEvent(flow, 2, -2.8, FileActivityOperation.Read, "C:\\Synthetic\\a.txt")), "Duplicate event was not deduplicated.");
        var result = engine.Correlate(flow, flow.FirstSeen.AddSeconds(3));
        AssertEqual(2, result.Count);
        AssertTrue(result[0].TimeDeltaSeconds == 2, "Closest out-of-order event was not first.");
        AssertTrue(result[1].TimeDeltaSeconds == -3, "Second out-of-order event was incorrect.");
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationCapacityAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine(maxEvidence: 2);
        for (var index = 0; index < 4; index++)
        {
            _ = engine.Add(FileEvent(flow, index, -index, FileActivityOperation.Read, $"C:\\Synthetic\\{index}.txt"));
        }

        AssertEqual(2, engine.Correlate(flow, flow.FirstSeen).Count);
        var secondFlow = flow with { Id = "second-flow", FirstSeen = flow.FirstSeen.AddSeconds(1) };
        AssertEqual(2, engine.Correlate(secondFlow, secondFlow.FirstSeen).Count);
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationRetentionAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine(maxBuffered: 2);
        _ = engine.Add(FileEvent(flow, 1, -2, FileActivityOperation.Read, "C:\\Synthetic\\1.txt"));
        _ = engine.Add(FileEvent(flow, 2, -1, FileActivityOperation.Read, "C:\\Synthetic\\2.txt"));
        _ = engine.Add(FileEvent(flow, 3, 0, FileActivityOperation.Read, "C:\\Synthetic\\3.txt"));
        AssertEqual(1L, engine.DroppedEvents);
        AssertEqual(2, engine.Correlate(flow, flow.FirstSeen).Count);
        AssertEqual(2, engine.Cleanup(flow.FirstSeen.AddMinutes(3)));
        AssertEqual(0, engine.Correlate(flow, flow.FirstSeen.AddMinutes(3)).Count);
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationDedupeBoundAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine(maxBuffered: 8);
        for (var index = 0; index < 20_000; index++)
        {
            _ = engine.Add(FileEvent(flow, index, index / 1000d, FileActivityOperation.Read, $"C:\\Synthetic\\unique-{index}.txt"));
        }

        AssertEqual(8, engine.BufferedEventCount);
        AssertTrue(engine.DedupeEntryCount <= 8, "Dedupe state exceeded the event buffer hard bound.");
        _ = engine.Cleanup(flow.FirstSeen.AddMinutes(3));
        AssertEqual(0, engine.BufferedEventCount);
        AssertEqual(0, engine.DedupeEntryCount);
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationDedupeEvictionAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine(maxBuffered: 2);
        var first = FileEvent(flow, 1, 0, FileActivityOperation.Read, "C:\\Synthetic\\same.txt");
        var newer = FileEvent(flow, 2, 2, FileActivityOperation.Read, "C:\\Synthetic\\same.txt");
        AssertTrue(engine.Add(first), "Initial event was rejected.");
        AssertTrue(engine.Add(newer), "Same-key event outside dedupe window was rejected.");
        AssertTrue(engine.Add(FileEvent(flow, 3, 3, FileActivityOperation.Read, "C:\\Synthetic\\other.txt")), "Eviction fixture was rejected.");
        AssertTrue(!engine.Add(FileEvent(flow, 4, 2.1, FileActivityOperation.Read, "C:\\Synthetic\\same.txt")), "Evicting an old event removed its newer dedupe entry.");
        AssertTrue(engine.Add(FileEvent(flow, 5, 4, FileActivityOperation.Read, "C:\\Synthetic\\same.txt")), "Evicted key was not accepted after the dedupe window.");
        AssertTrue(engine.DedupeEntryCount <= 2, "Dedupe state exceeded capacity after same-key eviction.");
        return Task.CompletedTask;
    }

    private static Task TestFileCorrelationExclusionAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine(excludedRoots: ["C:\\ProgramData\\EgressGuard"]);
        AssertTrue(!engine.Add(FileEvent(flow, 1, -1, FileActivityOperation.Write, "C:\\ProgramData\\EgressGuard\\egressguard.db-wal")), "Owned database event was accepted.");
        AssertEqual(0, engine.Correlate(flow, flow.FirstSeen).Count);
        return Task.CompletedTask;
    }

    private static async Task TestSystemPathFilteringAsync()
    {
        string[] systemRoots = ["C:\\Windows", "C:\\Program Files", "C:\\Program Files (x86)"];
        AssertTrue(EtwFileActivitySensor.IsLowValueSystemPath("C:\\Windows\\System32\\kernel32.dll", systemRoots), "A real Windows-root file was not filtered.");
        AssertTrue(EtwFileActivitySensor.IsLowValueSystemPath("c:\\program files\\Vendor\\tool.dll", systemRoots), "A real Program Files file was not filtered case-insensitively.");
        AssertTrue(EtwFileActivitySensor.IsLowValueSystemPath("C:\\Program Files (x86)\\Vendor\\tool.dll", systemRoots), "A real Program Files (x86) file was not filtered.");
        AssertTrue(!EtwFileActivitySensor.IsLowValueSystemPath("C:\\Users\\Test\\Windows\\secret.txt", systemRoots), "A user directory named Windows was filtered.");
        AssertTrue(!EtwFileActivitySensor.IsLowValueSystemPath("C:\\Users\\Test\\Program Files\\secret.txt", systemRoots), "A user directory named Program Files was filtered.");
        AssertTrue(!EtwFileActivitySensor.IsLowValueSystemPath("C:\\WindowsBackup\\secret.txt", systemRoots), "A near-match Windows root was filtered.");
        AssertTrue(!EtwFileActivitySensor.IsLowValueSystemPath("C:\\Users\\Test\\AppData\\Local\\Temp\\Windows\\secret.txt", systemRoots), "A Temp/AppData path was filtered by a component name.");

        await using var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(new ProcessIdentity(1, DateTimeOffset.UtcNow.AddMinutes(-1)), "filter"),
            excludedRoots: ["C:\\ProgramData\\EgressGuard"],
            capacity: 8,
            lowValueSystemRoots: systemRoots);
        var timestamp = DateTime.UtcNow;
        sensor.StageForTest(1, "filter", "C:\\Windows\\System32\\kernel32.dll", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\Program Files\\Vendor\\tool.dll", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\Program Files (x86)\\Vendor\\tool.dll", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\Users\\Test\\Windows\\secret.txt", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\Users\\Test\\Program Files\\secret.txt", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\WindowsBackup\\secret.txt", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\Users\\Test\\AppData\\Local\\Temp\\Windows\\secret.txt", FileActivityOperation.Read, timestamp);
        sensor.StageForTest(1, "filter", "C:\\ProgramData\\EgressGuard\\egressguard.db-wal", FileActivityOperation.Read, timestamp);
        AssertEqual(4, sensor.StagedEventCount);
        await sensor.StopAsync(CancellationToken.None).ConfigureAwait(false);
    }

    private static async Task TestFileSensorStatesAsync()
    {
        await using var disabled = new DisabledFileActivitySensor();
        await disabled.StartAsync(CancellationToken.None).ConfigureAwait(false);
        AssertEqual(FileSensorState.Disabled, disabled.Status.State);

        await using var sensor = new EtwFileActivitySensor(capacity: 1);
        var overflowNotifications = 0;
        sensor.StatusChanged += (_, status) =>
        {
            if (status.State == FileSensorState.OverflowDegraded) Interlocked.Increment(ref overflowNotifications);
        };
        var path = Path.Combine(Path.GetTempPath(), "EgressGuard-Synthetic", "overflow.txt");
        var timer = Stopwatch.StartNew();
        for (var index = 0; index < 20_000; index++)
        {
            sensor.StageForTest(Environment.ProcessId, "test", path + index, FileActivityOperation.Read, DateTime.UtcNow);
        }
        timer.Stop();
        await Task.Delay(100).ConfigureAwait(false);
        AssertEqual(FileSensorState.OverflowDegraded, sensor.Status.State);
        AssertEqual(19_999L, sensor.Status.DroppedEvents);
        AssertTrue(timer.Elapsed < TimeSpan.FromSeconds(2), "Synthetic ETW callback burst was unexpectedly slow.");
        AssertTrue(overflowNotifications <= 1, "Overflow emitted one status notification per dropped event.");
        using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await sensor.StopAsync(stopTimeout.Token).ConfigureAwait(false);
    }

    private static Task TestFileSensorPidReuseProjectionAsync()
    {
        var timestamp = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var resolver = new FixedProcessIdentityResolver(new ProcessIdentity(77, timestamp.AddSeconds(1)), "new-process");
        var sensor = new EtwFileActivitySensor(resolver, capacity: 4);
        var path = "C:\\Synthetic\\pid-reuse.txt";
        AssertEqual(null, sensor.ProjectForTest(77, "old-process", path, FileActivityOperation.Read, timestamp));
        var valid = sensor.ProjectForTest(77, "new-process", path, FileActivityOperation.Read, timestamp.AddSeconds(2));
        AssertTrue(valid is not null, "Event after the resolved process start was rejected.");
        var flow = SampleFlow() with { ProcessIdentity = resolver.Value.Identity, FirstSeen = timestamp.AddSeconds(3) };
        var engine = NewCorrelationEngine();
        _ = engine.Add(valid!);
        AssertEqual(1, engine.Correlate(flow, flow.FirstSeen).Count);
        return Task.CompletedTask;
    }

    private static async Task TestFileSensorDroppedCountNotificationsAsync()
    {
        var start = DateTimeOffset.UtcNow.AddMinutes(-1);
        var resolver = new FixedProcessIdentityResolver(new ProcessIdentity(Environment.ProcessId, start), "test");
        var identities = new ProcessIdentityCache(4, TimeSpan.FromMinutes(1));
        await using var sensor = new EtwFileActivitySensor(
            resolver,
            capacity: 1,
            processIdentities: identities,
            statusPublishInterval: TimeSpan.FromMilliseconds(25));
        var notifications = new List<FileSensorStatus>();
        sensor.StatusChanged += (_, status) =>
        {
            lock (notifications) notifications.Add(status);
        };
        var path = Path.Combine(Path.GetTempPath(), "EgressGuard-Synthetic", "coalesced.txt");

        for (var index = 0; index < 1_000; index++)
        {
            sensor.StageForTest(Environment.ProcessId, "test", path + index, FileActivityOperation.Read, DateTime.UtcNow);
        }

        await Task.Delay(75).ConfigureAwait(false);
        for (var index = 0; index < 1_000; index++)
        {
            sensor.StageForTest(Environment.ProcessId, "test", path + (index + 1_000), FileActivityOperation.Read, DateTime.UtcNow);
        }

        using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        await sensor.StopAsync(stopTimeout.Token).ConfigureAwait(false);
        FileSensorStatus[] published;
        lock (notifications) published = [.. notifications];
        AssertEqual(1_999L, sensor.Status.DroppedEvents);
        AssertTrue(published.Any(item => item.State == FileSensorState.OverflowDegraded), "OverflowDegraded was never published.");
        AssertEqual(1_999L, published[^1].DroppedEvents);
        AssertEqual(FileSensorState.Stopped, published[^1].State);
        AssertTrue(published.Select(item => item.DroppedEvents).Distinct().Count() >= 2, "Dropped count did not advance after initial degradation.");
        AssertTrue(published.Length <= 8, "Dropped notifications were not coalesced.");
    }

    private static async Task RunRawBufferBenchmarkAsync()
    {
        const int eventCount = 100_000;
        var now = DateTimeOffset.UtcNow;
        await using var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(new ProcessIdentity(1, now.AddMinutes(-1)), "benchmark"),
            capacity: 4096,
            recentRawCapacity: 4096,
            recentRawPerProcessCapacity: 256,
            recentRawRetention: TimeSpan.FromMinutes(5));

        _ = sensor.PromoteRawForTest(
            Enumerable.Range(0, 10_000).Select(index => new RawFileActivity(
                index, now.AddMilliseconds(-(index % 250)), 10_000 + (index % 32), "benchmark",
                FileActivityOperation.Read, $"C:\\Synthetic\\warmup-{index}.egfixture")),
            []);

        GC.Collect();
        GC.WaitForPendingFinalizers();
        GC.Collect();
        var allocatedBefore = GC.GetTotalAllocatedBytes(precise: true);
        var started = Stopwatch.StartNew();
        _ = sensor.PromoteRawForTest(
            Enumerable.Range(0, eventCount).Select(index => new RawFileActivity(
                10_000 + index, now.AddMilliseconds(-(index % 250)), 20_000 + (index % 32), "benchmark",
                FileActivityOperation.Read, $"C:\\Synthetic\\measured-{index}.egfixture")),
            []);
        started.Stop();
        var allocated = GC.GetTotalAllocatedBytes(precise: true) - allocatedBefore;

        Console.WriteLine($"Events={eventCount}");
        Console.WriteLine($"ElapsedMs={started.Elapsed.TotalMilliseconds:F3}");
        Console.WriteLine($"EventsPerSecond={eventCount / started.Elapsed.TotalSeconds:F0}");
        Console.WriteLine($"AllocatedBytes={allocated}");
        Console.WriteLine($"GlobalPeak={sensor.RecentRawPeak}");
        Console.WriteLine($"PerPidPeak={sensor.RecentRawPerProcessPeak}");
        Console.WriteLine($"Dropped={sensor.Status.DroppedEvents}");

        await using var perPidSensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(new ProcessIdentity(1, now.AddMinutes(-1)), "benchmark"),
            capacity: 4096,
            recentRawCapacity: 4096,
            recentRawPerProcessCapacity: 256,
            recentRawRetention: TimeSpan.FromMinutes(5));
        _ = perPidSensor.PromoteRawForTest(
            Enumerable.Range(0, 3_800).Select(index => new RawFileActivity(
                index, now, 30_000 + index, "background", FileActivityOperation.Read,
                $"C:\\Synthetic\\background-{index}.egfixture")),
            []);
        var perPidStarted = Stopwatch.StartNew();
        _ = perPidSensor.PromoteRawForTest(
            Enumerable.Range(0, 20_000).Select(index => new RawFileActivity(
                3_800 + index, now, 77, "hot-pid", FileActivityOperation.Read,
                $"C:\\Synthetic\\hot-{index}.egfixture")),
            []);
        perPidStarted.Stop();
        Console.WriteLine($"PerPidScenarioElapsedMs={perPidStarted.Elapsed.TotalMilliseconds:F3}");
        Console.WriteLine($"PerPidScenarioGlobalPeak={perPidSensor.RecentRawPeak}");
        Console.WriteLine($"PerPidScenarioPerPidPeak={perPidSensor.RecentRawPerProcessPeak}");
        Console.WriteLine($"PerPidScenarioDropped={perPidSensor.Status.DroppedEvents}");
    }

    private static Task TestProcessIdentityCacheAsync()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var resolver = new MutableProcessIdentityResolver();
        var cache = new ProcessIdentityCache(8, TimeSpan.FromMilliseconds(100));
        for (var processId = 1; processId <= 10_000; processId++)
        {
            cache.ObserveProcessStart(
                new ResolvedProcessIdentity(new ProcessIdentity(processId, now.AddSeconds(-1)), "process-" + processId),
                now);
        }

        AssertEqual(8, cache.Count);

        var oldIdentity = new ResolvedProcessIdentity(new ProcessIdentity(77, now), "same-name");
        cache.ObserveProcessStart(oldIdentity, now);
        resolver.Values[77] = oldIdentity;
        AssertEqual(oldIdentity, cache.Resolve(77, "same-name", now.AddMilliseconds(10), now.AddMilliseconds(10), resolver));
        AssertEqual(0, resolver.ResolveCalls);

        var newIdentity = new ResolvedProcessIdentity(new ProcessIdentity(77, now.AddSeconds(1)), "same-name");
        resolver.Values[77] = newIdentity;
        cache.ObserveProcessStart(newIdentity, now.AddSeconds(1));
        cache.ObserveProcessStop(77, now.AddMilliseconds(900));
        AssertEqual(null, cache.Resolve(77, "same-name", now.AddMilliseconds(950), now.AddSeconds(1), resolver));
        AssertEqual(newIdentity, cache.Resolve(77, "same-name", now.AddSeconds(1.1), now.AddSeconds(1.01), resolver));
        cache.ObserveProcessStop(77, now.AddSeconds(1.05));
        AssertEqual(newIdentity, cache.Resolve(77, "same-name", now.AddSeconds(1.06), now.AddSeconds(1.06), resolver));
        AssertEqual(0, resolver.ResolveCalls);

        resolver.Values[88] = new ResolvedProcessIdentity(new ProcessIdentity(88, now), "expires");
        AssertEqual(resolver.Values[88], cache.Resolve(88, "expires", now.AddSeconds(2), now.AddSeconds(2), resolver));
        AssertEqual(1, resolver.ResolveCalls);
        AssertEqual(resolver.Values[88], cache.Resolve(88, "expires", now.AddSeconds(2.05), now.AddSeconds(2.05), resolver));
        AssertEqual(1, resolver.ResolveCalls);
        AssertEqual(resolver.Values[88], cache.Resolve(88, "expires", now.AddSeconds(2.2), now.AddSeconds(2.2), resolver));
        AssertEqual(2, resolver.ResolveCalls);
        AssertTrue(cache.Count <= 8, "Process identity cache exceeded its hard bound.");
        return Task.CompletedTask;
    }

    private static Task TestPreFlowRawPromotionAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var identity = new ProcessIdentity(77, now.AddSeconds(-8.5));
        var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identity, "preflow"),
            capacity: 8,
            recentRawCapacity: 16,
            recentRawPerProcessCapacity: 4,
            recentRawRetention: TimeSpan.FromSeconds(35));
        var path = "C:\\Synthetic\\pre-flow.egfixture";
        var promoted = sensor.PromoteRawForTest(
            [
                new RawFileActivity(1, now.AddSeconds(-8), identity.ProcessId, "preflow", FileActivityOperation.Read, path),
                new RawFileActivity(2, now.AddSeconds(-31), identity.ProcessId, "preflow", FileActivityOperation.Read, "C:\\Synthetic\\too-old.egfixture"),
                new RawFileActivity(3, now.AddSeconds(-9), identity.ProcessId, "preflow", FileActivityOperation.Read, "C:\\Synthetic\\before-generation.egfixture")
            ],
            [new FileActivityProcessInterest(identity, "preflow")]);

        AssertEqual(1, promoted.Count);
        AssertEqual(identity, promoted[0].ProcessIdentity);
        AssertEqual(".egfixture", promoted[0].Extension);
        AssertEqual(-8, (promoted[0].TimestampUtc - now).TotalSeconds);
        AssertEqual(0, sensor.RecentRawEventCount);
        return Task.CompletedTask;
    }

    private static async Task TestPreFlowRawBufferBoundsAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var identity = new ProcessIdentity(81, now.AddMinutes(-1));
        var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identity, "noisy"),
            capacity: 8,
            recentRawCapacity: 8,
            recentRawPerProcessCapacity: 3,
            recentRawRetention: TimeSpan.FromMilliseconds(50));
        var events = Enumerable.Range(0, 200)
            .Select(index => new RawFileActivity(index, now.AddMilliseconds(-index), identity.ProcessId, "noisy", FileActivityOperation.Read, $"C:\\Synthetic\\noise-{index}.egfixture"));
        _ = sensor.PromoteRawForTest(events, []);
        AssertTrue(sensor.RecentRawEventCount <= 8, "Recent raw event buffer exceeded its global hard bound.");
        AssertTrue(sensor.RecentRawPeak <= 8, "Recent raw event peak exceeded its global hard bound.");
        AssertTrue(sensor.RecentRawPerProcessPeak <= 3, "Recent raw per-process peak exceeded its hard bound.");
        AssertTrue(sensor.Status.DroppedEvents > 0, "No bounded-buffer drop was recorded for a noisy process.");

        await Task.Delay(75).ConfigureAwait(false);

        var expired = sensor.PromoteRawForTest(
            [new RawFileActivity(1000, now.AddSeconds(-2), identity.ProcessId, "noisy", FileActivityOperation.Read, "C:\\Synthetic\\expired.egfixture")],
            [new FileActivityProcessInterest(identity, "noisy")]);
        AssertEqual(0, expired.Count);
        AssertEqual(0, sensor.RecentRawEventCount);

        var outOfOrderSensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identity, "out-of-order"),
            capacity: 8,
            recentRawCapacity: 8,
            recentRawPerProcessCapacity: 4,
            recentRawRetention: TimeSpan.FromSeconds(1));
        var outOfOrder = outOfOrderSensor.PromoteRawForTest(
            [
                new RawFileActivity(1, now.AddMilliseconds(-500), identity.ProcessId, "out-of-order", FileActivityOperation.Read, "C:\\Synthetic\\current-a.egfixture"),
                new RawFileActivity(2, now.AddSeconds(-2), identity.ProcessId, "out-of-order", FileActivityOperation.Read, "C:\\Synthetic\\expired-middle.egfixture"),
                new RawFileActivity(3, now.AddMilliseconds(-250), identity.ProcessId, "out-of-order", FileActivityOperation.Read, "C:\\Synthetic\\current-b.egfixture")
            ],
            [new FileActivityProcessInterest(identity, "out-of-order")]);
        AssertEqual(2, outOfOrder.Count);
        AssertTrue(outOfOrder.All(item => !item.Path.Contains("expired-middle", StringComparison.Ordinal)), "Out-of-order expiration promoted an expired event.");

        var globalSensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identity, "global-bound"),
            capacity: 8,
            recentRawCapacity: 4,
            recentRawPerProcessCapacity: 4,
            recentRawRetention: TimeSpan.FromMinutes(1));
        var globalPromoted = globalSensor.PromoteRawForTest(
            Enumerable.Range(1, 5).Select(processId => new RawFileActivity(
                processId,
                now,
                processId,
                $"global-{processId}",
                FileActivityOperation.Read,
                $"C:\\Synthetic\\global-{processId}.egfixture")),
            [
                new FileActivityProcessInterest(new ProcessIdentity(1, now.AddMinutes(-1)), "global-1"),
                new FileActivityProcessInterest(new ProcessIdentity(5, now.AddMinutes(-1)), "global-5")
            ]);
        AssertEqual(1, globalPromoted.Count);
        AssertTrue(globalPromoted[0].Path.EndsWith("global-5.egfixture", StringComparison.Ordinal), "Global eviction left a stale per-PID index or removed the newest event.");
        AssertTrue(globalSensor.RecentRawPeak <= 4, "Global raw buffer peak exceeded its hard bound.");
    }

    private static Task TestPreFlowRawDedupeAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var identity = new ProcessIdentity(82, now.AddMinutes(-1));
        var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identity, "chunked-read"),
            capacity: 8,
            recentRawCapacity: 8,
            recentRawPerProcessCapacity: 3,
            recentRawRetention: TimeSpan.FromMinutes(1));
        var path = "C:\\Synthetic\\chunked-read.egfixture";
        var events = Enumerable.Range(0, 1_000)
            .Select(index => new RawFileActivity(
                index,
                now.AddMilliseconds(index),
                identity.ProcessId,
                "chunked-read",
                FileActivityOperation.Read,
                path));

        _ = sensor.PromoteRawForTest(events, []);
        AssertEqual(1, sensor.RecentRawEventCount);
        AssertEqual(1, sensor.RecentRawDedupeCount);
        AssertEqual(0L, sensor.Status.DroppedEvents);

        var promoted = sensor.UpdateProcessInterests([new FileActivityProcessInterest(identity, "chunked-read")]);
        AssertEqual(1, promoted.Count);
        AssertEqual(999L, promoted[0].Sequence);
        AssertEqual(now.AddMilliseconds(999), promoted[0].TimestampUtc);
        AssertEqual(0, sensor.RecentRawEventCount);
        AssertEqual(0, sensor.RecentRawDedupeCount);
        return Task.CompletedTask;
    }

    private static async Task TestPreFlowAdmissionAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var identity = new ProcessIdentity(81, now.AddMinutes(-1));
        await using var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identity, "admission"),
            capacity: 16,
            recentRawCapacity: 16,
            recentRawPerProcessCapacity: 8,
            recentRawRetention: TimeSpan.FromMinutes(1),
            lowValueSystemRoots: []);

        foreach (var operation in new[]
        {
            FileActivityOperation.OpenCreate,
            FileActivityOperation.Write,
            FileActivityOperation.Rename,
            FileActivityOperation.Delete
        })
        {
            sensor.StageForTest(identity.ProcessId, "admission", $"C:\\Synthetic\\unknown-{operation}.egfixture", operation, now.UtcDateTime);
        }

        AssertEqual(0, sensor.StagedEventCount);
        AssertEqual(0L, sensor.Status.DroppedEvents);

        sensor.StageForTest(identity.ProcessId, "admission", "C:\\Synthetic\\unknown-read.egfixture", FileActivityOperation.Read, now.UtcDateTime);
        AssertEqual(1, sensor.StagedEventCount);

        _ = sensor.UpdateProcessInterests([new FileActivityProcessInterest(identity, "admission")]);
        sensor.StageForTest(identity.ProcessId, "admission", "C:\\Synthetic\\known-write.egfixture", FileActivityOperation.Write, now.UtcDateTime);
        AssertEqual(2, sensor.StagedEventCount);

        sensor.ObserveProcessStop(identity, now);
        sensor.StageForTest(identity.ProcessId, "admission", "C:\\Synthetic\\stopped-write.egfixture", FileActivityOperation.Write, now.UtcDateTime);
        AssertEqual(2, sensor.StagedEventCount);
    }

    private static Task TestEtwCallbackAdmissionAsync()
    {
        var cache = new EtwCallbackAdmissionCache(2, TimeSpan.FromMilliseconds(750));
        var now = DateTimeOffset.UtcNow;
        var first = new RawFileActivityKey(1, FileActivityOperation.Read, "C:\\Synthetic\\first.egfixture");
        var second = new RawFileActivityKey(1, FileActivityOperation.Read, "C:\\Synthetic\\second.egfixture");
        var third = new RawFileActivityKey(2, FileActivityOperation.Read, "C:\\Synthetic\\third.egfixture");

        AssertTrue(cache.ShouldAdmit(first, now), "The first callback event was not admitted.");
        AssertTrue(!cache.ShouldAdmit(first, now.AddMilliseconds(100)), "A duplicate chunk was admitted inside the coalescing window.");
        AssertTrue(cache.ShouldAdmit(second, now.AddMilliseconds(200)), "A distinct file event was not admitted.");
        AssertTrue(cache.ShouldAdmit(third, now.AddMilliseconds(300)), "A distinct process event was not admitted.");
        AssertEqual(2, cache.Count);
        AssertTrue(cache.ShouldAdmit(first, now.AddMilliseconds(301)), "The oldest bounded entry was not evicted.");
        AssertEqual(2, cache.Count);
        AssertTrue(cache.ShouldAdmit(first, now.AddSeconds(2)), "An expired callback entry suppressed a later event.");
        AssertEqual(1, cache.Count);
        return Task.CompletedTask;
    }

    private static Task TestPidReuseRawPromotionAsync()
    {
        var startA = DateTimeOffset.UtcNow.AddSeconds(-20);
        var startB = startA.AddSeconds(10);
        var identityA = new ProcessIdentity(77, startA);
        var identityB = new ProcessIdentity(77, startB);
        var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(identityB, "same-name"),
            capacity: 8,
            recentRawCapacity: 16,
            recentRawPerProcessCapacity: 8,
            recentRawRetention: TimeSpan.FromMinutes(1));
        var promoted = sensor.PromoteRawForTest(
            [
                new RawFileActivity(1, startA.AddSeconds(5), 77, "same-name", FileActivityOperation.Read, "C:\\Synthetic\\generation-a.egfixture"),
                new RawFileActivity(2, startB.AddSeconds(2), 77, "same-name", FileActivityOperation.Read, "C:\\Synthetic\\generation-b.egfixture")
            ],
            []);
        sensor.ObserveProcessStop(identityA, startA.AddSeconds(10));
        var current = sensor.UpdateProcessInterests([new FileActivityProcessInterest(identityB, "same-name")]);
        AssertEqual(1, current.Count);
        AssertEqual(identityB, current[0].ProcessIdentity);
        AssertTrue(current[0].Path.EndsWith("generation-b.egfixture", StringComparison.OrdinalIgnoreCase), "PID reuse promoted an event from the previous generation.");
        AssertEqual(0, promoted.Count);
        return Task.CompletedTask;
    }

    private static Task TestPendingPromotionIndexAsync()
    {
        var now = DateTimeOffset.UtcNow;
        var interests = Enumerable.Range(1, 64)
            .Select(processId => new FileActivityProcessInterest(new ProcessIdentity(processId, now.AddMinutes(-1)), $"process-{processId}"))
            .ToArray();
        var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(interests[0].Identity, interests[0].ProcessName),
            capacity: 4096,
            recentRawCapacity: 4096,
            recentRawPerProcessCapacity: 256,
            recentRawRetention: TimeSpan.FromMinutes(1));
        AssertEqual(0, sensor.UpdateProcessInterests(interests).Count);
        var events = Enumerable.Range(0, 256)
            .Select(index =>
            {
                var interest = interests[index % interests.Length];
                return new RawFileActivity(
                    index,
                    now.AddMilliseconds(index % 4),
                    interest.Identity.ProcessId,
                    interest.ProcessName,
                    FileActivityOperation.Read,
                    $"C:\\Synthetic\\pending-{index}.egfixture");
            })
            .ToArray();
        AssertEqual(0, sensor.PromoteRawForTest(events, []).Count);
        AssertEqual(events.Length, sensor.PendingPromotedCount);
        AssertEqual(interests.Length, sensor.PendingPromotedIdentityCount);

        var visitsBefore = sensor.PendingPromotionNodesVisited;
        var promoted = sensor.UpdateProcessInterests(interests);
        var visits = sensor.PendingPromotionNodesVisited - visitsBefore;
        AssertEqual(events.Length, promoted.Count);
        AssertEqual((long)events.Length, visits);
        AssertTrue(visits < (long)interests.Length * events.Length, "Pending promotion still scanned the process-by-event product.");
        AssertTrue(promoted.All(item => item.ProcessName == $"process-{item.ProcessIdentity.ProcessId}"), "An identity received another process's pending event.");
        foreach (var group in promoted.GroupBy(item => item.ProcessIdentity))
        {
            AssertTrue(group.Select(item => item.Sequence).SequenceEqual(group.Select(item => item.Sequence).Order()), "Pending promotion changed deterministic per-identity event order.");
        }
        AssertEqual(0, sensor.PendingPromotedCount);
        AssertEqual(0, sensor.PendingPromotedIdentityCount);
        AssertEqual(0, sensor.UpdateProcessInterests(interests).Count);
        AssertEqual(visitsBefore + visits, sensor.PendingPromotionNodesVisited);

        var reusedSensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(new ProcessIdentity(77, now), "same-name"),
            capacity: 8,
            recentRawCapacity: 4,
            recentRawPerProcessCapacity: 4,
            recentRawRetention: TimeSpan.FromMinutes(1));
        var generationA = new FileActivityProcessInterest(new ProcessIdentity(77, now.AddMinutes(-1)), "same-name");
        var generationB = new FileActivityProcessInterest(new ProcessIdentity(77, now), "same-name");
        _ = reusedSensor.UpdateProcessInterests([generationA]);
        _ = reusedSensor.PromoteRawForTest([
            new RawFileActivity(1, now.AddSeconds(-1), 77, "same-name", FileActivityOperation.Read, "C:\\Synthetic\\generation-a-pending.egfixture")
        ], []);
        AssertEqual(0, reusedSensor.UpdateProcessInterests([generationB]).Count);
        _ = reusedSensor.PromoteRawForTest([
            new RawFileActivity(2, now.AddSeconds(1), 77, "same-name", FileActivityOperation.Read, "C:\\Synthetic\\generation-b-pending.egfixture")
        ], []);
        var current = reusedSensor.UpdateProcessInterests([generationB]);
        AssertEqual(1, current.Count);
        AssertEqual(generationB.Identity, current[0].ProcessIdentity);
        AssertEqual(1, reusedSensor.PendingPromotedCount);

        var evictionInterests = Enumerable.Range(100, 5)
            .Select(processId => new FileActivityProcessInterest(new ProcessIdentity(processId, now.AddMinutes(-1)), $"evict-{processId}"))
            .ToArray();
        _ = reusedSensor.UpdateProcessInterests(evictionInterests);
        _ = reusedSensor.PromoteRawForTest(evictionInterests.Select((interest, index) => new RawFileActivity(
            10 + index,
            now,
            interest.Identity.ProcessId,
            interest.ProcessName,
            FileActivityOperation.Read,
            $"C:\\Synthetic\\evict-{index}.egfixture")), []);
        AssertEqual(4, reusedSensor.PendingPromotedCount);
        AssertEqual(4, reusedSensor.PendingPromotedIdentityCount);
        var retained = reusedSensor.UpdateProcessInterests(evictionInterests);
        AssertEqual(4, retained.Count);
        AssertEqual(0, reusedSensor.PendingPromotedCount);
        AssertEqual(0, reusedSensor.PendingPromotedIdentityCount);
        AssertEqual(2L, reusedSensor.Status.DroppedEvents);
        return Task.CompletedTask;
    }

    private static Task TestPromotedCorrelationCleanupAsync()
    {
        const int capacity = 4096;
        var now = DateTimeOffset.UtcNow;
        var interests = Enumerable.Range(1, 64)
            .Select(processId => new FileActivityProcessInterest(new ProcessIdentity(processId, now.AddMinutes(-1)), $"correlate-{processId}"))
            .ToArray();
        var sensor = new EtwFileActivitySensor(
            new FixedProcessIdentityResolver(interests[0].Identity, interests[0].ProcessName),
            capacity: capacity,
            recentRawCapacity: capacity,
            recentRawPerProcessCapacity: 256,
            recentRawRetention: TimeSpan.FromMinutes(2));
        _ = sensor.UpdateProcessInterests(interests);
        _ = sensor.PromoteRawForTest(Enumerable.Range(0, capacity).Select(index =>
        {
            var interest = interests[index % interests.Length];
            return new RawFileActivity(
                index,
                now.AddSeconds(-(index % 25)),
                interest.Identity.ProcessId,
                interest.ProcessName,
                FileActivityOperation.Read,
                $"C:\\Synthetic\\promoted-{index}.egfixture");
        }), []);
        var promoted = sensor.UpdateProcessInterests(interests);
        AssertEqual(capacity, promoted.Count);

        var options = new FileCorrelationOptions(
            TimeSpan.FromSeconds(30),
            TimeSpan.FromSeconds(5),
            TimeSpan.FromMinutes(2),
            TimeSpan.FromMilliseconds(750),
            capacity,
            20);
        var engine = new FileCorrelationEngine(options, pathSalt: [1, 2, 3, 4]);
        var inspectionsBefore = engine.CleanupNodesInspected;
        foreach (var activity in promoted) AssertTrue(engine.Add(activity), "A unique promoted event was rejected.");
        var addInspections = engine.CleanupNodesInspected - inspectionsBefore;
        AssertEqual(capacity, engine.BufferedEventCount);
        AssertEqual(capacity, engine.TimestampIndexCount);
        AssertEqual((long)capacity - 1, addInspections);

        var sample = SampleFlow() with
        {
            ProcessIdentity = interests[0].Identity,
            ProcessName = interests[0].ProcessName,
            FirstSeen = now,
            LastSeen = now.AddSeconds(1)
        };
        AssertEqual(20, engine.Correlate(sample, now).Count);
        AssertEqual(capacity, engine.Cleanup(now.AddMinutes(3)));
        AssertEqual(0, engine.BufferedEventCount);
        AssertEqual(0, engine.TimestampIndexCount);
        AssertEqual(0, engine.DedupeEntryCount);
        return Task.CompletedTask;
    }

    private static async Task TestEtwOwnershipAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-Ownership-" + Guid.NewGuid().ToString("N"));
        try
        {
            var registry = new FakeEtwSessionRegistry();
            var firstManager = new EtwSessionOwnershipManager(directory, registry, (_, _) => false);
            var first = firstManager.Acquire();
            registry.Active.Add(first.SessionName);
            registry.Active.Add("Foreign.Application.Session");

            var restartManager = new EtwSessionOwnershipManager(directory, registry, (_, _) => false);
            var restarted = restartManager.Acquire();
            AssertEqual(first.SessionName, restarted.SessionName);
            AssertEqual(1, registry.Stopped.Count);
            AssertEqual(first.SessionName, registry.Stopped[0]);
            AssertTrue(registry.Active.Contains("Foreign.Application.Session"), "Foreign ETW session was stopped.");

            var liveOwnerManager = new EtwSessionOwnershipManager(directory, registry, (_, _) => true);
            AssertThrows<InvalidOperationException>(() => liveOwnerManager.Acquire());
            AssertEqual(1, registry.Stopped.Count);
            restartManager.Release(restarted);
            return;
        }
        finally
        {
            if (Directory.Exists(directory)) await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }
    }

    private static async Task TestFileSensorDegradedServiceAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-DegradedSensor-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var database = new EgressGuardDatabase(Path.Combine(directory, "test.db"));
            await database.InitializeAsync().ConfigureAwait(false);
            await database.SetSettingAsync("enable_file_correlation", "true").ConfigureAwait(false);
            var logger = new ListLogger<FlowCoordinator>();
            var state = new ServiceState();
            var coordinator = new FlowCoordinator(
                new EmptyFlowSensor(), database, new RiskEngine(), new BaselineTracker(), new FakeFirewallRuleManager(),
                state, new EventHub(), logger, new AccessDeniedFileSensor(), NewCorrelationEngine());
            await coordinator.StartAsync(CancellationToken.None).ConfigureAwait(false);
            await Task.Delay(150).ConfigureAwait(false);
            await coordinator.StopAsync(CancellationToken.None).WaitAsync(TimeSpan.FromSeconds(5)).ConfigureAwait(false);
            AssertEqual(FileSensorState.Stopped, state.FileSensorStatus.State);
            AssertTrue(!logger.Entries.Any(item => item.Level == LogLevel.Error), "Degraded file sensor produced a service error.");
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task TestRealEtwFileIntegrationAsync()
    {
        if (!WindowsFirewallManager.IsAdministrator())
        {
            throw new TestFailureException("Real ETW file integration requires an Administrator token.");
        }

        var directory = Path.Combine(Path.GetTempPath(), $"EgressGuard-Etw-{Guid.NewGuid():N}");
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "synthetic.egfixture");
        var ownershipDirectory = Path.Combine(directory, "ownership");
        await using var sensor = new EtwFileActivitySensor([ownershipDirectory], ownershipDirectory: ownershipDirectory);
        try
        {
            await sensor.StartAsync(CancellationToken.None).ConfigureAwait(false);
            AssertEqual(FileSensorState.Running, sensor.Status.State);
            await File.WriteAllTextAsync(path, "synthetic non-sensitive fixture").ConfigureAwait(false);
            _ = await File.ReadAllTextAsync(path).ConfigureAwait(false);
            using var rawTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            while (sensor.RecentRawEventCount == 0)
            {
                await Task.Delay(50, rawTimeout.Token).ConfigureAwait(false);
            }
            using var process = Process.GetCurrentProcess();
            var promoted = sensor.UpdateProcessInterests([
                new FileActivityProcessInterest(
                    new ProcessIdentity(process.Id, process.StartTime.ToUniversalTime()),
                    process.ProcessName)
            ]);
            AssertTrue(promoted.Any(activity =>
                activity.ProcessIdentity.ProcessId == Environment.ProcessId
                && activity.Extension == ".egfixture"
                && activity.Path.Equals(path, StringComparison.OrdinalIgnoreCase)),
                "ETW sensor did not promote the synthetic pre-flow fixture after the exact network identity was supplied.");
            return;
        }
        finally
        {
            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await sensor.StopAsync(stopTimeout.Token).ConfigureAwait(false);
            if (File.Exists(path)) File.Delete(path);
            if (Directory.Exists(directory)) await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }
    }

    private static async Task<int> RunEtwOrphanChildAsync(string directory)
    {
        var ownershipDirectory = Path.Combine(directory, "ownership");
        await using var sensor = new EtwFileActivitySensor([ownershipDirectory], ownershipDirectory: ownershipDirectory);
        await sensor.StartAsync(CancellationToken.None).ConfigureAwait(false);
        if (sensor.Status.State != FileSensorState.Running || sensor.SessionName is null)
        {
            Console.Error.WriteLine($"FAILED|{sensor.Status.State}|{sensor.Status.Detail}");
            return 3;
        }

        Console.WriteLine("READY|" + sensor.SessionName);
        Console.Out.Flush();
        await Task.Delay(Timeout.InfiniteTimeSpan).ConfigureAwait(false);
        return 0;
    }

    private static async Task TestRealEtwOrphanReclaimIntegrationAsync()
    {
        if (!WindowsFirewallManager.IsAdministrator())
        {
            throw new TestFailureException("Real ETW orphan reclaim integration requires an Administrator token.");
        }

        var executable = Environment.ProcessPath ?? throw new TestFailureException("Test executable path is unavailable.");
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-Orphan-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        Process? child = null;
        string? sessionName = null;
        var registry = new TraceEventSessionRegistry();
        try
        {
            child = Process.Start(new ProcessStartInfo(executable)
            {
                UseShellExecute = false,
                CreateNoWindow = true,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                ArgumentList = { "--etw-orphan-child", directory }
            }) ?? throw new TestFailureException("Unable to start ETW orphan child.");
            var ready = await child.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            if (ready is null || !ready.StartsWith("READY|", StringComparison.Ordinal))
            {
                var error = await child.StandardError.ReadToEndAsync().ConfigureAwait(false);
                throw new TestFailureException($"ETW orphan child did not become ready: {ready} {error}");
            }

            sessionName = ready["READY|".Length..];
            AssertTrue(registry.IsActive(sessionName), "Child ETW session was not active.");
            child.Kill(entireProcessTree: true);
            await child.WaitForExitAsync().ConfigureAwait(false);
            AssertTrue(registry.IsActive(sessionName), "Windows did not leave the controlled session orphaned after controller termination.");

            var ownershipDirectory = Path.Combine(directory, "ownership");
            await using var restarted = new EtwFileActivitySensor([ownershipDirectory], ownershipDirectory: ownershipDirectory);
            await restarted.StartAsync(CancellationToken.None).ConfigureAwait(false);
            AssertEqual(FileSensorState.Running, restarted.Status.State);
            AssertEqual(sessionName, restarted.SessionName);
            using var stopTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await restarted.StopAsync(stopTimeout.Token).ConfigureAwait(false);
            AssertTrue(!registry.IsActive(sessionName), "Reclaimed ETW session remained after clean stop.");
        }
        finally
        {
            if (child is { HasExited: false })
            {
                child.Kill(entireProcessTree: true);
                await child.WaitForExitAsync().ConfigureAwait(false);
            }
            child?.Dispose();
            if (sessionName is not null && registry.IsActive(sessionName)) registry.StopExact(sessionName);
            if (Directory.Exists(directory)) await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }
    }

    private static async Task TestRealEtwLifecycleIntegrationAsync(int cycleCount)
    {
        if (!WindowsFirewallManager.IsAdministrator())
        {
            throw new TestFailureException("Real ETW lifecycle integration requires an Administrator token.");
        }

        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-Lifecycle-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var registry = new TraceEventSessionRegistry();
        var foreignBefore = TraceEventSession.GetActiveSessionNames()
            .Where(name => !name.StartsWith(EtwSessionOwnershipManager.SessionPrefix, StringComparison.Ordinal))
            .ToHashSet(StringComparer.Ordinal);
        string? lingering = null;
        try
        {
            for (var cycle = 0; cycle < cycleCount; cycle++)
            {
                var ownershipDirectory = Path.Combine(directory, $"ownership-{cycle}");
                await using var sensor = new EtwFileActivitySensor([ownershipDirectory], ownershipDirectory: ownershipDirectory);
                await sensor.StartAsync(CancellationToken.None).ConfigureAwait(false);
                AssertEqual(FileSensorState.Running, sensor.Status.State);
                var sessionName = sensor.SessionName ?? throw new TestFailureException("ETW sensor did not expose its exact session name.");
                AssertTrue(registry.IsActive(sessionName), $"ETW session was not active in cycle {cycle}.");

                if (cycle == 5)
                {
                    using var cancellation = new CancellationTokenSource(TimeSpan.FromMilliseconds(1));
                    try { await sensor.StopAsync(cancellation.Token).ConfigureAwait(false); }
                    catch (OperationCanceledException) { }
                    await sensor.StopAsync(CancellationToken.None).ConfigureAwait(false);
                }
                else
                {
                    await sensor.StopAsync(CancellationToken.None).ConfigureAwait(false);
                }

                AssertTrue(!registry.IsActive(sessionName), $"Exact ETW session remained active in cycle {cycle}.");
                AssertTrue(!File.Exists(Path.Combine(ownershipDirectory, "file-activity-session-owner.json")), $"Ownership marker remained in cycle {cycle}.");
                AssertTrue(
                    !TraceEventSession.GetActiveSessionNames().Any(name => name.StartsWith(EtwSessionOwnershipManager.SessionPrefix, StringComparison.Ordinal)),
                    $"An EgressGuard ETW session remained before lifecycle cycle {cycle + 1}.");
                AssertTrue(foreignBefore.All(registry.IsActive), "Lifecycle test changed a foreign/shared ETW session.");
            }
        }
        finally
        {
            lingering = TraceEventSession.GetActiveSessionNames()
                .Where(name => name.StartsWith(EtwSessionOwnershipManager.SessionPrefix, StringComparison.Ordinal))
                .FirstOrDefault();

            if (Directory.Exists(directory)) await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }

        if (lingering is not null)
        {
            throw new TestFailureException($"ETW session remained after lifecycle test: {lingering}");
        }
    }

    private static FileCorrelationEngine NewCorrelationEngine(int maxBuffered = 32, int maxEvidence = 20, IEnumerable<string>? excludedRoots = null) =>
        new(new FileCorrelationOptions(TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(5), TimeSpan.FromMinutes(2), TimeSpan.FromMilliseconds(750), maxBuffered, maxEvidence), excludedRoots, [1, 2, 3, 4]);

    private static FileActivity FileEvent(NetworkFlow flow, long sequence, double secondsFromFlow, FileActivityOperation operation, string path) =>
        new(sequence, flow.FirstSeen.AddSeconds(secondsFromFlow), flow.ProcessIdentity!.Value, flow.ProcessName, operation, path, Path.GetExtension(path), "Test", true);

    private static Task TestPortConversionAsync()
    {
        var native = unchecked((uint)(ushort)IPAddress.HostToNetworkOrder((short)443));
        AssertEqual(443, NetworkValueConverter.DecodePort(native));
        return Task.CompletedTask;
    }

    private static Task TestEndpointFormattingAsync()
    {
        AssertEqual("127.0.0.1:5050", NetworkValueConverter.FormatEndpoint(new NetworkEndpoint(IPAddress.Loopback, 5050)));
        AssertEqual("[::1]:5050", NetworkValueConverter.FormatEndpoint(new NetworkEndpoint(IPAddress.IPv6Loopback, 5050)));
        AssertEqual("*: *".Replace(" ", string.Empty, StringComparison.Ordinal), NetworkValueConverter.FormatEndpoint(null));
        return Task.CompletedTask;
    }

    private static Task TestExecutableMetadataAsync()
    {
        var testDirectory = Path.Combine(Path.GetTempPath(), "EgressGuard-Tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
        var testPath = Path.Combine(testDirectory, "sample.exe");
        try
        {
            var sourcePath = Environment.ProcessPath ?? throw new TestFailureException("Current executable path is unavailable.");
            File.Copy(sourcePath, testPath);
            var bytes = File.ReadAllBytes(testPath);
            var provider = new ExecutableMetadataProvider();
            var first = provider.GetMetadata(testPath) ?? throw new TestFailureException("Metadata was null.");
            var second = provider.GetMetadata(testPath) ?? throw new TestFailureException("Cached metadata was null.");
            AssertEqual(Convert.ToHexString(SHA256.HashData(bytes)), first.Sha256);
            AssertTrue(ReferenceEquals(first, second), "Expected the unchanged file metadata to come from cache.");
            AssertEqual(SignatureVerificationStatus.Unsigned, first.SignatureStatus);
            File.WriteAllBytes(testPath, [.. bytes, 0x45, 0x47]);
            File.SetLastWriteTimeUtc(testPath, DateTime.UtcNow.AddSeconds(2));
            var changed = provider.GetMetadata(testPath) ?? throw new TestFailureException("Changed metadata was null.");
            AssertTrue(!ReferenceEquals(first, changed), "Changed file incorrectly reused cached metadata.");
            AssertNotEqual(first.Sha256, changed.Sha256);
        }
        finally
        {
            Directory.Delete(testDirectory, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static Task TestAuthenticodeAsync()
    {
        AssertEqual(SignatureVerificationStatus.Valid, AuthenticodeVerifier.MapStatus(0));
        AssertEqual(SignatureVerificationStatus.Unsigned, AuthenticodeVerifier.MapStatus(unchecked((int)0x800B0100)));
        AssertEqual(SignatureVerificationStatus.Invalid, AuthenticodeVerifier.MapStatus(unchecked((int)0x80096010)));
        AssertEqual(SignatureVerificationStatus.Expired, AuthenticodeVerifier.MapStatus(unchecked((int)0x800B0101)));
        AssertEqual(SignatureVerificationStatus.Revoked, AuthenticodeVerifier.MapStatus(unchecked((int)0x800B010C)));
        AssertEqual(SignatureVerificationStatus.Untrusted, AuthenticodeVerifier.MapStatus(unchecked((int)0x800B0111)));
        AssertEqual(SignatureVerificationStatus.VerificationUnavailable, AuthenticodeVerifier.MapStatus(unchecked((int)0x80092013)));
        AssertEqual(SignatureVerificationStatus.Unknown, AuthenticodeVerifier.MapStatus(unchecked((int)0x81234567)));
        AssertEqual(SignatureVerificationStatus.VerificationUnavailable, AuthenticodeVerifier.Verify(Path.Combine(Path.GetTempPath(), Guid.NewGuid() + ".exe")));

        var catalogSignedPath = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32", "cmd.exe");
        AssertEqual(SignatureVerificationStatus.Valid, AuthenticodeVerifier.Verify(catalogSignedPath));
        var signedPath = new[]
        {
            Environment.GetEnvironmentVariable("DOTNET_HOST_PATH"),
            Path.Combine(Environment.GetEnvironmentVariable("DOTNET_ROOT") ?? string.Empty, "dotnet.exe"),
            Path.Combine(Path.GetTempPath(), "EgressGuard-dotnet8", "dotnet.exe")
        }.FirstOrDefault(path => !string.IsNullOrWhiteSpace(path) && File.Exists(path))
            ?? throw new TestFailureException("No embedded-signed test executable was found.");
        AssertEqual(SignatureVerificationStatus.Valid, AuthenticodeVerifier.Verify(signedPath));

        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-SignatureTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var tamperedPath = Path.Combine(directory, "signed-tampered.exe");
            File.Copy(signedPath, tamperedPath);
            var bytes = File.ReadAllBytes(tamperedPath);
            var offset = Math.Min(4096, bytes.Length / 2);
            bytes[offset] ^= 0x01;
            File.WriteAllBytes(tamperedPath, bytes);
            AssertEqual(SignatureVerificationStatus.Invalid, AuthenticodeVerifier.Verify(tamperedPath));
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static Task TestFirewallPathValidationAsync()
    {
        var testDirectory = Path.Combine(Path.GetTempPath(), "EgressGuard-Tests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(testDirectory);
        var simulatorPath = Path.Combine(testDirectory, "EgressGuard.Simulator.exe");
        var otherPath = Path.Combine(testDirectory, "other.exe");
        try
        {
            File.WriteAllBytes(simulatorPath, [0]);
            File.WriteAllBytes(otherPath, [0]);
            AssertEqual(Path.GetFullPath(simulatorPath), WindowsFirewallManager.ValidateSimulatorPath(simulatorPath));
            AssertThrows<ArgumentException>(() => WindowsFirewallManager.ValidateSimulatorPath(otherPath));
            AssertThrows<FileNotFoundException>(() => WindowsFirewallManager.ValidateSimulatorPath(Path.Combine(testDirectory, "missing.exe")));
            var hash = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(simulatorPath)));
            var rule = new FirewallRule(Guid.NewGuid(), "hash validation", FirewallAction.Block, RuleSource.User, simulatorPath, hash, null, null, null, true, DateTimeOffset.UtcNow, null);
            OwnedFirewallRuleManager.ValidateExecutableHash(rule);
            AssertThrows<InvalidOperationException>(() => OwnedFirewallRuleManager.ValidateExecutableHash(rule with { ExecutableSha256 = new string('A', 64) }));
        }
        finally
        {
            Directory.Delete(testDirectory, recursive: true);
        }

        return Task.CompletedTask;
    }

    private static async Task TestPowerShellPreCancellationAsync()
    {
        var starts = 0;
        var runner = new PowerShellProcessRunner(
            startProcess: startInfo =>
            {
                Interlocked.Increment(ref starts);
                return Process.Start(startInfo);
            });
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();

        await AssertThrowsAsync<OperationCanceledException>(() =>
            runner.RunAsync("Write-Output 'unexpected'", new Dictionary<string, string>(), cancellation.Token)).ConfigureAwait(false);

        AssertEqual(0, starts);

        var firewallRunner = new StatefulFirewallPowerShellRunner();
        var manager = new OwnedFirewallRuleManager(firewallRunner, () => true);
        var executablePath = Environment.ProcessPath ?? throw new TestFailureException("Test executable path is unavailable.");
        await AssertThrowsAsync<OperationCanceledException>(() =>
            manager.CreateAsync(TestRuleForExecutable(executablePath), cancellation.Token)).ConfigureAwait(false);
        AssertEqual(0, firewallRunner.InvocationCount);
        AssertEqual(FakeExactRuleState.Absent, firewallRunner.State);
    }

    private static async Task TestPowerShellCancellationCleanupAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-PowerShellCancellation-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var parentPidPath = Path.Combine(directory, "parent.pid");
        var childPidPath = Path.Combine(directory, "child.pid");
        using var unrelated = Process.Start(new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30" }
        }) ?? throw new TestFailureException("Unable to start unrelated PowerShell fixture.");
        try
        {
            var runner = new PowerShellProcessRunner(TimeSpan.FromSeconds(15), TimeSpan.FromSeconds(5));
            var environment = new Dictionary<string, string>
            {
                ["EG_PARENT_PID_PATH"] = parentPidPath,
                ["EG_CHILD_PID_PATH"] = childPidPath
            };
            const string script = """
                Set-Content -LiteralPath $env:EG_PARENT_PID_PATH -Value $PID
                $child=Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru
                Set-Content -LiteralPath $env:EG_CHILD_PID_PATH -Value $child.Id
                Wait-Process -Id $child.Id
                """;
            using var cancellation = new CancellationTokenSource();
            var runTask = runner.RunAsync(script, environment, cancellation.Token);
            await WaitForFileAsync(parentPidPath).ConfigureAwait(false);
            await WaitForFileAsync(childPidPath).ConfigureAwait(false);
            var parentPid = int.Parse((await File.ReadAllTextAsync(parentPidPath).ConfigureAwait(false)).Trim(), System.Globalization.CultureInfo.InvariantCulture);
            var childPid = int.Parse((await File.ReadAllTextAsync(childPidPath).ConfigureAwait(false)).Trim(), System.Globalization.CultureInfo.InvariantCulture);

            cancellation.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(() => runTask).ConfigureAwait(false);

            await AssertProcessExitedAsync(parentPid).ConfigureAwait(false);
            await AssertProcessExitedAsync(childPid).ConfigureAwait(false);
            AssertTrue(!unrelated.HasExited, "Cancellation killed an unrelated PowerShell process.");
        }
        finally
        {
            if (!unrelated.HasExited)
            {
                unrelated.Kill(entireProcessTree: true);
                await unrelated.WaitForExitAsync().ConfigureAwait(false);
            }

            await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }
    }

    private static async Task TestPowerShellTimeoutCleanupAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-PowerShellTimeout-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var parentPidPath = Path.Combine(directory, "parent.pid");
        var childPidPath = Path.Combine(directory, "child.pid");
        try
        {
            var runner = new PowerShellProcessRunner(TimeSpan.FromSeconds(2), TimeSpan.FromSeconds(5));
            var environment = new Dictionary<string, string>
            {
                ["EG_PARENT_PID_PATH"] = parentPidPath,
                ["EG_CHILD_PID_PATH"] = childPidPath
            };
            var runTask = runner.RunAsync(
                "Set-Content -LiteralPath $env:EG_PARENT_PID_PATH -Value $PID; $child=Start-Process powershell.exe -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; Set-Content -LiteralPath $env:EG_CHILD_PID_PATH -Value $child.Id; Wait-Process -Id $child.Id",
                environment,
                CancellationToken.None);
            await WaitForFileAsync(parentPidPath).ConfigureAwait(false);
            await WaitForFileAsync(childPidPath).ConfigureAwait(false);
            var parentPid = int.Parse((await File.ReadAllTextAsync(parentPidPath).ConfigureAwait(false)).Trim(), System.Globalization.CultureInfo.InvariantCulture);
            var childPid = int.Parse((await File.ReadAllTextAsync(childPidPath).ConfigureAwait(false)).Trim(), System.Globalization.CultureInfo.InvariantCulture);

            await AssertThrowsAsync<TimeoutException>(() => runTask).ConfigureAwait(false);
            await AssertProcessExitedAsync(parentPid).ConfigureAwait(false);
            await AssertProcessExitedAsync(childPid).ConfigureAwait(false);
        }
        finally
        {
            await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }
    }

    private static async Task TestFirewallCreateReconciliationAsync()
    {
        var executablePath = Environment.ProcessPath ?? throw new TestFailureException("Test executable path is unavailable.");
        var rule = TestRuleForExecutable(executablePath);
        var runner = new StatefulFirewallPowerShellRunner { CancelCreateAfterMutation = true };
        var manager = new OwnedFirewallRuleManager(runner, () => true);
        using var cancellation = new CancellationTokenSource();
        runner.Cancellation = cancellation;

        await AssertThrowsAsync<OperationCanceledException>(() => manager.CreateAsync(rule, cancellation.Token)).ConfigureAwait(false);

        AssertEqual(FakeExactRuleState.Absent, runner.State);
        AssertEqual(1, runner.ExactDeleteCount);

        var preExistingRunner = new StatefulFirewallPowerShellRunner { State = FakeExactRuleState.Match };
        var preExistingManager = new OwnedFirewallRuleManager(preExistingRunner, () => true);
        AssertEqual(FirewallMutationStatus.Unchanged, await preExistingManager.CreateAsync(rule, CancellationToken.None).ConfigureAwait(false));
        AssertEqual(0, preExistingRunner.CreateCount);
        AssertEqual(0, preExistingRunner.ExactDeleteCount);

        var foreignRunner = new StatefulFirewallPowerShellRunner { State = FakeExactRuleState.Mismatch };
        var foreignManager = new OwnedFirewallRuleManager(foreignRunner, () => true);
        await AssertThrowsAsync<InvalidOperationException>(() => foreignManager.CreateAsync(rule, CancellationToken.None)).ConfigureAwait(false);
        AssertEqual(FakeExactRuleState.Mismatch, foreignRunner.State);
        AssertEqual(0, foreignRunner.ExactDeleteCount);
    }

    private static async Task TestConcurrentFirewallCreationAsync()
    {
        var savedRules = new List<FirewallRule>();
        var sync = new object();
        var firewall = new FakeFirewallRuleManager();
        Task<IReadOnlyList<FirewallRule>> GetRules(CancellationToken _)
        {
            lock (sync)
            {
                return Task.FromResult<IReadOnlyList<FirewallRule>>([.. savedRules]);
            }
        }

        async Task SaveRule(FirewallRule rule, CancellationToken cancellationToken)
        {
            await Task.Delay(50, cancellationToken).ConfigureAwait(false);
            lock (sync)
            {
                savedRules.Add(rule);
            }
        }

        var firstRule = SampleRule(FirewallAction.Block, SampleFlow());
        var secondRule = firstRule with { Id = Guid.NewGuid() };
        var first = new FirewallRuleCreateCoordinator(firewall, SaveRule, new ListLogger<FirewallRuleCreateCoordinator>(), GetRules);
        var second = new FirewallRuleCreateCoordinator(firewall, SaveRule, new ListLogger<FirewallRuleCreateCoordinator>(), GetRules);

        var results = await Task.WhenAll(
            first.ApplyAsync(firstRule, CancellationToken.None, failOpen: false),
            second.ApplyAsync(secondRule, CancellationToken.None, failOpen: false)).ConfigureAwait(false);

        AssertEqual(1, firewall.CreateCallCount);
        AssertEqual(1, savedRules.Count);
        AssertEqual(1, results.Count(result => result.Status == FirewallMutationStatus.Created));
        AssertEqual(1, results.Count(result => result.ExistingRuleId is not null));
    }

    private static async Task TestCompleteFirewallSemanticsMatchAsync()
    {
        var executablePath = Environment.ProcessPath ?? throw new TestFailureException("Test executable path is unavailable.");
        var rule = TestRuleForExecutable(executablePath);
        var runner = new MockFirewallSemanticsRunner(new Dictionary<string, string>
        {
            ["EG_ACTUAL_PROGRAM"] = executablePath.ToUpperInvariant(),
            ["EG_ACTUAL_REMOTE_ADDRESS"] = rule.RemoteAddress!.ToUpperInvariant(),
            ["EG_ACTUAL_PROTOCOL"] = "6",
            ["EG_ACTUAL_ENABLED"] = "true",
            ["EG_ACTUAL_PROFILE"] = "ANY"
        });
        var manager = new OwnedFirewallRuleManager(runner, () => true);

        AssertEqual(FirewallMutationStatus.Unchanged, await manager.CreateAsync(rule, CancellationToken.None).ConfigureAwait(false));
        AssertEqual(1, runner.QueryCount);
        AssertEqual(0, runner.CreateCount);
        AssertEqual(0, runner.DeleteCount);
        var description = runner.LastEnvironment?["EG_RULE_DESCRIPTION"] ?? string.Empty;
        foreach (var property in new[] { "id", "hash", "path", "action", "remoteAddress", "remotePort", "protocol", "enabled" })
        {
            AssertTrue(description.Contains($"\"{property}\"", StringComparison.Ordinal), $"Ownership description omitted {property}.");
        }
    }

    private static async Task TestCompleteFirewallSemanticsMismatchAsync()
    {
        var executablePath = Environment.ProcessPath ?? throw new TestFailureException("Test executable path is unavailable.");
        var rule = TestRuleForExecutable(executablePath);
        var cases = new (string Field, string Value)[]
        {
            ("EG_ACTUAL_REMOTE_ADDRESS", "198.51.100.2"),
            ("EG_ACTUAL_REMOTE_PORT", "10"),
            ("EG_ACTUAL_PROTOCOL", "17"),
            ("EG_ACTUAL_ENABLED", "False")
        };

        foreach (var testCase in cases)
        {
            var runner = new MockFirewallSemanticsRunner(new Dictionary<string, string> { [testCase.Field] = testCase.Value });
            var manager = new OwnedFirewallRuleManager(runner, () => true);
            var saveCount = 0;
            var coordinator = new FirewallRuleCreateCoordinator(
                manager,
                (_, _) =>
                {
                    saveCount++;
                    return Task.CompletedTask;
                },
                new ListLogger<FirewallRuleCreateCoordinator>());

            await AssertThrowsAsync<InvalidOperationException>(() =>
                coordinator.ApplyAsync(rule, CancellationToken.None, failOpen: false)).ConfigureAwait(false);
            AssertEqual(0, saveCount);
            AssertEqual(0, runner.CreateCount);
            AssertEqual(0, runner.DeleteCount);
        }
    }

    private static async Task TestControlledTcpMappingAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var listenerEndpoint = (IPEndPoint)listener.LocalEndpoint;
            using var client = new TcpClient(AddressFamily.InterNetwork);
            var acceptTask = listener.AcceptTcpClientAsync();
            await client.ConnectAsync(IPAddress.Loopback, listenerEndpoint.Port).ConfigureAwait(false);
            using var accepted = await acceptTask.ConfigureAwait(false);
            var clientEndpoint = (IPEndPoint)(client.Client.LocalEndPoint
                ?? throw new TestFailureException("Client local endpoint is unavailable."));

            var snapshot = new ConnectionSnapshotService().Capture();
            var currentPid = Environment.ProcessId;
            var match = snapshot.FirstOrDefault(item =>
                item.Connection.ProcessId == currentPid
                && item.Connection.Protocol == TransportProtocol.Tcp
                && item.Connection.LocalEndpoint.Port == clientEndpoint.Port
                && item.Connection.RemoteEndpoint?.Port == listenerEndpoint.Port);

            AssertTrue(match is not null, "The controlled TCP connection was not found in the owner-PID table.");
            AssertTrue(match!.Process is not null, "The connection PID was not joined to a process snapshot.");
            AssertEqual(currentPid, match.Process!.Identity.ProcessId);
            AssertTrue(match.Process.Identity.StartTime <= DateTimeOffset.Now, "Process start time is invalid.");
            AssertEqual(Process.GetCurrentProcess().ProcessName, match.Process.Name);
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task TestWindowsFlowSensorAsync()
    {
        var listener = new TcpListener(IPAddress.Loopback, 0);
        listener.Start();
        try
        {
            var endpoint = (IPEndPoint)listener.LocalEndpoint;
            using var client = new TcpClient(AddressFamily.InterNetwork);
            var accept = listener.AcceptTcpClientAsync();
            await client.ConnectAsync(IPAddress.Loopback, endpoint.Port).ConfigureAwait(false);
            using var accepted = await accept.ConfigureAwait(false);
            var local = (IPEndPoint)client.Client.LocalEndPoint!;
            var flow = new WindowsFlowSensor().Capture().FirstOrDefault(item =>
                item.ProcessIdentity?.ProcessId == Environment.ProcessId
                && item.LocalEndpoint.Port == local.Port
                && item.Destination?.Port == endpoint.Port);
            AssertTrue(flow is not null, "WindowsFlowSensor did not preserve the controlled connection.");
            AssertTrue(flow!.ProcessIdentity?.StartTime < DateTimeOffset.Now, "Flow process identity has no valid start time.");
            AssertEqual(IpVersion.IPv4, flow.IpVersion);
            AssertEqual(TransportProtocol.Tcp, flow.Protocol);
            AssertEqual(null, flow.BytesSent);
            AssertEqual(null, flow.BytesReceived);
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task TestControlledIPv6MappingAsync()
    {
        if (!Socket.OSSupportsIPv6)
        {
            return;
        }

        var listener = new TcpListener(IPAddress.IPv6Loopback, 0);
        listener.Start();
        try
        {
            var endpoint = (IPEndPoint)listener.LocalEndpoint;
            using var client = new TcpClient(AddressFamily.InterNetworkV6);
            var accept = listener.AcceptTcpClientAsync();
            await client.ConnectAsync(IPAddress.IPv6Loopback, endpoint.Port).ConfigureAwait(false);
            using var accepted = await accept.ConfigureAwait(false);
            var local = (IPEndPoint)client.Client.LocalEndPoint!;
            var match = NativeNetworkTableReader.Capture().FirstOrDefault(item => item.ProcessId == Environment.ProcessId && item.IpVersion == IpVersion.IPv6 && item.LocalEndpoint.Port == local.Port && item.RemoteEndpoint?.Port == endpoint.Port);
            AssertTrue(match is not null, "Controlled IPv6 connection was not found.");
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task TestControlledUdpMappingAsync()
    {
        using var server = new UdpClient(new IPEndPoint(IPAddress.Loopback, 0));
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect((IPEndPoint)server.Client.LocalEndPoint!);
        _ = await client.SendAsync(new byte[] { 1, 2, 3 }).ConfigureAwait(false);
        var local = (IPEndPoint)client.Client.LocalEndPoint!;
        var match = NativeNetworkTableReader.Capture().FirstOrDefault(item => item.ProcessId == Environment.ProcessId && item.Protocol == TransportProtocol.Udp && item.LocalEndpoint.Port == local.Port);
        AssertTrue(match is not null, "Controlled UDP endpoint was not found.");
        AssertEqual(null, match!.RemoteEndpoint);
    }

    private static Task TestRiskEngineAsync()
    {
        var engine = new RiskEngine();
        var low = Signals();
        var medium = Signals(isInTemp: true);
        var high = Signals(isInTemp: true, isUnsigned: true, isFirstSeen: true, unknownPublisher: true);
        var critical = Signals(destinationBlocked: true);
        AssertEqual(RiskLevel.Low, engine.Assess(low).Level);
        AssertEqual(RiskLevel.Medium, engine.Assess(medium).Level);
        AssertEqual(RiskLevel.High, engine.Assess(high).Level);
        AssertEqual(RiskLevel.Critical, engine.Assess(critical).Level);
        AssertEqual(80, engine.Assess(critical).Score);
        var firstHigh = engine.Assess(high);
        var secondHigh = engine.Assess(high);
        AssertEqual(firstHigh.Score, secondHigh.Score);
        AssertEqual(firstHigh.Level, secondHigh.Level);
        AssertEqual(
            string.Join(',', firstHigh.Reasons.Select(reason => reason.Code)),
            string.Join(',', secondHigh.Reasons.Select(reason => reason.Code)));
        AssertEqual(100, engine.Assess(Signals(true, true, true, true, true, true, true, true, true, true)).Score);
        return Task.CompletedTask;
    }

    private static Task TestPolicyPriorityAsync()
    {
        var flow = SampleFlow(risk: new RiskAssessment(100, RiskLevel.Critical, PolicyDecision.Block, []));
        var allow = SampleRule(FirewallAction.Allow, flow);
        var block = SampleRule(FirewallAction.Block, flow);
        var result = PolicyEngine.Evaluate(flow, ProtectionMode.Protect, [allow, block], isSystemProtected: false);
        AssertEqual(PolicyDecision.Block, result.Decision);
        AssertEqual(block.Id, result.MatchedRule?.Id);
        AssertTrue(!PolicyEngine.RuleMatches(block, flow with { Executable = flow.Executable! with { Path = "C:\\Tests\\Different.exe" } }), "A path-bound rule matched another executable.");
        var safe = PolicyEngine.Evaluate(flow, ProtectionMode.Protect, [], isSystemProtected: true);
        AssertEqual(PolicyDecision.Allow, safe.Decision);
        return Task.CompletedTask;
    }

    private static Task TestBaselineAsync()
    {
        var baseline = new BaselineTracker(3);
        var flow = SampleFlow();
        baseline.Observe(flow, wasBlocked: true, clearlyDangerous: false);
        AssertEqual(0, baseline.Assess(flow).SampleCount);
        baseline.Observe(flow, false, false);
        baseline.Observe(flow, false, false);
        AssertTrue(!baseline.Assess(flow).HasSufficientSamples, "Baseline became sufficient too early.");
        baseline.Observe(flow, false, false);
        AssertTrue(baseline.Assess(flow).HasSufficientSamples, "Baseline did not reach minimum samples.");
        var changed = flow with { Destination = new DestinationInfo(IPAddress.Parse("127.0.0.2"), 5051, null, "test") };
        AssertTrue(!baseline.Assess(changed).IsKnownDestination, "New destination was incorrectly treated as known.");
        AssertTrue(baseline.Reset(flow.Executable!.Sha256), "Per-executable reset failed.");
        AssertEqual(0, baseline.Assess(flow).SampleCount);
        return Task.CompletedTask;
    }

    private static async Task TestPersistenceAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-DbTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var database = new EgressGuardDatabase(Path.Combine(directory, "test.db"));
            await database.InitializeAsync().ConfigureAwait(false);
            await database.InitializeAsync().ConfigureAwait(false);
            var sample = SampleFlow(risk: new RiskAssessment(0, RiskLevel.Low, PolicyDecision.Allow, []));
            await database.SaveFlowsAsync([sample]).ConfigureAwait(false);
            var history = await database.GetRecentFlowsAsync(10).ConfigureAwait(false);
            AssertEqual(1, history.Count);
            AssertEqual(SampleFlow().Id, history[0].Id);
            var correlation = NewCorrelationEngine().Correlate(sample, sample.FirstSeen);
            AssertEqual(0, correlation.Count);
            var engine = NewCorrelationEngine();
            _ = engine.Add(FileEvent(sample, 10, -1, FileActivityOperation.Read, "C:\\Synthetic\\persist.txt"));
            var selected = engine.Correlate(sample, sample.FirstSeen);
            await database.SaveFileCorrelationsAsync(selected).ConfigureAwait(false);
            AssertEqual(1, (await database.GetFileCorrelationsAsync(sample.Id, 20).ConfigureAwait(false)).Count);
            await database.SaveBaselineObservationsAsync([sample]).ConfigureAwait(false);
            AssertEqual(1, (await database.GetBaselinesAsync().ConfigureAwait(false)).Count);
            await database.ResetBaselineAsync(sample.Executable!.Sha256).ConfigureAwait(false);
            AssertEqual(0, (await database.GetBaselinesAsync().ConfigureAwait(false)).Count);
            var high = sample with { Id = "high-flow", Risk = new RiskAssessment(70, RiskLevel.High, PolicyDecision.Ask, [new RiskReason("TEST_HIGH", "Synthetic high risk.", 70, "controlled")]) };
            await database.SaveAlertsAsync([high]).ConfigureAwait(false);
            AssertEqual(1, (await database.GetRecentAlertsAsync(10).ConfigureAwait(false)).Count);
            await database.SetSettingAsync("protection_mode", ProtectionMode.Protect.ToString()).ConfigureAwait(false);
            AssertEqual("Protect", await database.GetSettingAsync("protection_mode").ConfigureAwait(false));
            await database.ApplyRetentionAsync(30).ConfigureAwait(false);
            await database.ClearHistoryAsync().ConfigureAwait(false);
            AssertEqual(0, (await database.GetRecentFlowsAsync(10).ConfigureAwait(false)).Count);
            AssertEqual(0, (await database.GetFileCorrelationsAsync(sample.Id, 20).ConfigureAwait(false)).Count);
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task TestCorrelationPersistenceBatchAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-CorrelationBatch-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var database = new EgressGuardDatabase(Path.Combine(directory, "test.db"));
            await database.InitializeAsync().ConfigureAwait(false);
            var template = SampleFlow();
            var flows = Enumerable.Range(0, 10).Select(index => template with { Id = $"batch-flow-{index}" }).ToArray();
            await database.SaveFlowsAsync(flows).ConfigureAwait(false);
            var correlations = flows.SelectMany((flow, flowIndex) => Enumerable.Range(0, 20).Select(itemIndex => new FileCorrelation(
                Guid.NewGuid(), flow.Id, flow.ProcessIdentity!.Value, flow.ProcessName, FileActivityOperation.Read,
                $"protected-{flowIndex}-{itemIndex}", $"file-{flowIndex}-{itemIndex}.txt", ".txt",
                flow.FirstSeen.AddSeconds(-itemIndex / 10d), -itemIndex / 10d, CorrelationConfidence.High,
                "Same exact process identity in the configured temporal window.", flow.FirstSeen))).ToArray();
            await database.SaveFileCorrelationsAsync(correlations).ConfigureAwait(false);
            await database.SaveFileCorrelationsAsync(correlations).ConfigureAwait(false);
            foreach (var flow in flows)
            {
                AssertEqual(20, (await database.GetFileCorrelationsAsync(flow.Id, 20).ConfigureAwait(false)).Count);
            }
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task TestProtocolRoundTripAsync()
    {
        var message = MessageEnvelope.Create(MessageTypes.GetStatus, new { Request = true });
        await using var stream = new MemoryStream();
        await MessageFraming.WriteAsync(stream, message, CancellationToken.None).ConfigureAwait(false);
        stream.Position = 0;
        var result = await MessageFraming.ReadAsync(stream, CancellationToken.None).ConfigureAwait(false);
        AssertEqual(message.Type, result?.Type);
        AssertEqual(message.CorrelationId, result?.CorrelationId);
    }

    private static Task TestSimulatedDecisionProtocolRequestAndProjectionValidationAsync()
    {
        var sample = CreateSimulatedProtocolSample();
        var messageTypes = new[]
        {
            OutboundGateMessageTypes.GetSimulatedDecisionSnapshot,
            OutboundGateMessageTypes.SimulatedDecisionSnapshot,
            OutboundGateMessageTypes.SubscribeSimulatedDecisionEvents,
            OutboundGateMessageTypes.SimulatedDecisionEvent,
            OutboundGateMessageTypes.SubmitSimulatedDecision,
            OutboundGateMessageTypes.SimulatedDecisionResult,
            OutboundGateMessageTypes.RevokeSimulatedRememberedRule,
            OutboundGateMessageTypes.SimulatedRuleMutationResult
        };
        AssertEqual(8, messageTypes.Distinct(StringComparer.Ordinal).Count());
        AssertTrue(messageTypes.All(type => type.StartsWith("Phase5B.Ui.", StringComparison.Ordinal)), "A simulated-decision message type escaped the frozen namespace.");

        _ = new GetSimulatedDecisionSnapshotMessage(1);
        _ = new SubscribeSimulatedDecisionEventsMessage(1, 0);
        _ = new SubmitSimulatedDecisionMessage(1, sample.ChallengeId, SimulatedDecisionChoice.AllowOnce);
        _ = new RevokeSimulatedRememberedRuleMessage(1, sample.RuleId, 1);
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new GetSimulatedDecisionSnapshotMessage(2));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SubscribeSimulatedDecisionEventsMessage(1, -1));
        AssertThrows<ArgumentException>(() => _ = new SubmitSimulatedDecisionMessage(1, Guid.Empty, SimulatedDecisionChoice.AllowOnce));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SubmitSimulatedDecisionMessage(1, sample.ChallengeId, SimulatedDecisionChoice.Unspecified));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SubmitSimulatedDecisionMessage(1, sample.ChallengeId, (SimulatedDecisionChoice)99));
        AssertThrows<ArgumentException>(() => _ = new RevokeSimulatedRememberedRuleMessage(1, Guid.Empty, 0));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new RevokeSimulatedRememberedRuleMessage(1, sample.RuleId, -1));

        var absentDomain = new SimulatedDestinationProjection(1, IPAddress.IPv6Loopback, IpVersion.IPv6, 443, TransportProtocol.Tcp, null, DomainEvidenceProvenance.None, null);
        AssertEqual(null, absentDomain.DomainObservedAtUtc);
        var observedAt = sample.Now.ToOffset(TimeSpan.FromHours(2));
        var observedDomain = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "localhost", DomainEvidenceProvenance.DnsObservation, observedAt);
        AssertEqual(sample.Now, observedDomain.DomainObservedAtUtc);
        _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "xn--mnich-kva.example", DomainEvidenceProvenance.DnsObservation, sample.Now);
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.IPv6Loopback, IpVersion.IPv6, 443, TransportProtocol.Tcp, null, DomainEvidenceProvenance.None, sample.Now));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "localhost", DomainEvidenceProvenance.None, sample.Now));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "localhost", DomainEvidenceProvenance.DnsObservation, null));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "m\u0800nich.example", DomainEvidenceProvenance.DnsObservation, sample.Now));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "MUNICH.example", DomainEvidenceProvenance.DnsObservation, sample.Now));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "bad_label.example", DomainEvidenceProvenance.DnsObservation, sample.Now));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, $"{new string('a', 64)}.example", DomainEvidenceProvenance.DnsObservation, sample.Now));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "empty..label", DomainEvidenceProvenance.DnsObservation, sample.Now));

        AssertThrows<JsonException>(() => _ = JsonSerializer.Deserialize<GetSimulatedDecisionSnapshotMessage>("{\"version\":1,\"caller\":\"test\"}", JsonDefaults.Options));
        AssertThrows<JsonException>(() => _ = JsonSerializer.Deserialize<GetSimulatedDecisionSnapshotMessage>("{\"version\":1,\"time\":\"2026-01-01T00:00:00Z\"}", JsonDefaults.Options));
        AssertThrows<JsonException>(() => _ = JsonSerializer.Deserialize<SubscribeSimulatedDecisionEventsMessage>("{\"version\":1,\"lastSequence\":0,\"scope\":\"all\"}", JsonDefaults.Options));
        AssertThrows<JsonException>(() => _ = JsonSerializer.Deserialize<SubscribeSimulatedDecisionEventsMessage>("{\"version\":1,\"lastSequence\":0,\"decisionId\":\"00000000-0000-0000-0000-000000000001\"}", JsonDefaults.Options));
        AssertThrows<JsonException>(() => _ = JsonSerializer.Deserialize<SubmitSimulatedDecisionMessage>($"{{\"version\":1,\"challengeId\":\"{sample.ChallengeId}\",\"choice\":1,\"nonce\":\"x\"}}", JsonDefaults.Options));
        AssertThrows<JsonException>(() => _ = JsonSerializer.Deserialize<RevokeSimulatedRememberedRuleMessage>($"{{\"version\":1,\"ruleId\":\"{sample.RuleId}\",\"expectedRevision\":0,\"ticket\":\"x\",\"grant\":\"x\"}}", JsonDefaults.Options));

        AssertThrows<ArgumentException>(() => _ = new SimulatedFileVersionProjection(1, new string('v', 129), 1, sample.Now, sample.Now, null));
        AssertThrows<ArgumentException>(() => _ = new SimulatedFileVersionProjection(1, "version\u0800token", 1, sample.Now, sample.Now, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedFileVersionProjection(1, "v1", -1, sample.Now, sample.Now, null));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "C:\\secret.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report.txt", sample.File, "sha256/app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "bad@reason", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report\u0800.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, true, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "..", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionExpiryProjection(1, 15_001, sample.Now, true));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionExpiryProjection(1, 0, sample.Now, true));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionExpiryProjection(1, -1, sample.Now, false));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ClosedExpiry, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, (GateRuntimeState)99, "awaiting", null, sample.ActiveExpiry, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionPromptProjection(1, sample.ChallengeId, sample.IntentId, "report.txt", sample.File, "sha256:app", sample.ProcessSubject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting", null, sample.ActiveExpiry, -1));

        var processMembers = new List<ProcessIdentity> { sample.Process };
        var processSubject = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcess, sample.Process, null, processMembers, false, null);
        processMembers.Clear();
        AssertEqual(1, processSubject.ExactMembers.Count);
        AssertThrows<NotSupportedException>(() => ((IList<ProcessIdentity>)processSubject.ExactMembers).Clear());
        AssertThrows<ArgumentException>(() => _ = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcess, sample.Process, Guid.NewGuid(), [sample.Process], false, null));
        AssertThrows<ArgumentException>(() => _ = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcessGroup, sample.Process, sample.GroupSubject.ProcessGroupId, [sample.Process], true, SimulatedDecisionProtocolLimits.GroupCollateralWarning));
        AssertThrows<ArgumentException>(() => _ = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcessGroup, sample.Process, sample.GroupSubject.ProcessGroupId, [sample.GroupMember, sample.Process], true, SimulatedDecisionProtocolLimits.GroupCollateralWarning));
        AssertThrows<ArgumentException>(() => _ = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcessGroup, sample.Process, sample.GroupSubject.ProcessGroupId, [sample.Process, sample.GroupMember], true, "wrong warning"));
        AssertThrows<ArgumentException>(() => _ = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcessGroup, sample.Process, Guid.Empty, [sample.Process, sample.GroupMember], true, SimulatedDecisionProtocolLimits.GroupCollateralWarning));

        AssertEqual(SimulatedDecisionProtocolLimits.DecisionSubscriberCapacity, sample.Capacity.DecisionSubscriberCapacity);
        AssertEqual(SimulatedDecisionProtocolLimits.PipeInstanceCapacity, sample.Capacity.PipeInstanceCapacity);
        AssertEqual(SimulatedDecisionProtocolLimits.ReservedRequestReconnectCapacity, sample.Capacity.ReservedRequestReconnectCapacity);
        AssertEqual(SimulatedDecisionProtocolLimits.RuleIdRegistryEntryCapacity, sample.Capacity.RuleIdRegistryEntryCapacity);
        AssertEqual(8, SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount);
        AssertEqual(64, SimulatedDecisionProtocolLimits.MaximumStatusCount);
        AssertEqual(32, SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount);
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionCapacitySnapshot(3, 2, 0, 8, 0, 2, 0, 256));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionCapacitySnapshot(0, 3, 0, 8, 0, 2, 0, 256));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionCapacitySnapshot(0, 2, 0, 8, 0, 2, 257, 256));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionCounterSnapshot(-1, 0, 0, 0));

        var prompts = new List<SimulatedDecisionPromptProjection> { sample.Prompt };
        var snapshot = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, prompts, [sample.Reconnect], [sample.Rule], [sample.Status], [sample.Alert], sample.Capacity, sample.Counters);
        prompts.Clear();
        AssertEqual(1, snapshot.ActivePrompts.Count);
        AssertTrue(snapshot.ActivePrompts is IList<SimulatedDecisionPromptProjection> exposedPrompts && exposedPrompts.IsReadOnly, "Snapshot prompt collection was not read-only.");
        AssertThrows<NotSupportedException>(() => ((IList<SimulatedDecisionPromptProjection>)snapshot.ActivePrompts).Clear());
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, Enumerable.Repeat(sample.Prompt, SimulatedDecisionProtocolLimits.MaximumPromptCount + 1).ToArray(), [], [], [], [], sample.Capacity, sample.Counters));
        var sameSubjectPrompts = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject + 1)
            .Select(index => CreatePrompt(sample, sample.ProcessSubject, index, "sha256:subject-bound"))
            .ToArray();
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, sameSubjectPrompts, [], [], [], [], sample.Capacity, sample.Counters));
        var structuralSubjectCopy = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcess, sample.Process, null, [sample.Process], false, null);
        var structurallyEqualPrompts = sameSubjectPrompts
            .Take(SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject)
            .Append(CreatePrompt(sample, structuralSubjectCopy, SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject, "sha256:subject-bound"))
            .ToArray();
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, structurallyEqualPrompts, [], [], [], [], sample.Capacity, sample.Counters));
        var ordinalApplicationPrompts = sameSubjectPrompts
            .Take(SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject)
            .Append(CreatePrompt(sample, sample.ProcessSubject, SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject, "SHA256:SUBJECT-BOUND"))
            .ToArray();
        _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, ordinalApplicationPrompts, [], [], [], [], sample.Capacity, sample.Counters);
        var sameApplicationRules = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumRememberedRulesPerApplication + 1)
            .Select(index => CreateRule(sample, index, "sha256:one-application"))
            .ToArray();
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, [], [], sameApplicationRules, [], [], sample.Capacity, sample.Counters));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, [], Enumerable.Repeat(sample.Reconnect, SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount + 1).ToArray(), [], [], [], sample.Capacity, sample.Counters));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, [], [], [], Enumerable.Repeat(sample.Status, SimulatedDecisionProtocolLimits.MaximumStatusCount + 1).ToArray(), [], sample.Capacity, sample.Counters));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, [], [], [], [], Enumerable.Repeat(sample.Alert, SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount + 1).ToArray(), sample.Capacity, sample.Counters));
        return Task.CompletedTask;
    }

    private static Task TestSimulatedDecisionProtocolEventAndResultValidationAsync()
    {
        var sample = CreateSimulatedProtocolSample();
        var events = new[]
        {
            new SimulatedDecisionEventMessage(1, 1, SimulatedDecisionEventKind.PromptUpserted, sample.Prompt, null, null, null, null, null, null, false),
            new SimulatedDecisionEventMessage(1, 2, SimulatedDecisionEventKind.PromptRemoved, null, sample.ChallengeId, null, null, null, null, null, false),
            new SimulatedDecisionEventMessage(1, 3, SimulatedDecisionEventKind.ReconnectRequired, null, null, sample.Reconnect, null, null, null, null, false),
            new SimulatedDecisionEventMessage(1, 4, SimulatedDecisionEventKind.RememberedRuleUpserted, null, null, null, sample.Rule, null, null, null, false),
            new SimulatedDecisionEventMessage(1, 5, SimulatedDecisionEventKind.RememberedRuleRemoved, null, null, null, null, sample.RuleId, null, null, false),
            new SimulatedDecisionEventMessage(1, 6, SimulatedDecisionEventKind.StatusChanged, null, null, null, null, null, sample.Status, null, false),
            new SimulatedDecisionEventMessage(1, 7, SimulatedDecisionEventKind.CriticalAlertRaised, null, null, null, null, null, null, sample.Alert, false),
            new SimulatedDecisionEventMessage(1, 8, SimulatedDecisionEventKind.ResyncRequired, null, null, null, null, null, null, null, true)
        };
        AssertEqual(8, events.Length);
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionEventMessage(1, 1, SimulatedDecisionEventKind.PromptRemoved, sample.Prompt, sample.ChallengeId, null, null, null, null, null, false));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionEventMessage(1, 1, SimulatedDecisionEventKind.ResyncRequired, null, null, null, null, null, null, null, false));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionEventMessage(1, 1, (SimulatedDecisionEventKind)99, null, null, null, null, null, null, null, true));

        var outcome = sample.RuleOutcome;
        _ = new SimulatedDecisionResultMessage(1, 10, sample.ChallengeId, SimulatedDecisionChoice.AllowOnce, SimulatedDecisionItemState.AllowedOnce, "allowed-once", false, null, false, 1);
        _ = new SimulatedDecisionResultMessage(1, 11, sample.ChallengeId, SimulatedDecisionChoice.BlockCurrent, SimulatedDecisionItemState.BlockedCurrent, "blocked-current", false, null, false, 2);
        _ = new SimulatedDecisionResultMessage(1, 12, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.Remembered, "remembered", false, outcome, false, 3);
        _ = new SimulatedDecisionResultMessage(1, 13, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.FailedOpen, "ticket-failed-open", true, outcome, false, 4);
        _ = new SimulatedDecisionResultMessage(1, 14, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.AwaitingDecision, "sim-ui-rule-id-retention-capacity-exhausted", false, null, false, 5);
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionResultMessage(1, 1, sample.ChallengeId, SimulatedDecisionChoice.AllowOnce, SimulatedDecisionItemState.AllowedOnce, "allowed", false, outcome, false, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionResultMessage(1, 1, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.Remembered, "remembered", false, null, false, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionResultMessage(1, 1, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.FailedOpen, "failed", false, outcome, false, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedDecisionResultMessage(1, 1, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.Remembered, "remembered", false, new SimulatedRememberedRuleOutcome(sample.RuleId, 1, SimulatedDecisionItemState.Revoked, "revoked"), false, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedDecisionResultMessage(1, 1, sample.ChallengeId, (SimulatedDecisionChoice)99, SimulatedDecisionItemState.AllowedOnce, "allowed", false, null, false, 1));
        AssertThrows<ArgumentException>(() => _ = new SimulatedCriticalAlertProjection(1, sample.AlertId, sample.IntentId, sample.GroupSubject, "fail", sample.Now, 0, 0, true, "wrong", 1));
        _ = new SimulatedRuleMutationResultMessage(1, 15, sample.RuleId, 3, SimulatedRuleMutationKind.Revoke, SimulatedDecisionItemState.Revoked, "revoked", false, 6);
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedRuleMutationResultMessage(1, 1, sample.RuleId, 0, (SimulatedRuleMutationKind)99, SimulatedDecisionItemState.Revoked, "revoked", false, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new SimulatedRuleMutationResultMessage(1, 1, sample.RuleId, 0, SimulatedRuleMutationKind.Revoke, SimulatedDecisionItemState.Remembered, "wrong state", false, 1));
        return Task.CompletedTask;
    }

    private static Task TestSimulatedDecisionProtocolJsonRoundTripAsync()
    {
        var sample = CreateSimulatedProtocolSample();
        var snapshot = new SimulatedDecisionSnapshotMessage(1, 1, true, sample.Authorization, [sample.Prompt], [sample.Reconnect], [sample.Rule], [sample.Status], [sample.Alert], sample.Capacity, sample.Counters);
        var events = new object[]
        {
            new SimulatedDecisionEventMessage(1, 1, SimulatedDecisionEventKind.PromptUpserted, sample.Prompt, null, null, null, null, null, null, false),
            new SimulatedDecisionEventMessage(1, 2, SimulatedDecisionEventKind.ResyncRequired, null, null, null, null, null, null, null, true)
        };
        var values = new object[]
        {
            new GetSimulatedDecisionSnapshotMessage(1),
            new SubscribeSimulatedDecisionEventsMessage(1, 0),
            new SubmitSimulatedDecisionMessage(1, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days),
            new RevokeSimulatedRememberedRuleMessage(1, sample.RuleId, 3),
            sample.File,
            sample.ProcessSubject,
            sample.Destination,
            sample.ActiveExpiry,
            sample.Prompt,
            sample.Reconnect,
            sample.Rule,
            sample.Status,
            sample.Alert,
            sample.Authorization,
            sample.Capacity,
            sample.Counters,
            snapshot,
            events[0],
            events[1],
            sample.RuleOutcome,
            new SimulatedDecisionResultMessage(1, 3, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.FailedOpen, "ticket-failed-open", true, sample.RuleOutcome, false, 4),
            new SimulatedRuleMutationResultMessage(1, 4, sample.RuleId, 3, SimulatedRuleMutationKind.Revoke, SimulatedDecisionItemState.Revoked, "revoked", false, 5)
        };
        foreach (var value in values)
        {
            var json = JsonSerializer.Serialize(value, value.GetType(), JsonDefaults.Options);
            var roundTripped = JsonSerializer.Deserialize(json, value.GetType(), JsonDefaults.Options);
            AssertTrue(roundTripped is not null, $"{value.GetType().Name} did not JSON round-trip.");
            AssertEqual(json, JsonSerializer.Serialize(roundTripped, value.GetType(), JsonDefaults.Options));
        }

        var messages = new (string Type, object Payload)[]
        {
            (OutboundGateMessageTypes.GetSimulatedDecisionSnapshot, new GetSimulatedDecisionSnapshotMessage(1)),
            (OutboundGateMessageTypes.SimulatedDecisionSnapshot, snapshot),
            (OutboundGateMessageTypes.SubscribeSimulatedDecisionEvents, new SubscribeSimulatedDecisionEventsMessage(1, 0)),
            (OutboundGateMessageTypes.SimulatedDecisionEvent, events[0]),
            (OutboundGateMessageTypes.SubmitSimulatedDecision, new SubmitSimulatedDecisionMessage(1, sample.ChallengeId, SimulatedDecisionChoice.AllowOnce)),
            (OutboundGateMessageTypes.SimulatedDecisionResult, new SimulatedDecisionResultMessage(1, 3, sample.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, SimulatedDecisionItemState.FailedOpen, "ticket-failed-open", true, sample.RuleOutcome, false, 4)),
            (OutboundGateMessageTypes.RevokeSimulatedRememberedRule, new RevokeSimulatedRememberedRuleMessage(1, sample.RuleId, 3)),
            (OutboundGateMessageTypes.SimulatedRuleMutationResult, new SimulatedRuleMutationResultMessage(1, 4, sample.RuleId, 3, SimulatedRuleMutationKind.Revoke, SimulatedDecisionItemState.Revoked, "revoked", false, 5))
        };
        foreach (var (type, payload) in messages)
        {
            var envelope = MessageEnvelope.Create(type, payload, sample.CorrelationId);
            var json = JsonSerializer.Serialize(envelope, JsonDefaults.Options);
            var roundTripped = JsonSerializer.Deserialize<MessageEnvelope>(json, JsonDefaults.Options);
            AssertEqual(type, roundTripped?.Type);
            AssertEqual(sample.CorrelationId, roundTripped?.CorrelationId);
        }

        var serializedContracts = string.Join('\n', values.Select(value => JsonSerializer.Serialize(value, value.GetType(), JsonDefaults.Options)));
        foreach (var forbidden in new[] { "VolumeId", "FileId", "RawPath", "FilePath", "Content", "Payload", "Packet", "Buffer", "TicketSecret", "AuthenticatorProof", "OneTimeTicket", "EphemeralFlowGrant", "RequestedPersistentScope", "UserDecision", "Nonce", "Caller" })
            AssertTrue(!serializedContracts.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"Serialized UI contract exposed forbidden field {forbidden}.");
        return Task.CompletedTask;
    }

    private static Task TestSimulatedDecisionProtocolMaximumSnapshotAsync()
    {
        var sample = CreateSimulatedProtocolSample();
        var maximumTime = sample.Now.AddTicks(1_234_567);
        var maximumLabel = new string('l', SimulatedDecisionProtocolLimits.MaximumRedactedFileLabelLength);
        var maximumVersionToken = new string('v', OutboundGateLimits.MaximumIdentifierLength);
        var maximumDomain = MaximumCanonicalDomain();
        var maximumReason = new string('r', OutboundGateLimits.MaximumReasonLength);
        var maximumLimitation = new string('m', OutboundGateLimits.MaximumReasonLength);
        var maximumFile = new SimulatedFileVersionProjection(1, maximumVersionToken, OutboundGateLimits.MaximumFileSizeBytes, maximumTime, maximumTime, long.MaxValue);
        var maximumDestination = new SimulatedDestinationProjection(1, IPAddress.Parse("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), IpVersion.IPv6, 65535, TransportProtocol.Tcp, maximumDomain, DomainEvidenceProvenance.DnsObservation, maximumTime);
        var maximumAuthorization = new SimulatedDecisionAuthorizationProjection(false, false, false, false, false, maximumReason);
        var maximumExpiry = new SimulatedDecisionExpiryProjection(1, SimulatedDecisionProtocolLimits.MaximumDecisionRemainingMilliseconds, maximumTime, true);
        var groupSubjects = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumPromptCount / SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject)
            .Select(index => CreateMaximumGroupSubject(maximumTime, index))
            .ToArray();
        var prompts = groupSubjects
            .SelectMany((subject, groupIndex) => Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject)
                .Select(promptIndex => CreateMaximumPrompt(maximumFile, maximumDestination, subject, maximumExpiry, groupIndex * SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject + promptIndex, MaximumApplicationIdentity(groupIndex), maximumLabel, maximumReason, maximumLimitation)))
            .ToArray();
        var rules = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumRememberedRuleCount)
            .Select(index => CreateRule(maximumTime, maximumFile, maximumDestination, index, MaximumApplicationIdentity(100 + index / SimulatedDecisionProtocolLimits.MaximumRememberedRulesPerApplication), maximumLabel, maximumReason))
            .ToArray();
        var reconnectNotices = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount)
            .Select(index => new SimulatedReconnectRequiredProjection(1, StableGuid("41000000", index + 1), maximumLabel, maximumFile, MaximumApplicationIdentity(200 + index), groupSubjects[index % groupSubjects.Length], maximumDestination, maximumReason, maximumLimitation, maximumTime, index))
            .ToArray();
        var statuses = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumStatusCount)
            .Select(index => new SimulatedGateStatusProjection(1, StableGuid("51000000", index + 1), GateRuntimeState.FailedOpen, maximumReason, maximumTime, true, OutboundGateLimits.MaximumDiagnosticCounter, OutboundGateLimits.MaximumDiagnosticCounter, index))
            .ToArray();
        var alerts = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount)
            .Select(index => new SimulatedCriticalAlertProjection(1, StableGuid("61000000", index + 1), StableGuid("62000000", index + 1), groupSubjects[index % groupSubjects.Length], maximumReason, maximumTime, OutboundGateLimits.MaximumDiagnosticCounter, OutboundGateLimits.MaximumDiagnosticCounter, true, SimulatedDecisionProtocolLimits.FailOpenPresentationText, index))
            .ToArray();
        var capacity = new SimulatedDecisionCapacitySnapshot(2, 2, 8, 8, 2, 2, 256, 256);
        var snapshot = new SimulatedDecisionSnapshotMessage(1, long.MaxValue, true, maximumAuthorization, prompts, reconnectNotices, rules, statuses, alerts, capacity, new SimulatedDecisionCounterSnapshot(OutboundGateLimits.MaximumDiagnosticCounter, OutboundGateLimits.MaximumDiagnosticCounter, OutboundGateLimits.MaximumDiagnosticCounter, OutboundGateLimits.MaximumDiagnosticCounter));
        var envelope = MessageEnvelope.Create(OutboundGateMessageTypes.SimulatedDecisionSnapshot, snapshot, sample.CorrelationId);
        var serialized = JsonSerializer.SerializeToUtf8Bytes(envelope, JsonDefaults.Options);
        AssertTrue(prompts.Length == SimulatedDecisionProtocolLimits.MaximumPromptCount, "Maximum prompt snapshot was not constructed.");
        AssertTrue(rules.Length == SimulatedDecisionProtocolLimits.MaximumRememberedRuleCount, "Maximum remembered-rule snapshot was not constructed.");
        AssertEqual(SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount, reconnectNotices.Length);
        AssertEqual(SimulatedDecisionProtocolLimits.MaximumStatusCount, statuses.Length);
        AssertEqual(SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount, alerts.Length);
        const string allowedWireCharacters = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 ._():-";
        _ = new SimulatedDecisionAuthorizationProjection(true, false, false, false, false, allowedWireCharacters);
        AssertEqual(allowedWireCharacters.Length + 2, JsonSerializer.SerializeToUtf8Bytes(allowedWireCharacters, JsonDefaults.Options).Length);
        Console.WriteLine($"INFO  Phase 5B-05 maximum snapshot envelope bytes: {serialized.Length}");
        AssertEqual(898_812, serialized.Length);
        AssertTrue(serialized.Length < ProtocolConstants.MaximumMessageBytes, "Maximum simulated-decision snapshot exceeded the framing limit.");
        AssertTrue(ProtocolConstants.MaximumMessageBytes - serialized.Length >= 131_072, "Maximum simulated-decision snapshot did not retain the locked 128 KiB reserve.");
        return Task.CompletedTask;
    }

    private static SimulatedDecisionPromptProjection CreatePrompt(SimulatedProtocolSample sample, SimulatedSubjectProjection subject, int index, string applicationIdentity) =>
        new(1, StableGuid("13000000", index + 1), StableGuid("23000000", index + 1), "report.txt", sample.File, applicationIdentity, subject, sample.Destination, false, GateRuntimeState.AwaitingDecision, "awaiting-decision", "Simulation", sample.ActiveExpiry, index + 1);

    private static SimulatedDecisionPromptProjection CreateMaximumPrompt(SimulatedFileVersionProjection file, SimulatedDestinationProjection destination, SimulatedSubjectProjection subject, SimulatedDecisionExpiryProjection expiry, int index, string applicationIdentity, string label, string reason, string limitation) =>
        new(1, StableGuid("11000000", index + 1), StableGuid("12000000", index + 1), label, file, applicationIdentity, subject, destination, false, GateRuntimeState.AwaitingDecision, reason, limitation, expiry, long.MaxValue - index);

    private static SimulatedRememberedRuleProjection CreateRule(SimulatedProtocolSample sample, int index, string applicationIdentity) =>
        new(1, StableGuid("31000000", index + 1), "report.txt", sample.File, applicationIdentity, sample.Destination, sample.Now, sample.Now.AddDays(30).AddSeconds(index), SimulatedDecisionItemState.Remembered, "remembered", index + 1);

    private static SimulatedRememberedRuleProjection CreateRule(DateTimeOffset now, SimulatedFileVersionProjection file, SimulatedDestinationProjection destination, int index, string applicationIdentity, string label, string reason) =>
        new(1, StableGuid("31000000", index + 1), label, file, applicationIdentity, destination, now, now.AddDays(30).AddSeconds(index), SimulatedDecisionItemState.Remembered, reason, long.MaxValue - index);

    private static SimulatedSubjectProjection CreateMaximumGroupSubject(DateTimeOffset now, int index)
    {
        var members = Enumerable.Range(0, SimulatedDecisionProtocolLimits.MaximumGroupMembers)
            .Select(memberIndex => new ProcessIdentity(1_000_000_000 + index * SimulatedDecisionProtocolLimits.MaximumGroupMembers + memberIndex, now.AddSeconds(index * 60 + memberIndex)))
            .ToArray();
        return new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcessGroup, members[0], StableGuid("71000000", index + 1), members, true, SimulatedDecisionProtocolLimits.GroupCollateralWarning);
    }

    private static Guid StableGuid(string prefix, int value) => Guid.Parse($"{prefix}-0000-0000-0000-{value:D12}");

    private static string MaximumApplicationIdentity(int value)
    {
        var prefix = $"app-{value:D4}-";
        return prefix + new string('a', OutboundGateLimits.MaximumIdentifierLength - prefix.Length);
    }

    private static string MaximumCanonicalDomain() => string.Join('.', new string('d', 63), new string('d', 63), new string('d', 63), new string('d', 61));

    private static SimulatedProtocolSample CreateSimulatedProtocolSample()
    {
        var now = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var process = new ProcessIdentity(42, now);
        var groupMember = new ProcessIdentity(43, now.AddSeconds(1));
        var processSubject = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcess, process, null, [process], false, null);
        var groupSubject = new SimulatedSubjectProjection(1, SimulatedDecisionSubjectKind.ExactProcessGroup, process, Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), [process, groupMember], true, SimulatedDecisionProtocolLimits.GroupCollateralWarning);
        var file = new SimulatedFileVersionProjection(1, "version-token-1", 512, now, now.AddSeconds(1), 7);
        var destination = new SimulatedDestinationProjection(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, "localhost", DomainEvidenceProvenance.DnsObservation, now);
        var activeExpiry = new SimulatedDecisionExpiryProjection(1, 15_000, now, true);
        var closedExpiry = new SimulatedDecisionExpiryProjection(1, 0, now, false);
        var prompt = new SimulatedDecisionPromptProjection(1, Guid.Parse("10000000-0000-0000-0000-000000000001"), Guid.Parse("20000000-0000-0000-0000-000000000002"), "report.txt", file, "sha256:application", processSubject, destination, false, GateRuntimeState.AwaitingDecision, "awaiting-decision", "Simulation", activeExpiry, 1);
        var reconnect = new SimulatedReconnectRequiredProjection(1, prompt.IntentId, "report.txt", file, "sha256:application", processSubject, destination, "reconnect-required", "Simulation", now, 2);
        var rule = new SimulatedRememberedRuleProjection(1, Guid.Parse("30000000-0000-0000-0000-000000000003"), "report.txt", file, "sha256:application", destination, now, now.AddDays(30), SimulatedDecisionItemState.Remembered, "remembered", 3);
        var status = new SimulatedGateStatusProjection(1, prompt.IntentId, GateRuntimeState.FailedOpen, "ticket-failed-open", now, true, 0, 0, 4);
        var alert = new SimulatedCriticalAlertProjection(1, Guid.Parse("40000000-0000-0000-0000-000000000004"), prompt.IntentId, groupSubject, "ticket-failed-open", now, 0, 0, true, SimulatedDecisionProtocolLimits.FailOpenPresentationText, 5);
        var authorization = new SimulatedDecisionAuthorizationProjection(true, true, true, true, true, "authorized");
        var capacity = new SimulatedDecisionCapacitySnapshot(0, 2, 0, 8, 0, 2, 0, 256);
        var counters = new SimulatedDecisionCounterSnapshot(0, 0, 0, 0);
        var outcome = new SimulatedRememberedRuleOutcome(rule.RuleId, rule.Revision, SimulatedDecisionItemState.Remembered, "remembered");
        return new SimulatedProtocolSample(now, process, groupMember, groupSubject, file, destination, activeExpiry, closedExpiry, prompt, reconnect, rule, status, alert, authorization, capacity, counters, outcome, prompt.ChallengeId, prompt.IntentId, rule.RuleId, alert.AlertId, Guid.Parse("50000000-0000-0000-0000-000000000005"));
    }

    private sealed record SimulatedProtocolSample(
        DateTimeOffset Now,
        ProcessIdentity Process,
        ProcessIdentity GroupMember,
        SimulatedSubjectProjection GroupSubject,
        SimulatedFileVersionProjection File,
        SimulatedDestinationProjection Destination,
        SimulatedDecisionExpiryProjection ActiveExpiry,
        SimulatedDecisionExpiryProjection ClosedExpiry,
        SimulatedDecisionPromptProjection Prompt,
        SimulatedReconnectRequiredProjection Reconnect,
        SimulatedRememberedRuleProjection Rule,
        SimulatedGateStatusProjection Status,
        SimulatedCriticalAlertProjection Alert,
        SimulatedDecisionAuthorizationProjection Authorization,
        SimulatedDecisionCapacitySnapshot Capacity,
        SimulatedDecisionCounterSnapshot Counters,
        SimulatedRememberedRuleOutcome RuleOutcome,
        Guid ChallengeId,
        Guid IntentId,
        Guid RuleId,
        Guid AlertId,
        Guid CorrelationId)
    {
        public SimulatedSubjectProjection ProcessSubject => Prompt.Subject;
    }

    private static Task TestOutboundGateContractRoundTripAsync()
    {
        var sample = OutboundGateSamples();
        var values = new object[]
        {
            sample.ReadWindow.StartedAt,
            sample.ReadWindow,
            sample.Coverage,
            sample.File,
            sample.Subject,
            sample.Destination,
            sample.Intent,
            sample.Request,
            sample.Ack,
            sample.Disposition,
            sample.Completion,
            sample.Challenge,
            sample.PersistentScope,
            sample.Decision,
            sample.Ticket,
            sample.Grant,
            sample.AffectedScope,
            sample.Status,
            sample.CriticalAlert
        };

        foreach (var value in values)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(value, value.GetType(), JsonDefaults.Options);
            var roundTripped = System.Text.Json.JsonSerializer.Deserialize(json, value.GetType(), JsonDefaults.Options);
            AssertTrue(roundTripped is not null, $"Contract {value.GetType().Name} did not deserialize.");
            var secondJson = System.Text.Json.JsonSerializer.Serialize(roundTripped, value.GetType(), JsonDefaults.Options);
            AssertEqual(json, secondJson);
        }

        var wrappers = new (string Type, object Wrapper)[]
        {
            (OutboundGateMessageTypes.FileReadIntent, new FileReadIntentMessage(sample.Intent)),
            (OutboundGateMessageTypes.GateArmRequest, new GateArmRequestMessage(sample.Request)),
            (OutboundGateMessageTypes.GateArmAck, new GateArmAckMessage(sample.Ack)),
            (OutboundGateMessageTypes.FileReadDisposition, new FileReadDispositionMessage(sample.Disposition)),
            (OutboundGateMessageTypes.FileReadCompletionAck, new FileReadCompletionAckMessage(sample.Completion)),
            (OutboundGateMessageTypes.NetworkGateChallenge, new NetworkGateChallengeMessage(sample.Challenge)),
            (OutboundGateMessageTypes.UserDecision, new UserDecisionMessage(sample.Decision)),
            (OutboundGateMessageTypes.OneTimeTicket, new OneTimeTicketMessage(sample.Ticket)),
            (OutboundGateMessageTypes.EphemeralFlowGrant, new EphemeralFlowGrantMessage(sample.Grant)),
            (OutboundGateMessageTypes.GateStatus, new GateStatusMessage(sample.Status)),
            (OutboundGateMessageTypes.CriticalAlert, new CriticalAlertMessage(sample.CriticalAlert))
        };
        foreach (var (type, wrapper) in wrappers)
        {
            var wrapperJson = System.Text.Json.JsonSerializer.Serialize(wrapper, wrapper.GetType(), JsonDefaults.Options);
            var roundTripped = System.Text.Json.JsonSerializer.Deserialize(wrapperJson, wrapper.GetType(), JsonDefaults.Options);
            AssertTrue(roundTripped is not null, $"{wrapper.GetType().Name} did not deserialize.");
            AssertEqual(wrapperJson, System.Text.Json.JsonSerializer.Serialize(roundTripped, wrapper.GetType(), JsonDefaults.Options));

            var wrappedEnvelope = MessageEnvelope.Create(type, wrapper);
            var envelopeJson = System.Text.Json.JsonSerializer.Serialize(wrappedEnvelope, JsonDefaults.Options);
            var envelopeRoundTrip = System.Text.Json.JsonSerializer.Deserialize<MessageEnvelope>(envelopeJson, JsonDefaults.Options);
            AssertEqual(type, envelopeRoundTrip?.Type);
        }

        var envelope = MessageEnvelope.Create(OutboundGateMessageTypes.GateArmRequest, new GateArmRequestMessage(sample.Request));
        var payload = envelope.ReadPayload<GateArmRequestMessage>();
        AssertEqual(sample.Request.IntentId, payload.Request.IntentId);
        AssertEqual(sample.Request.Subject.ProcessIdentity, payload.Request.Subject.ProcessIdentity);
        AssertEqual(sample.Request.RequestNonce, payload.Request.RequestNonce);
        var destinationJson = System.Text.Json.JsonSerializer.Serialize(sample.Destination, JsonDefaults.Options);
        var destinationRoundTrip = System.Text.Json.JsonSerializer.Deserialize<DestinationBinding>(destinationJson, JsonDefaults.Options);
        AssertEqual(sample.Destination, destinationRoundTrip);
        AssertEqual(NetworkTrafficDirection.Outbound, destinationRoundTrip?.Direction);
        AssertEqual((uint?)12, destinationRoundTrip?.NetworkCompartmentId);
        AssertEqual((ulong?)34, destinationRoundTrip?.InterfaceLuid);
        var ackJson = System.Text.Json.JsonSerializer.Serialize(sample.Ack, JsonDefaults.Options);
        AssertTrue(!ackJson.Contains("ServiceAcknowledgedAt", StringComparison.Ordinal), "Wire Ack exposed a self-declared authoritative acknowledgement time.");
        AssertTrue(!ackJson.Contains("ServiceReceivedAt", StringComparison.Ordinal), "Wire Ack exposed service-owned receipt metadata.");
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateMonotonicValidationAsync()
    {
        var sample = OutboundGateSamples();
        _ = ServiceRange(sample.Clock, 0, 2_000);
        _ = ServiceRange(sample.Clock, 0, 15_000);
        _ = ServiceRange(sample.Clock, 0, 5_000);
        _ = ServiceRange(sample.Clock, 0, 300_000);
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileReadIntent(1, Guid.NewGuid(), sample.Subject, sample.File, FileActivityOperation.Read, sample.Start, ServiceRange(sample.Clock, 0, 2_001), sample.Boot, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new NetworkGateChallenge(1, Guid.NewGuid(), Guid.NewGuid(), sample.Subject, sample.Destination, 1, false, sample.Coverage, sample.Start, ServiceRange(sample.Clock, 0, 15_001), null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new OneTimeTicket(1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), sample.Subject, sample.File, sample.Destination, 1, 1, sample.Boot, sample.Start, sample.Start.AddSeconds(5), ServiceRange(sample.Clock, 0, 5_001), 1, 1, [1]));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new OneTimeTicket(1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), sample.Subject, sample.File, sample.Destination, 1, 1, sample.Boot, sample.Start, sample.Start.AddSeconds(5), sample.Ticket.ValidityWindow, OutboundGateLimits.MaximumGrantBytes + 1, 1, [1]));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new EphemeralFlowGrant(1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), sample.Subject, sample.Destination, 1, 1, sample.Boot, 1, ServiceRange(sample.Clock, 0, 300_001)));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new EphemeralFlowGrant(1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), sample.Subject, sample.Destination, 1, 1, sample.Boot, OutboundGateLimits.MaximumGrantBytes + 1, sample.Grant.GrantWindow));

        AssertThrows<ArgumentException>(() => _ = new GateArmAck(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Subject, sample.Coverage, sample.Coverage, 7, Guid.Empty, sample.Request.RequestNonce, Guid.NewGuid(), sample.Start, sample.ReadWindow, null));

        var serviceReceipt = new ServiceMonotonicTimestamp(1, sample.Clock, 1_500);
        sample.Ack.ValidateFor(sample.Request, serviceReceipt);
        AssertThrows<InvalidOperationException>(() => sample.Ack.ValidateFor(sample.Request, new ServiceMonotonicTimestamp(1, sample.Clock, sample.ReadWindow.Deadline.ElapsedMilliseconds + 1)));
        AssertThrows<InvalidOperationException>(() => sample.Ack.ValidateFor(sample.Request, new ServiceMonotonicTimestamp(1, sample.Clock, sample.ReadWindow.StartedAt.ElapsedMilliseconds - 1)));
        AssertThrows<InvalidOperationException>(() => sample.Ack.ValidateFor(sample.Request, new ServiceMonotonicTimestamp(1, Guid.NewGuid(), 1_500)));

        var oldEndpointAuditAck = new GateArmAck(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Subject, sample.Coverage, sample.Coverage, 7, sample.DriverGeneration, sample.Request.RequestNonce, Guid.NewGuid(), sample.Start.AddYears(-20), sample.ReadWindow, null);
        AssertThrows<InvalidOperationException>(() => oldEndpointAuditAck.ValidateFor(sample.Request, new ServiceMonotonicTimestamp(1, sample.Clock, sample.ReadWindow.Deadline.ElapsedMilliseconds + 1)));
        var wrongGenerationAck = new GateArmAck(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Subject, sample.Coverage, sample.Coverage, 7, Guid.NewGuid(), sample.Request.RequestNonce, Guid.NewGuid(), sample.Start, sample.ReadWindow, null);
        AssertThrows<InvalidOperationException>(() => wrongGenerationAck.ValidateFor(sample.Request, serviceReceipt));
        AssertThrows<ArgumentException>(() => _ = new FileReadCompletionAck(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Process, sample.File, sample.Disposition.Sequence, sample.Disposition.Disposition, sample.Disposition.GateAckId, FileReadCompletionResult.Released, "read-released", 3, Guid.Empty));
        AssertTrue(sample.Completion.IsBoundTo(sample.Disposition, sample.MinifilterGeneration), "Completion did not retain exact disposition and minifilter-generation binding.");
        AssertTrue(!sample.Completion.IsBoundTo(sample.Disposition, Guid.NewGuid()), "Completion accepted the wrong minifilter generation.");
        var completionMachine = CreateOutboundGateMachine(sample, new TestMonotonicClock(sample.ReadWindow.StartedAt), new TestNonceProvider());
        var completionNonces = new TestNonceProvider();
        var completionRequest = completionMachine.ReceiveIntent(sample.Intent).ArmRequest!;
        var completionAck = new GateArmAck(1, completionNonces.NextNonce(), sample.Intent.IntentId, sample.Subject, completionRequest.RequiredCoverage, completionRequest.RequiredCoverage, 7, completionRequest.DriverGeneration, completionRequest.RequestNonce, completionNonces.NextNonce(), sample.Start, completionRequest.ArmWindow, null);
        completionMachine.ReceiveGateArmAck(completionAck);
        var completionDisposition = completionMachine.ReleaseAfterGateArmed(sample.Intent.IntentId).Disposition!;
        var completionValue = new FileReadCompletionAck(1, completionNonces.NextNonce(), sample.Intent.IntentId, sample.Process, sample.File, completionDisposition.Sequence, completionDisposition.Disposition, completionDisposition.GateAckId, FileReadCompletionResult.Released, "released", 1, Guid.NewGuid());
        var rejectedCompletion = completionMachine.AcceptCompletion(completionValue);
        AssertEqual(GateRuntimeState.FailedOpen, rejectedCompletion.Status.State);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateDecisionValidationAsync()
    {
        var sample = OutboundGateSamples();
        _ = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.AlwaysAllow, sample.PersistentScope, sample.Start, "interactive-user");
        sample.Decision.ValidatePersistentScopeFor(sample.Challenge, sample.File);
        AssertThrows<ArgumentException>(() => _ = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.AlwaysAllow, null, sample.Start, "interactive-user"));
        AssertThrows<ArgumentException>(() => _ = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.AllowOnce, sample.PersistentScope, sample.Start, "interactive-user"));
        AssertThrows<ArgumentException>(() => _ = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.Block, sample.PersistentScope, sample.Start, "interactive-user"));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new RequestedPersistentScope(1, (PersistentAllowPolicyKind)1, sample.File, sample.Subject.ApplicationIdentity, sample.Destination));
        var wrongApplicationScope = new RequestedPersistentScope(1, PersistentAllowPolicyKind.RememberFor30Days, sample.File, "sha256:different-application", sample.Destination);
        var wrongScopeDecision = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.AlwaysAllow, wrongApplicationScope, sample.Start, "interactive-user");
        AssertThrows<InvalidOperationException>(() => wrongScopeDecision.ValidatePersistentScopeFor(sample.Challenge, sample.File));

        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileReadDisposition(1, sample.Intent.IntentId, sample.Process, sample.File, (FileReadDispositionKind)99, null, sample.ReadWindow, "invalid", 2));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileReadDisposition(1, sample.Intent.IntentId, sample.Process, sample.File, FileReadDispositionKind.ReleaseAfterGateArmed, null, sample.ReadWindow, "missing-ack", 2));
        AssertThrows<ArgumentException>(() => _ = new FileReadDisposition(1, sample.Intent.IntentId, sample.Process, sample.File, FileReadDispositionKind.ReleaseAfterGateArmed, Guid.Empty, sample.ReadWindow, "empty-ack", 2));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileReadDisposition(1, sample.Intent.IntentId, sample.Process, sample.File, FileReadDispositionKind.FailOpenRelease, sample.Ack.AckId, sample.ReadWindow, "unexpected-ack", 2));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileReadDisposition(1, sample.Intent.IntentId, sample.Process, sample.File, FileReadDispositionKind.Cancel, sample.Ack.AckId, sample.ReadWindow, "unexpected-ack", 2));
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateNetworkScopeAsync()
    {
        var sample = OutboundGateSamples();
        var absentEvidence = new DestinationBinding(1, IPAddress.IPv6Loopback, IpVersion.IPv6, 443, TransportProtocol.Udp, NetworkTrafficDirection.Outbound, null, null, null, DomainEvidenceProvenance.None, null);
        AssertEqual(null, absentEvidence.NetworkCompartmentId);
        AssertEqual(null, absentEvidence.InterfaceLuid);
        var absentRoundTrip = System.Text.Json.JsonSerializer.Deserialize<DestinationBinding>(System.Text.Json.JsonSerializer.Serialize(absentEvidence, JsonDefaults.Options), JsonDefaults.Options);
        AssertEqual(absentEvidence, absentRoundTrip);

        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 443, TransportProtocol.Tcp, NetworkTrafficDirection.Unspecified, null, null, null, DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 443, TransportProtocol.Tcp, NetworkTrafficDirection.Inbound, null, null, null, DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 443, TransportProtocol.Tcp, (NetworkTrafficDirection)99, null, null, null, DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 443, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, 0, null, null, DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 443, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, null, 0, null, DomainEvidenceProvenance.None, null));

        var differentCompartment = new DestinationBinding(1, sample.Destination.Address, sample.Destination.IpVersion, sample.Destination.RemotePort, sample.Destination.Protocol, NetworkTrafficDirection.Outbound, 13, sample.Destination.InterfaceLuid, sample.Destination.DomainEvidence, sample.Destination.DomainProvenance, sample.Destination.DomainObservedAtUtc);
        var differentInterface = new DestinationBinding(1, sample.Destination.Address, sample.Destination.IpVersion, sample.Destination.RemotePort, sample.Destination.Protocol, NetworkTrafficDirection.Outbound, sample.Destination.NetworkCompartmentId, 35, sample.Destination.DomainEvidence, sample.Destination.DomainProvenance, sample.Destination.DomainObservedAtUtc);
        AssertTrue(sample.Destination != differentCompartment, "Destination equality ignored network compartment evidence.");
        AssertTrue(sample.Destination != differentInterface, "Destination equality ignored interface evidence.");

        var wrongNetworkScope = new RequestedPersistentScope(1, PersistentAllowPolicyKind.RememberFor30Days, sample.File, sample.Subject.ApplicationIdentity, differentCompartment);
        var wrongNetworkDecision = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.AlwaysAllow, wrongNetworkScope, sample.Start, "interactive-user");
        AssertThrows<InvalidOperationException>(() => wrongNetworkDecision.ValidatePersistentScopeFor(sample.Challenge, sample.File));
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateContractValidationAsync()
    {
        var sample = OutboundGateSamples();
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new GateCoverage(1, (GateCoverageFlags)(1 << 5)));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new GateCoverage(2, GateCoverageFlags.NewTcp));
        AssertThrows<ArgumentException>(() => _ = new GateSubject(1, new ProcessIdentity(0, sample.Start), "sha256:app", null, [new ProcessIdentity(0, sample.Start)]));
        AssertThrows<ArgumentException>(() => _ = new GateSubject(1, sample.Process, null!, null, [sample.Process]));
        AssertThrows<ArgumentException>(() => _ = new GateSubject(1, sample.Process, new string('x', OutboundGateLimits.MaximumIdentifierLength + 1), null, [sample.Process]));
        AssertThrows<ArgumentException>(() => _ = new GateSubject(1, sample.Process, "C:\\not-an-identity", null, [sample.Process]));
        AssertThrows<ArgumentException>(() => _ = new GateSubject(1, sample.Process, "sha256:app", Guid.NewGuid(), Enumerable.Repeat(sample.Process, OutboundGateLimits.MaximumGroupMembers + 1).ToArray()));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileVersionIdentity(1, "volume", "file", sample.Start, 1, sample.Start, sample.Start, -1, "token"));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv6, 443, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, null, null, null, DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, IPAddress.IPv6Loopback, IpVersion.IPv6, 443, (TransportProtocol)99, NetworkTrafficDirection.Outbound, null, null, null, DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentException>(() => _ = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 443, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, null, null, "example.test", DomainEvidenceProvenance.None, null));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new FileReadIntent(1, Guid.NewGuid(), sample.Subject, sample.File, FileActivityOperation.Write, sample.Start, sample.ReadWindow, sample.Boot, 1));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new GateArmRequest(1, Guid.NewGuid(), sample.Subject, new GateCoverage(1, GateCoverageFlags.None), 1, sample.DriverGeneration, Guid.NewGuid(), sample.Start, sample.ReadWindow));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new OneTimeTicket(1, Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid(), sample.Subject, sample.File, sample.Destination, 1, 1, sample.Boot, sample.Start, sample.Start, sample.Ticket.ValidityWindow, 1, 1, [1]));
        AssertThrows<ArgumentException>(() => _ = new GateAffectedScope(1, GateAffectedScopeKind.Intent, Guid.Empty, sample.Subject));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new GateStatus(1, OutboundGateMode.Simulation, GateRuntimeState.FailedOpen, sample.Coverage, "overflow", sample.AffectedScope, sample.Start, sample.Status.ServiceObservedAt, -1, 0, true));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new CriticalAlert(1, Guid.NewGuid(), "overflow", sample.AffectedScope, sample.Start, sample.Status.ServiceObservedAt, 0, OutboundGateLimits.MaximumDiagnosticCounter + 1, true));
        AssertThrows<ArgumentException>(() => _ = new GateStatus(1, OutboundGateMode.Simulation, GateRuntimeState.Armed, sample.Coverage, "inconsistent-fail-open", sample.AffectedScope, sample.Start, sample.Status.ServiceObservedAt, 0, 0, true));

        var partial = new GateArmAck(1, sample.Ack.AckId, sample.Ack.IntentId, sample.Ack.Subject, sample.Ack.RequiredCoverage, new GateCoverage(1, GateCoverageFlags.NewTcp), sample.Ack.PolicyEpoch, sample.Ack.DriverGeneration, sample.Ack.RequestNonce, sample.Ack.AckNonce, sample.Ack.EndpointAcknowledgedAtUtc, sample.Ack.ArmWindow, "unsupported existing coverage");
        AssertThrows<InvalidOperationException>(() => partial.ValidateFor(sample.Request, new ServiceMonotonicTimestamp(1, sample.Clock, 1_500)));
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateContractCompatibilityAsync()
    {
        var sample = OutboundGateSamples();
        var contracts = new object[]
        {
            sample.ReadWindow.StartedAt, sample.ReadWindow, sample.Coverage, sample.File, sample.Subject,
            sample.Destination, sample.Intent, sample.Request, sample.Ack, sample.Disposition, sample.Completion,
            sample.Challenge, sample.PersistentScope, sample.Decision, sample.Ticket, sample.Grant,
            sample.AffectedScope, sample.Status, sample.CriticalAlert,
            new CriticalAlertMessage(sample.CriticalAlert)
        };
        foreach (var contract in contracts)
        {
            var json = System.Text.Json.JsonSerializer.Serialize(contract, contract.GetType(), JsonDefaults.Options);
            foreach (var forbidden in new[] { "RawPath", "FileContent", "PacketPayload", "ContentHash", "TicketSecret" })
                AssertTrue(!json.Contains(forbidden, StringComparison.OrdinalIgnoreCase), $"Sensitive contract field name {forbidden} was exposed by {contract.GetType().Name}.");
        }

        var decision = new UserDecision(1, Guid.NewGuid(), sample.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start.AddYears(20), "interactive-user");
        AssertEqual(UserDecisionKind.AllowOnce, decision.Decision);
        AssertTrue(decision.UiTimestampUtc > DateTimeOffset.UtcNow.AddYears(10), "UI audit timestamp fixture was not retained as metadata.");
        AssertEqual(OutboundGateMode.Disabled, default(OutboundGateMode));

        var legacy = MessageEnvelope.Create(MessageTypes.GetStatus, new { Request = true });
        AssertEqual(MessageTypes.GetStatus, legacy.Type);
        AssertEqual(ProtocolConstants.Version, legacy.Version);
        AssertTrue(!System.Text.Json.JsonSerializer.Serialize(legacy, JsonDefaults.Options).Contains("Phase5B", StringComparison.Ordinal), "Legacy protocol message was changed by the new vocabulary.");
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateTrustedGenerationsAsync()
    {
        var sample = OutboundGateSamples();
        var forgedClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var forgedNonces = new TestNonceProvider();
        var forgedMachine = CreateOutboundGateMachine(sample, forgedClock, forgedNonces);
        var forgedRequest = forgedMachine.ReceiveIntent(sample.Intent).ArmRequest!;
        AssertEqual(sample.DriverGeneration, forgedRequest.DriverGeneration);
        var forgedAck = new GateArmAck(1, forgedNonces.NextNonce(), sample.Intent.IntentId, sample.Subject, forgedRequest.RequiredCoverage, forgedRequest.RequiredCoverage, 7, Guid.NewGuid(), forgedRequest.RequestNonce, forgedNonces.NextNonce(), sample.Start, forgedRequest.ArmWindow, null);
        AssertEqual(GateRuntimeState.FailedOpen, forgedMachine.ReceiveGateArmAck(forgedAck).Status.State);

        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces);
        var prepared = PrepareToChallenge(machine, sample, clock, nonces);
        var issued = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start.AddYears(20), "test"));
        var redeemed = machine.RedeemTicket(issued.Ticket!);
        AssertEqual(GateRuntimeState.Granted, redeemed.Status.State);
        AssertTrue(redeemed.Grant is not null, "Trusted endpoint generations did not complete the happy path.");

        var disabled = new OutboundGateStateMachine(new TestMonotonicClock(sample.ReadWindow.StartedAt), new TestNonceProvider(), new TestAuditClock(sample.Start));
        AssertEqual(GateRuntimeState.Unsupported, disabled.ReceiveIntent(sample.Intent).Status.State);
        AssertThrows<ArgumentNullException>(() => _ = new OutboundGateStateMachine(clock, nonces, null!, OutboundGateMode.Simulation, 7));
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateCompletionGenerationAsync()
    {
        var sample = OutboundGateSamples();
        AssertEqual(1, typeof(OutboundGateStateMachine).GetMethods().Count(method => method.Name == nameof(OutboundGateStateMachine.AcceptCompletion)));

        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces);
        var prepared = PrepareToDisposition(machine, sample, nonces);
        var forged = CompletionFor(sample, prepared.Disposition, nonces, Guid.NewGuid());
        var failed = machine.AcceptCompletion(forged);
        AssertEqual(GateRuntimeState.FailedOpen, failed.Status.State);
        AssertThrows<InvalidOperationException>(() => machine.AcceptCompletion(CompletionFor(sample, prepared.Disposition, nonces, sample.MinifilterGeneration)));

        var validClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var validNonces = new TestNonceProvider();
        var validMachine = CreateOutboundGateMachine(sample, validClock, validNonces);
        var validPrepared = PrepareToDisposition(validMachine, sample, validNonces);
        AssertEqual(GateRuntimeState.Armed, validMachine.AcceptCompletion(CompletionFor(sample, validPrepared.Disposition, validNonces, sample.MinifilterGeneration)).Status.State);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateTerminalInvariantAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces);
        var request = machine.ReceiveIntent(sample.Intent).ArmRequest!;
        var partial = new GateArmAck(1, nonces.NextNonce(), sample.Intent.IntentId, sample.Subject, request.RequiredCoverage, new GateCoverage(1, GateCoverageFlags.NewTcp), 7, request.DriverGeneration, request.RequestNonce, nonces.NextNonce(), sample.Start, request.ArmWindow, "partial");
        var failed = machine.ReceiveGateArmAck(partial);
        AssertEqual(GateRuntimeState.FailedOpen, failed.Status.State);
        var counters = machine.Counters;
        var alerts = machine.CriticalAlerts.Count;
        AssertThrows<InvalidOperationException>(() => machine.ReleaseAfterGateArmed(sample.Intent.IntentId));
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallenge(sample.Challenge));
        var duplicate = machine.ReceiveIntent(CloneIntent(sample.Intent));
        AssertTrue(duplicate.IsDuplicate, "Exact terminal intent replay was not idempotent.");
        AssertEqual(GateRuntimeState.FailedOpen, duplicate.Status.State);
        AssertTrue(duplicate.ArmRequest is null && duplicate.Challenge is null && duplicate.Ticket is null && duplicate.Grant is null, "Terminal replay exposed an active capability.");
        AssertEqual(counters, machine.Counters);
        AssertEqual(alerts, machine.CriticalAlerts.Count);
        AssertThrows<InvalidOperationException>(() => machine.ReceiveIntent(IntentFor(sample, sample.Intent.IntentId, sample.Subject, 99)));

        var blockClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var blockNonces = new TestNonceProvider();
        var blockMachine = CreateOutboundGateMachine(sample, blockClock, blockNonces);
        var challenged = PrepareToChallenge(blockMachine, sample, blockClock, blockNonces);
        var decision = new UserDecision(1, blockNonces.NextNonce(), challenged.Challenge.ChallengeId, UserDecisionKind.Block, null, sample.Start, "test");
        AssertEqual(GateRuntimeState.Blocked, blockMachine.ReceiveDecision(decision).Status.State);
        AssertThrows<InvalidOperationException>(() => blockMachine.ReceiveDecision(decision));
        AssertThrows<InvalidOperationException>(() => blockMachine.ReceiveChallenge(challenged.Challenge));
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateRestartInvalidationAsync()
    {
        var sample = OutboundGateSamples();
        var ticketClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var ticketNonces = new TestNonceProvider();
        var ticketMachine = CreateOutboundGateMachine(sample, ticketClock, ticketNonces);
        var challenged = PrepareToChallenge(ticketMachine, sample, ticketClock, ticketNonces);
        var issued = ticketMachine.ReceiveDecision(new UserDecision(1, ticketNonces.NextNonce(), challenged.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test"));
        var newBoot = Guid.NewGuid();
        AssertEqual(GateRuntimeState.FailedOpen, ticketMachine.HandleServiceRestart(newBoot).Single().State);
        AssertEqual(newBoot, ticketMachine.TrustedRuntime!.BootInstance);
        AssertThrows<InvalidOperationException>(() => ticketMachine.RedeemTicket(issued.Ticket!));

        var grantClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var grantNonces = new TestNonceProvider();
        var grantMachine = CreateOutboundGateMachine(sample, grantClock, grantNonces);
        var grantChallenge = PrepareToChallenge(grantMachine, sample, grantClock, grantNonces);
        var grantTicket = grantMachine.ReceiveDecision(new UserDecision(1, grantNonces.NextNonce(), grantChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        AssertEqual(GateRuntimeState.Granted, grantMachine.RedeemTicket(grantTicket).Status.State);
        var restarted = grantMachine.HandleServiceRestart(new OutboundGateTrustedRuntimeState(Guid.NewGuid(), Guid.NewGuid(), Guid.NewGuid()));
        AssertEqual(GateRuntimeState.Blocked, restarted.Single().State);
        AssertThrows<InvalidOperationException>(() => grantMachine.RedeemTicket(grantTicket));
        AssertTrue(grantMachine.ReceiveIntent(sample.Intent).Grant is null, "Restarted terminal history retained a grant capability.");
        return Task.CompletedTask;
    }

    private static Task TestOutboundGatePolicyAndGrantExpiryAsync()
    {
        var sample = OutboundGateSamples();
        var ticketClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var ticketNonces = new TestNonceProvider();
        var ticketMachine = CreateOutboundGateMachine(sample, ticketClock, ticketNonces);
        var challenged = PrepareToChallenge(ticketMachine, sample, ticketClock, ticketNonces);
        var ticket = ticketMachine.ReceiveDecision(new UserDecision(1, ticketNonces.NextNonce(), challenged.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        AssertEqual(GateRuntimeState.FailedOpen, ticketMachine.ApplyPolicyEpoch(8).Single().State);
        AssertThrows<InvalidOperationException>(() => ticketMachine.RedeemTicket(ticket));

        var policyClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var policyNonces = new TestNonceProvider();
        var policyMachine = CreateOutboundGateMachine(sample, policyClock, policyNonces);
        var policyChallenge = PrepareToChallenge(policyMachine, sample, policyClock, policyNonces);
        var policyTicket = policyMachine.ReceiveDecision(new UserDecision(1, policyNonces.NextNonce(), policyChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        policyMachine.RedeemTicket(policyTicket);
        AssertEqual(GateRuntimeState.Blocked, policyMachine.ApplyPolicyEpoch(8).Single().State);
        AssertThrows<InvalidOperationException>(() => policyMachine.RedeemTicket(policyTicket));

        var expiryClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var expiryNonces = new TestNonceProvider();
        var expiryMachine = CreateOutboundGateMachine(sample, expiryClock, expiryNonces);
        var expiryChallenge = PrepareToChallenge(expiryMachine, sample, expiryClock, expiryNonces);
        var expiryTicket = expiryMachine.ReceiveDecision(new UserDecision(1, expiryNonces.NextNonce(), expiryChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        var grant = expiryMachine.RedeemTicket(expiryTicket).Grant!;
        expiryClock.Set(grant.GrantWindow.Deadline);
        AssertEqual(GateRuntimeState.Blocked, expiryMachine.ProcessExpired().Single().State);
        AssertThrows<InvalidOperationException>(() => expiryMachine.RedeemTicket(expiryTicket));
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateReadDeadlineAsync()
    {
        var sample = OutboundGateSamples();
        var nearDeadline = new ServiceMonotonicTimestamp(1, sample.Clock, sample.ReadWindow.Deadline.ElapsedMilliseconds - 1);
        var nearClock = new TestMonotonicClock(nearDeadline);
        var nearMachine = CreateOutboundGateMachine(sample, nearClock, new TestNonceProvider());
        var request = nearMachine.ReceiveIntent(sample.Intent).ArmRequest!;
        AssertEqual(sample.ReadWindow.Deadline, request.ArmWindow.Deadline);

        var exhaustedClock = new TestMonotonicClock(sample.ReadWindow.Deadline);
        var exhaustedMachine = CreateOutboundGateMachine(sample, exhaustedClock, new TestNonceProvider());
        AssertEqual(GateRuntimeState.FailedOpen, exhaustedMachine.ReceiveIntent(sample.Intent).Status.State);

        var ackClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var ackNonces = new TestNonceProvider();
        var ackMachine = CreateOutboundGateMachine(sample, ackClock, ackNonces);
        var ackRequest = ackMachine.ReceiveIntent(sample.Intent).ArmRequest!;
        ackMachine.ReceiveGateArmAck(AckFor(sample, ackRequest, ackNonces));
        ackClock.Set(ackRequest.ArmWindow.Deadline);
        AssertEqual(GateRuntimeState.FailedOpen, ackMachine.ProcessExpired().Single().State);

        var dispositionClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var dispositionNonces = new TestNonceProvider();
        var dispositionMachine = CreateOutboundGateMachine(sample, dispositionClock, dispositionNonces);
        var disposition = PrepareToDisposition(dispositionMachine, sample, dispositionNonces);
        dispositionClock.Set(disposition.Request.ArmWindow.Deadline);
        AssertEqual(GateRuntimeState.FailedOpen, dispositionMachine.ProcessExpired().Single().State);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateAllPhaseExpiryAsync()
    {
        var sample = OutboundGateSamples();
        var completionClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var completionNonces = new TestNonceProvider();
        var completionMachine = CreateOutboundGateMachine(sample, completionClock, completionNonces);
        var completionPrepared = PrepareToDisposition(completionMachine, sample, completionNonces);
        completionMachine.AcceptCompletion(CompletionFor(sample, completionPrepared.Disposition, completionNonces, sample.MinifilterGeneration));
        completionClock.Advance((long)OutboundGateLimits.MaximumDecisionHoldDuration.TotalMilliseconds);
        AssertEqual(GateRuntimeState.FailedOpen, completionMachine.ProcessExpired().Single().State);

        var decisionClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var decisionNonces = new TestNonceProvider();
        var decisionMachine = CreateOutboundGateMachine(sample, decisionClock, decisionNonces);
        PrepareToChallenge(decisionMachine, sample, decisionClock, decisionNonces);
        decisionClock.Advance((long)OutboundGateLimits.MaximumDecisionHoldDuration.TotalMilliseconds);
        AssertEqual(GateRuntimeState.FailedOpen, decisionMachine.ProcessExpired().Single().State);

        var ticketClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var ticketNonces = new TestNonceProvider();
        var ticketMachine = CreateOutboundGateMachine(sample, ticketClock, ticketNonces);
        var ticketChallenge = PrepareToChallenge(ticketMachine, sample, ticketClock, ticketNonces);
        ticketMachine.ReceiveDecision(new UserDecision(1, ticketNonces.NextNonce(), ticketChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start.AddYears(-50), "test"));
        ticketClock.Advance((long)OutboundGateLimits.MaximumTicketValidity.TotalMilliseconds);
        AssertEqual(GateRuntimeState.FailedOpen, ticketMachine.ProcessExpired().Single().State);

        var mismatchClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var mismatchMachine = CreateOutboundGateMachine(sample, mismatchClock, new TestNonceProvider());
        mismatchMachine.ReceiveIntent(sample.Intent);
        mismatchClock.Set(new ServiceMonotonicTimestamp(1, Guid.NewGuid(), mismatchClock.Now().ElapsedMilliseconds));
        AssertEqual(GateRuntimeState.FailedOpen, mismatchMachine.ProcessExpired().Single().State);

        var grantClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var grantNonces = new TestNonceProvider();
        var grantMachine = CreateOutboundGateMachine(sample, grantClock, grantNonces);
        var grantChallenge = PrepareToChallenge(grantMachine, sample, grantClock, grantNonces);
        var grantTicket = grantMachine.ReceiveDecision(new UserDecision(1, grantNonces.NextNonce(), grantChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        grantMachine.RedeemTicket(grantTicket);
        grantClock.Set(new ServiceMonotonicTimestamp(1, Guid.NewGuid(), grantClock.Now().ElapsedMilliseconds));
        AssertEqual(GateRuntimeState.Blocked, grantMachine.ProcessExpired().Single().State);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateIntentReplayAsync()
    {
        var sample = OutboundGateSamples();
        var invalidClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var invalidMachine = CreateOutboundGateMachine(sample, invalidClock, new TestNonceProvider());
        var invalidIntent = new FileReadIntent(1, Guid.NewGuid(), sample.Subject, sample.File, FileActivityOperation.Read, sample.Start, sample.ReadWindow, Guid.NewGuid(), 1);
        var invalidFirst = invalidMachine.ReceiveIntent(invalidIntent);
        var counters = invalidMachine.Counters;
        var alertCount = invalidMachine.CriticalAlerts.Count;
        var invalidDuplicate = invalidMachine.ReceiveIntent(CloneIntent(invalidIntent));
        AssertTrue(invalidDuplicate.IsDuplicate, "Invalid intent replay was not recorded.");
        AssertEqual(counters, invalidMachine.Counters);
        AssertEqual(alertCount, invalidMachine.CriticalAlerts.Count);
        AssertThrows<InvalidOperationException>(() => invalidMachine.ReceiveIntent(new FileReadIntent(1, invalidIntent.IntentId, invalidIntent.Subject, invalidIntent.File, invalidIntent.Operation, invalidIntent.ObservedAtUtc, invalidIntent.ReadWindow, invalidIntent.BootInstance, 2)));
        AssertTrue(invalidFirst.ArmRequest is null && invalidFirst.Ticket is null, "Invalid intent created a capability.");

        var overflowClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var overflowMachine = CreateOutboundGateMachine(sample, overflowClock, new TestNonceProvider());
        for (var index = 0; index < 4; index++)
            overflowMachine.ReceiveIntent(IntentFor(sample, Guid.NewGuid(), sample.Subject, index + 1));
        var overflowIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 5);
        AssertEqual(GateRuntimeState.FailedOpen, overflowMachine.ReceiveIntent(overflowIntent).Status.State);
        var overflowCounters = overflowMachine.Counters;
        var overflowAlerts = overflowMachine.CriticalAlerts.Count;
        AssertTrue(overflowMachine.ReceiveIntent(CloneIntent(overflowIntent)).IsDuplicate, "Overflow replay was not idempotent.");
        AssertEqual(overflowCounters, overflowMachine.Counters);
        AssertEqual(overflowAlerts, overflowMachine.CriticalAlerts.Count);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateStorageBoundsAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var machine = CreateOutboundGateMachine(sample, clock, new TestNonceProvider());
        var liveIntent = machine.ReceiveIntent(sample.Intent);
        AssertEqual(GateRuntimeState.Idle, liveIntent.Status.State);

        FileReadIntent? oldest = null;
        FileReadIntent? newest = null;
        for (var index = 0; index < 300; index++)
        {
            var intent = new FileReadIntent(1, Guid.NewGuid(), sample.Subject, sample.File, FileActivityOperation.Read, sample.Start, sample.ReadWindow, Guid.NewGuid(), index + 2);
            oldest ??= intent;
            newest = intent;
            machine.ReceiveIntent(intent);
        }
        var storage = machine.Storage;
        AssertEqual(1, storage.ActiveContextCount);
        AssertEqual(storage.TerminalHistoryCapacity, storage.TerminalHistoryCount);
        AssertEqual(storage.CriticalAlertCapacity, storage.CriticalAlertCount);
        AssertEqual(0, storage.ChallengeMappingCount);
        var beforeNewestReplay = machine.Counters;
        AssertTrue(machine.ReceiveIntent(newest!).IsDuplicate, "Newest bounded terminal record was lost.");
        AssertEqual(beforeNewestReplay, machine.Counters);
        machine.ReceiveIntent(oldest!);
        AssertEqual(beforeNewestReplay.FailedOpenCount + 1, machine.Counters.FailedOpenCount);
        AssertEqual(1, machine.Storage.ActiveContextCount);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateChallengeBoundsAsync()
    {
        var sample = OutboundGateSamples();
        var subjectClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var subjectNonces = new TestNonceProvider();
        var subjectMachine = CreateOutboundGateMachine(sample, subjectClock, subjectNonces);
        var subjectIntents = new List<FileReadIntent>();
        for (var index = 0; index < 5; index++)
        {
            var intent = IntentFor(sample, Guid.NewGuid(), sample.Subject, index + 1);
            subjectIntents.Add(intent);
            var result = PrepareToChallenge(subjectMachine, sample, subjectClock, subjectNonces, intent);
            if (index == 4)
                AssertEqual(GateRuntimeState.FailedOpen, result.Result.Status.State);
        }
        AssertEqual(4, subjectMachine.Storage.ChallengeMappingCount);
        AssertEqual(GateRuntimeState.AwaitingDecision, subjectMachine.ReceiveIntent(subjectIntents[0]).Status.State);

        var globalClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var globalNonces = new TestNonceProvider();
        var globalMachine = CreateOutboundGateMachine(sample, globalClock, globalNonces);
        FileReadIntent? firstLive = null;
        for (var index = 0; index < 129; index++)
        {
            var process = new ProcessIdentity(10_000 + index, sample.Start);
            var subject = new GateSubject(1, process, $"sha256:challenge-{index}", null, [process]);
            var intent = IntentFor(sample, Guid.NewGuid(), subject, index + 1);
            firstLive ??= intent;
            var result = PrepareToChallenge(globalMachine, sample, globalClock, globalNonces, intent);
            if (index == 128)
                AssertEqual(GateRuntimeState.FailedOpen, result.Result.Status.State);
        }
        AssertEqual(128, globalMachine.Storage.ChallengeMappingCount);
        AssertEqual(GateRuntimeState.AwaitingDecision, globalMachine.ReceiveIntent(firstLive!).Status.State);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateChallengeCoverageAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces);
        var prepared = PrepareToDisposition(machine, sample, nonces);
        machine.AcceptCompletion(CompletionFor(sample, prepared.Disposition, nonces, sample.MinifilterGeneration));
        var partialCoverage = new GateCoverage(1, GateCoverageFlags.NewTcp);
        var partialChallenge = ChallengeFor(sample, prepared.Request, clock, nonces, sample.Intent, partialCoverage);
        AssertEqual(GateRuntimeState.FailedOpen, machine.ReceiveChallenge(partialChallenge).Status.State);

        var ackClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var ackNonces = new TestNonceProvider();
        var ackMachine = CreateOutboundGateMachine(sample, ackClock, ackNonces);
        var request = ackMachine.ReceiveIntent(sample.Intent).ArmRequest!;
        var partialAck = new GateArmAck(1, ackNonces.NextNonce(), sample.Intent.IntentId, sample.Subject, request.RequiredCoverage, partialCoverage, 7, request.DriverGeneration, request.RequestNonce, ackNonces.NextNonce(), sample.Start, request.ArmWindow, "partial");
        AssertEqual(GateRuntimeState.FailedOpen, ackMachine.ReceiveGateArmAck(partialAck).Status.State);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGatePendingAfterAckBoundsAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces);
        for (var index = 0; index < 2; index++)
        {
            var intent = IntentFor(sample, Guid.NewGuid(), sample.Subject, index + 1);
            var request = machine.ReceiveIntent(intent).ArmRequest!;
            machine.ReceiveGateArmAck(AckFor(sample, request, nonces, intent));
        }
        for (var index = 2; index < 4; index++)
            _ = PrepareToDisposition(machine, sample, nonces, IntentFor(sample, Guid.NewGuid(), sample.Subject, index + 1));

        var fifth = IntentFor(sample, Guid.NewGuid(), sample.Subject, 5);
        var overflow = machine.ReceiveIntent(fifth);
        AssertEqual(GateRuntimeState.FailedOpen, overflow.Status.State);
        AssertTrue(overflow.CriticalAlert is not null, "Per-subject pending overflow did not alert.");
        var counters = machine.Counters;
        var alerts = machine.CriticalAlerts.Count;
        AssertTrue(machine.ReceiveIntent(CloneIntent(fifth)).IsDuplicate, "Pending overflow duplicate was not idempotent.");
        AssertEqual(counters, machine.Counters);
        AssertEqual(alerts, machine.CriticalAlerts.Count);

        var globalClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var globalNonces = new TestNonceProvider();
        var globalMachine = CreateOutboundGateMachine(sample, globalClock, globalNonces);
        for (var index = 0; index < 64; index++)
        {
            var process = new ProcessIdentity(20_000 + index, sample.Start);
            var subject = new GateSubject(1, process, $"sha256:pending-global-{index}", null, [process]);
            var intent = IntentFor(sample, Guid.NewGuid(), subject, index + 1);
            var request = globalMachine.ReceiveIntent(intent).ArmRequest!;
            globalMachine.ReceiveGateArmAck(AckFor(sample, request, globalNonces, intent));
        }
        var globalOverflowIntent = IntentFor(sample, Guid.NewGuid(), new GateSubject(1, new ProcessIdentity(30_000, sample.Start), "sha256:pending-global-overflow", null, [new ProcessIdentity(30_000, sample.Start)]), 65);
        AssertEqual(GateRuntimeState.FailedOpen, globalMachine.ReceiveIntent(globalOverflowIntent).Status.State);
        AssertEqual(1L, globalMachine.Counters.OverflowCount);
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateTerminalDuplicateAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces);
        var prepared = PrepareToDisposition(machine, sample, nonces);
        var acceptedCompletion = CompletionFor(sample, prepared.Disposition, nonces, sample.MinifilterGeneration);
        machine.AcceptCompletion(acceptedCompletion);
        var challenge = ChallengeFor(sample, prepared.Request, clock, nonces, sample.Intent, prepared.Request.RequiredCoverage);
        machine.ReceiveChallenge(challenge);
        var ticket = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        machine.RedeemTicket(ticket);
        machine.ApplyPolicyEpoch(8);

        var before = machine.Counters;
        var dispositionDuplicate = machine.ReleaseAfterGateArmed(prepared.Disposition);
        var completionDuplicate = machine.AcceptCompletion(acceptedCompletion);
        AssertTrue(dispositionDuplicate.IsDuplicate && completionDuplicate.IsDuplicate, "Late terminal duplicates were not idempotent.");
        AssertTrue(dispositionDuplicate.Disposition is not null && completionDuplicate.Completion is not null, "Terminal replay omitted the accepted identity.");
        AssertTrue(dispositionDuplicate.Ticket is null && dispositionDuplicate.Grant is null && dispositionDuplicate.Challenge is null && dispositionDuplicate.ArmRequest is null, "Terminal history retained a live capability.");
        AssertEqual(before, machine.Counters);
        var mismatchedDisposition = new FileReadDisposition(1, prepared.Disposition.IntentId, prepared.Disposition.ProcessIdentity, prepared.Disposition.File, prepared.Disposition.Disposition, prepared.Disposition.GateAckId, prepared.Disposition.ReadWindow, prepared.Disposition.ReasonCode, prepared.Disposition.Sequence + 1);
        AssertThrows<InvalidOperationException>(() => machine.ReleaseAfterGateArmed(mismatchedDisposition));
        var mismatchedCompletion = new FileReadCompletionAck(1, acceptedCompletion.CompletionId, acceptedCompletion.IntentId, acceptedCompletion.ProcessIdentity, acceptedCompletion.File, acceptedCompletion.DispositionSequence, acceptedCompletion.Disposition, acceptedCompletion.GateAckId, acceptedCompletion.Result, "mismatched", acceptedCompletion.MonotonicSequence, acceptedCompletion.MinifilterGeneration);
        AssertThrows<InvalidOperationException>(() => machine.AcceptCompletion(mismatchedCompletion));

        var failedClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var failedNonces = new TestNonceProvider();
        var failedMachine = CreateOutboundGateMachine(sample, failedClock, failedNonces);
        var failedPrepared = PrepareToDisposition(failedMachine, sample, failedNonces);
        var rejectedCompletion = CompletionFor(sample, failedPrepared.Disposition, failedNonces, Guid.NewGuid());
        AssertEqual(GateRuntimeState.FailedOpen, failedMachine.AcceptCompletion(rejectedCompletion).Status.State);
        AssertTrue(failedMachine.ReleaseAfterGateArmed(failedPrepared.Disposition).IsDuplicate, "Fail-open terminal disposition replay was not idempotent.");
        AssertTrue(failedMachine.AcceptCompletion(rejectedCompletion).IsDuplicate, "Fail-open terminal completion replay was not idempotent.");
        return Task.CompletedTask;
    }

    private static Task TestOutboundGateAuditClockAsync()
    {
        var sample = OutboundGateSamples();
        var auditClock = new TestAuditClock(new DateTimeOffset(2042, 5, 6, 7, 8, 9, TimeSpan.Zero));
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var machine = CreateOutboundGateMachine(sample, clock, nonces, auditClock: auditClock);
        var received = machine.ReceiveIntent(sample.Intent);
        AssertEqual(auditClock.Current, received.Status.AuditTimeUtc);
        AssertTrue(received.Status.AuditTimeUtc.Year != 1970, "Audit timestamp was fabricated from monotonic elapsed time.");

        auditClock.Set(new DateTimeOffset(1999, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var request = received.ArmRequest!;
        var armed = machine.ReceiveGateArmAck(AckFor(sample, request, nonces));
        AssertEqual(auditClock.Current, armed.Status.AuditTimeUtc);

        var ticketClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var ticketNonces = new TestNonceProvider();
        var ticketMachine = CreateOutboundGateMachine(sample, ticketClock, ticketNonces, auditClock: auditClock);
        var prepared = PrepareToChallenge(ticketMachine, sample, ticketClock, ticketNonces);
        auditClock.Set(new DateTimeOffset(2088, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var issued = ticketMachine.ReceiveDecision(new UserDecision(1, ticketNonces.NextNonce(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start.AddYears(-100), "test"));
        AssertEqual(auditClock.Current, issued.Ticket!.IssuedAtUtc);
        AssertEqual(auditClock.Current.Add(OutboundGateLimits.MaximumTicketValidity), issued.Ticket.ExpiresAtUtc);

        auditClock.Set(new DateTimeOffset(1901, 1, 1, 0, 0, 0, TimeSpan.Zero));
        AssertEqual(GateRuntimeState.Granted, ticketMachine.RedeemTicket(issued.Ticket).Status.State);

        var expiryClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var expiryAudit = new TestAuditClock(new DateTimeOffset(2040, 1, 1, 0, 0, 0, TimeSpan.Zero));
        var expiryMachine = CreateOutboundGateMachine(sample, expiryClock, new TestNonceProvider(), auditClock: expiryAudit);
        expiryMachine.ReceiveIntent(sample.Intent);
        expiryAudit.Set(new DateTimeOffset(2030, 1, 1, 0, 0, 0, TimeSpan.Zero));
        expiryClock.Set(sample.ReadWindow.Deadline);
        AssertEqual(GateRuntimeState.FailedOpen, expiryMachine.ProcessExpired().Single().State);

        var alertClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var alertAudit = new TestAuditClock(new DateTimeOffset(2077, 7, 7, 0, 0, 0, TimeSpan.Zero));
        var alertNonces = new TestNonceProvider();
        var alertMachine = CreateOutboundGateMachine(sample, alertClock, alertNonces, auditClock: alertAudit);
        var alertRequest = alertMachine.ReceiveIntent(sample.Intent).ArmRequest!;
        var forgedAck = new GateArmAck(1, alertNonces.NextNonce(), sample.Intent.IntentId, sample.Subject, alertRequest.RequiredCoverage, alertRequest.RequiredCoverage, 7, Guid.NewGuid(), alertRequest.RequestNonce, alertNonces.NextNonce(), sample.Start, alertRequest.ArmWindow, null);
        var alertResult = alertMachine.ReceiveGateArmAck(forgedAck);
        AssertEqual(alertAudit.Current, alertResult.CriticalAlert!.AuditTimeUtc);
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketSuccessAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        var binding = TicketBinding(sample);

        var issued = service.TryIssue(binding);
        AssertEqual(TicketServiceResultKind.Success, issued.Kind);
        AssertTrue(issued.Ticket is not null, "One-time ticket was not issued.");
        AssertEqual(OutboundGateLimits.AuthenticatorProofBytes, issued.Ticket!.AuthenticatorProof.Count);
        AssertTrue(issued.Ticket.AuthenticatorProof.Any(value => value != 0), "Authenticator proof was empty/placeholder.");

        var redeemed = service.TryRedeem(issued.Ticket, binding);
        AssertEqual(TicketServiceResultKind.Success, redeemed.Kind);
        AssertTrue(redeemed.TicketConsumed, "Successful redemption did not consume the ticket.");
        AssertTrue(redeemed.Grant is not null, "Successful redemption did not create a separate grant.");
        AssertTrue(redeemed.Grant!.TicketId == issued.Ticket.TicketId && redeemed.Grant.GrantId != issued.Ticket.TicketId, "Grant authority was not separate from ticket authority.");
        AssertEqual(binding.FlowGeneration, redeemed.Grant.FlowGeneration);
        AssertEqual(binding.Destination, redeemed.Grant.Destination);
        AssertEqual(binding.Subject, redeemed.Grant.Subject);
        AssertEqual(1, service.Snapshot.ReplayTombstones);

        var failureClock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var failureService = new OneTimeGateTicketService(failureClock, new TestAuditClock(sample.Start), new TestNonceProvider(), new DeterministicTestTicketAuthenticator(sample.Boot), 7, new FailingGrantFactory());
        var failureTicket = failureService.TryIssue(binding).Ticket!;
        var grantFailure = failureService.TryRedeem(failureTicket, binding);
        AssertEqual(TicketServiceResultKind.FailOpenCritical, grantFailure.Kind);
        AssertTrue(grantFailure.TicketConsumed, "Grant creation failure resurrected the ticket.");
        AssertEqual("ticket-replay", failureService.TryRedeem(failureTicket, binding).ReasonCode);
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketBindingAsync()
    {
        var sample = OutboundGateSamples();
        var variants = new List<TicketAuthorizationBinding>
        {
            TicketBinding(sample, subject: new GateSubject(1, new ProcessIdentity(sample.Process.ProcessId, sample.Start.AddSeconds(1)), sample.Subject.ApplicationIdentity, null, [new ProcessIdentity(sample.Process.ProcessId, sample.Start.AddSeconds(1))])),
            TicketBinding(sample, subject: new GateSubject(1, sample.Process, sample.Subject.ApplicationIdentity, Guid.Parse("31000000-0000-0000-0000-000000000031"), [sample.Process, new ProcessIdentity(43, sample.Start)])),
            TicketBinding(sample, subject: new GateSubject(1, sample.Process, "sha256:other", null, [sample.Process])),
            TicketBinding(sample, file: new FileVersionIdentity(1, sample.File.VolumeId, sample.File.FileId, sample.File.CreationTimeUtc, sample.File.SizeBytes + 1, sample.File.LastWriteTimeUtc, sample.File.ChangeTimeUtc, sample.File.Usn, "mutated-version")),
            TicketBinding(sample, destination: new DestinationBinding(1, IPAddress.Parse("127.0.0.2"), IpVersion.IPv4, 5050, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, 12, 34, "localhost", DomainEvidenceProvenance.DnsObservation, sample.Start)),
            TicketBinding(sample, destination: new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 5051, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, 12, 34, "localhost", DomainEvidenceProvenance.DnsObservation, sample.Start)),
            TicketBinding(sample, destination: new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Udp, NetworkTrafficDirection.Outbound, 12, 34, "localhost", DomainEvidenceProvenance.DnsObservation, sample.Start)),
            TicketBinding(sample, destination: new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, 13, 34, "localhost", DomainEvidenceProvenance.DnsObservation, sample.Start)),
            TicketBinding(sample, destination: new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, 12, 35, "localhost", DomainEvidenceProvenance.DnsObservation, sample.Start)),
            TicketBinding(sample, flowGeneration: 2)
        };

        foreach (var variant in variants)
        {
            var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
            var service = CreateTicketService(sample, clock, new TestNonceProvider());
            using (service)
            {
                var issued = service.TryIssue(TicketBinding(sample));
                var result = service.TryRedeem(issued.Ticket!, variant);
                AssertEqual(TicketServiceResultKind.Rejected, result.Kind);
                AssertEqual(0, result.Grant is null ? 0 : 1);
                AssertEqual(1, service.Snapshot.OutstandingGlobal);
            }
        }

        using var replayService = CreateTicketService(sample, new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000)), new TestNonceProvider());
        var replayBinding = TicketBinding(sample);
        var replayTicket = replayService.TryIssue(replayBinding).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, replayService.TryRedeem(replayTicket, replayBinding).Kind);
        var replay = replayService.TryRedeem(replayTicket, replayBinding);
        AssertEqual(TicketServiceResultKind.Rejected, replay.Kind);
        AssertEqual("ticket-replay", replay.ReasonCode);

        var alteredProof = replayTicket.AuthenticatorProof.ToArray();
        alteredProof[0] ^= 0x80;
        AssertEqual("ticket-proof-invalid", replayService.TryRedeem(new OneTimeTicket(replayTicket.Version, replayTicket.TicketId, replayTicket.Nonce, replayTicket.IntentId, replayTicket.Subject, replayTicket.File, replayTicket.Destination, replayTicket.FlowGeneration, replayTicket.PolicyEpoch, replayTicket.BootInstance, replayTicket.IssuedAtUtc, replayTicket.ExpiresAtUtc, replayTicket.ValidityWindow, replayTicket.GrantMaxBytes, replayTicket.GrantMaxDurationMilliseconds, alteredProof), replayBinding).ReasonCode);
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new DestinationBinding(1, sample.Destination.Address, sample.Destination.IpVersion, sample.Destination.RemotePort, sample.Destination.Protocol, NetworkTrafficDirection.Inbound, sample.Destination.NetworkCompartmentId, sample.Destination.InterfaceLuid, sample.Destination.DomainEvidence, sample.Destination.DomainProvenance, sample.Destination.DomainObservedAtUtc));
        AssertThrows<ArgumentException>(() => _ = new OneTimeTicket(replayTicket.Version, replayTicket.TicketId, replayTicket.Nonce, replayTicket.IntentId, replayTicket.Subject, replayTicket.File, replayTicket.Destination, replayTicket.FlowGeneration, replayTicket.PolicyEpoch, replayTicket.BootInstance, replayTicket.IssuedAtUtc, replayTicket.ExpiresAtUtc, replayTicket.ValidityWindow, replayTicket.GrantMaxBytes, replayTicket.GrantMaxDurationMilliseconds, [1]));
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketExpiryAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        var audit = new TestAuditClock(sample.Start);
        using var service = new OneTimeGateTicketService(clock, audit, new TestNonceProvider(), new DeterministicTestTicketAuthenticator(sample.Boot), 7);
        var binding = TicketBinding(sample);
        var ticket = service.TryIssue(binding).Ticket!;

        clock.Set(new ServiceMonotonicTimestamp(1, sample.Clock, 9_999));
        AssertEqual("ticket-not-yet-valid", service.TryRedeem(ticket, binding).ReasonCode);
        AssertEqual(1, service.Snapshot.OutstandingGlobal);

        audit.Set(sample.Start.AddYears(50));
        clock.Set(new ServiceMonotonicTimestamp(1, sample.Clock, 15_000));
        var expired = service.TryRedeem(ticket, binding);
        AssertEqual(TicketServiceResultKind.FailOpenCritical, expired.Kind);
        AssertEqual("ticket-expired", expired.ReasonCode);
        AssertEqual(0, service.Snapshot.OutstandingGlobal);

        var second = service.TryIssue(binding).Ticket!;
        clock.Set(new ServiceMonotonicTimestamp(1, Guid.NewGuid(), 10_000));
        AssertEqual("ticket-clock-instance-mismatch", service.TryRedeem(second, binding).ReasonCode);
        return Task.CompletedTask;
    }

    private static async Task TestOneTimeTicketConcurrentRedemptionAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var service = CreateTicketService(sample, clock, new TestNonceProvider());
        var binding = TicketBinding(sample);
        var ticket = service.TryIssue(binding).Ticket!;
        using var barrier = new Barrier(2);
        var results = await Task.WhenAll(
            Task.Run(() => { barrier.SignalAndWait(); return service.TryRedeem(ticket, binding); }),
            Task.Run(() => { barrier.SignalAndWait(); return service.TryRedeem(ticket, binding); }));
        AssertEqual(1, results.Count(result => result.Kind == TicketServiceResultKind.Success));
        AssertEqual(1, results.Count(result => result.ReasonCode == "ticket-replay"));
        AssertEqual(1, service.Snapshot.ReplayTombstones);
    }

    private static Task TestOneTimeTicketCapacityAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var subjectService = CreateTicketService(sample, clock, new TestNonceProvider());
        var subjectTickets = new List<OneTimeTicket>();
        for (var index = 0; index < OneTimeGateTicketService.MaximumOutstandingPerSubject; index++)
            subjectTickets.Add(subjectService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid())).Ticket!);
        var ninth = subjectService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid()));
        AssertEqual(TicketServiceResultKind.FailOpenCritical, ninth.Kind);
        AssertEqual(OneTimeGateTicketService.MaximumOutstandingPerSubject, subjectService.Snapshot.OutstandingGlobal);
        AssertEqual(TicketServiceResultKind.Success, subjectService.TryRedeem(subjectTickets[0], TicketBinding(sample, intentId: subjectTickets[0].IntentId)).Kind);

        using var globalService = CreateTicketService(sample, new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000)), new TestNonceProvider());
        for (var index = 0; index < OneTimeGateTicketService.MaximumOutstandingGlobal; index++)
        {
            var process = new ProcessIdentity(50_000 + index, sample.Start);
            var subject = new GateSubject(1, process, $"sha256:global-{index}", null, [process]);
            AssertEqual(TicketServiceResultKind.Success, globalService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid(), subject: subject)).Kind);
        }
        var overflowProcess = new ProcessIdentity(60_000, sample.Start);
        var overflowSubject = new GateSubject(1, overflowProcess, "sha256:overflow", null, [overflowProcess]);
        var globalOverflow = globalService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid(), subject: overflowSubject));
        AssertEqual(TicketServiceResultKind.FailOpenCritical, globalOverflow.Kind);

        var tombstoneClock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var tombstoneService = CreateTicketService(sample, tombstoneClock, new TestNonceProvider());
        OneTimeTicket? replayTicket = null;
        var tombstonePolicyEpoch = 7L;
        for (var index = 0; index < OneTimeGateTicketService.MaximumReplayTombstonesGlobal; index++)
        {
            var binding = TicketBinding(sample, intentId: Guid.NewGuid(), policyEpoch: tombstonePolicyEpoch);
            var ticket = tombstoneService.TryIssue(binding).Ticket!;
            replayTicket = ticket;
            AssertEqual(TicketServiceResultKind.Success, tombstoneService.TryRedeem(ticket, binding).Kind);
            if ((index + 1) % OneTimeGateTicketService.MaximumActiveGrantsGlobal == 0
                && index + 1 < OneTimeGateTicketService.MaximumReplayTombstonesGlobal)
            {
                tombstonePolicyEpoch++;
                tombstoneService.ApplyPolicyEpoch(tombstonePolicyEpoch);
                AssertEqual(0, tombstoneService.Snapshot.ActiveGrantReservations);
            }
        }
        AssertEqual(OneTimeGateTicketService.MaximumReplayTombstonesGlobal, tombstoneService.Snapshot.ReplayTombstones);
        AssertEqual(TicketServiceResultKind.FailOpenCritical, tombstoneService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid(), policyEpoch: tombstonePolicyEpoch)).Kind);
        AssertEqual("ticket-replay", tombstoneService.TryRedeem(replayTicket!, TicketBinding(sample, intentId: replayTicket!.IntentId, policyEpoch: tombstonePolicyEpoch)).ReasonCode);
        tombstonePolicyEpoch++;
        tombstoneService.ApplyPolicyEpoch(tombstonePolicyEpoch);
        AssertEqual(0, tombstoneService.Snapshot.ActiveGrantReservations);
        tombstoneClock.Set(new ServiceMonotonicTimestamp(1, sample.Clock, 14_999));
        AssertEqual(0, tombstoneService.PruneExpired().TombstonesRemoved);
        tombstoneClock.Set(new ServiceMonotonicTimestamp(1, sample.Clock, 15_000));
        AssertEqual(OneTimeGateTicketService.MaximumReplayTombstonesGlobal, tombstoneService.PruneExpired().TombstonesRemoved);
        AssertEqual(TicketServiceResultKind.Success, tombstoneService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid(), policyEpoch: tombstonePolicyEpoch)).Kind);
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketCapacityFailOpenAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        for (var index = 0; index < OneTimeGateTicketService.MaximumOutstandingPerSubject; index++)
            AssertEqual(TicketServiceResultKind.Success, service.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid())).Kind);

        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        var prepared = PrepareToChallenge(machine, sample, clock, nonces, IntentFor(sample, Guid.NewGuid(), sample.Subject, 900));
        var failed = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test"));
        AssertEqual(GateRuntimeState.FailedOpen, failed.Status.State);
        AssertTrue(failed.CriticalAlert is not null, "Ticket capacity refusal did not create a Critical Alert.");
        AssertTrue(failed.Status.TrafficFailedOpen, "Ticket capacity refusal did not fail open.");
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketInvalidationAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        var binding = TicketBinding(sample);
        var ticket = service.TryIssue(binding).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(ticket, binding).Kind);
        AssertEqual(1, service.Snapshot.ActiveGrantReservations);
        service.ApplyPolicyEpoch(7);
        AssertEqual(1, service.Snapshot.ActiveGrantReservations);
        service.ApplyPolicyEpoch(8);
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);
        AssertEqual("ticket-policy-epoch-mismatch", service.TryRedeem(ticket, binding).ReasonCode);

        var epochBinding = TicketBinding(sample, intentId: Guid.NewGuid(), policyEpoch: 8);
        var epochTicket = service.TryIssue(epochBinding).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(epochTicket, epochBinding).Kind);
        AssertEqual(1, service.Snapshot.ActiveGrantReservations);
        var newBoot = Guid.NewGuid();
        service.ResetRuntime(newBoot, 9, new DeterministicTestTicketAuthenticator(newBoot));
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);
        AssertEqual("ticket-boot-instance-mismatch", service.TryRedeem(ticket, binding).ReasonCode);
        AssertEqual(0, service.Snapshot.OutstandingGlobal);

        var resetBinding = TicketBinding(sample, intentId: Guid.NewGuid(), bootInstance: newBoot, policyEpoch: 9);
        var resetTicket = service.TryIssue(resetBinding).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(resetTicket, resetBinding).Kind);
        AssertEqual(1, service.Snapshot.ActiveGrantReservations);
        service.Dispose();
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketIdentifierCollisionAsync()
    {
        var sample = OutboundGateSamples();
        var ticketId = Guid.Parse("e1000000-0000-0000-0000-000000000001");
        var nonce = Guid.Parse("e1000000-0000-0000-0000-000000000002");
        var grantId = Guid.Parse("e1000000-0000-0000-0000-000000000003");
        var nextTicketId = Guid.Parse("e1000000-0000-0000-0000-000000000004");
        var nextNonce = Guid.Parse("e1000000-0000-0000-0000-000000000005");

        var consumedCollisionCases = new[]
        {
            (TicketId: ticketId, Nonce: nonce),
            (TicketId: ticketId, Nonce: nextNonce),
            (TicketId: nextTicketId, Nonce: ticketId),
            (TicketId: nonce, Nonce: nextNonce),
            (TicketId: nextTicketId, Nonce: nonce)
        };
        foreach (var candidate in consumedCollisionCases)
        {
            var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
            using var service = new OneTimeGateTicketService(
                clock,
                new TestAuditClock(sample.Start),
                new ScriptedNonceProvider(ticketId, nonce, grantId, candidate.TicketId, candidate.Nonce),
                new DeterministicTestTicketAuthenticator(sample.Boot),
                7);
            var binding = TicketBinding(sample);
            var first = service.TryIssue(binding).Ticket!;
            var redeemed = service.TryRedeem(first, binding);
            AssertEqual(TicketServiceResultKind.Success, redeemed.Kind);
            AssertTrue(redeemed.Grant is not null, "The first ticket did not produce a grant before collision testing.");
            var collision = service.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid()));
            AssertEqual(TicketServiceResultKind.FailOpenCritical, collision.Kind);
            AssertEqual("ticket-identifier-collision", collision.ReasonCode);
            AssertTrue(collision.CapacityFailure, "Identifier collision was not surfaced as a reservation failure.");
            AssertEqual(1, service.Snapshot.ReplayTombstones);
            var replay = service.TryRedeem(first, binding);
            AssertEqual("ticket-replay", replay.ReasonCode);
            AssertTrue(replay.Grant is null, "A replay after identifier collision created a grant.");
        }

        var outstandingClock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using (var outstandingService = new OneTimeGateTicketService(
            outstandingClock,
            new TestAuditClock(sample.Start),
            new ScriptedNonceProvider(ticketId, nonce, nonce, nextNonce),
            new DeterministicTestTicketAuthenticator(sample.Boot),
            7))
        {
            AssertEqual(TicketServiceResultKind.Success, outstandingService.TryIssue(TicketBinding(sample)).Kind);
            var outstandingCollision = outstandingService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid()));
            AssertEqual(TicketServiceResultKind.FailOpenCritical, outstandingCollision.Kind);
            AssertEqual("ticket-identifier-collision", outstandingCollision.ReasonCode);
            AssertEqual(1, outstandingService.Snapshot.OutstandingGlobal);
        }

        var stateClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var stateService = new OneTimeGateTicketService(stateClock, new TestAuditClock(sample.Start), new ScriptedNonceProvider(ticketId, nonce, grantId, ticketId, nextNonce), new DeterministicTestTicketAuthenticator(sample.Boot), 7);
        var firstStateTicket = stateService.TryIssue(TicketBinding(sample)).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, stateService.TryRedeem(firstStateTicket, TicketBinding(sample)).Kind);
        using var machine = CreateOutboundGateMachine(sample, stateClock, new TestNonceProvider(), ticketService: stateService);
        var prepared = PrepareToChallenge(machine, sample, stateClock, new TestNonceProvider(), IntentFor(sample, Guid.NewGuid(), sample.Subject, 901));
        var failed = machine.ReceiveDecision(new UserDecision(1, Guid.NewGuid(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "collision-test"));
        AssertEqual(GateRuntimeState.FailedOpen, failed.Status.State);
        AssertEqual("ticket-identifier-collision", failed.Status.ReasonCode);
        AssertTrue(failed.CriticalAlert is not null, "State-machine ticket collision did not emit a Critical Alert.");
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketAuthenticatedFieldsAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var service = CreateTicketService(sample, clock, new TestNonceProvider());
        var binding = TicketBinding(sample);
        var ticket = service.TryIssue(binding).Ticket!;
        var alteredSubject = new GateSubject(1, new ProcessIdentity(sample.Process.ProcessId, sample.Start.AddSeconds(1)), sample.Subject.ApplicationIdentity, null, [new ProcessIdentity(sample.Process.ProcessId, sample.Start.AddSeconds(1))]);
        var alteredFile = new FileVersionIdentity(1, sample.File.VolumeId, sample.File.FileId, sample.File.CreationTimeUtc, sample.File.SizeBytes + 1, sample.File.LastWriteTimeUtc, sample.File.ChangeTimeUtc, sample.File.Usn, "altered");
        var alteredDestination = new DestinationBinding(1, IPAddress.Parse("127.0.0.2"), IpVersion.IPv4, sample.Destination.RemotePort, sample.Destination.Protocol, NetworkTrafficDirection.Outbound, sample.Destination.NetworkCompartmentId, sample.Destination.InterfaceLuid, sample.Destination.DomainEvidence, sample.Destination.DomainProvenance, sample.Destination.DomainObservedAtUtc);
        var altered = new[]
        {
            CloneTicket(ticket, ticketId: Guid.NewGuid()),
            CloneTicket(ticket, nonce: Guid.NewGuid()),
            CloneTicket(ticket, intentId: Guid.NewGuid()),
            CloneTicket(ticket, subject: alteredSubject),
            CloneTicket(ticket, file: alteredFile),
            CloneTicket(ticket, destination: alteredDestination),
            CloneTicket(ticket, flowGeneration: 2),
            CloneTicket(ticket, policyEpoch: 8),
            CloneTicket(ticket, bootInstance: Guid.NewGuid()),
            CloneTicket(ticket, issuedAtUtc: ticket.IssuedAtUtc.AddSeconds(1)),
            CloneTicket(ticket, expiresAtUtc: ticket.ExpiresAtUtc.AddSeconds(-1)),
            CloneTicket(ticket, validityWindow: ServiceRange(sample.Clock, 10_000, 4_000)),
            CloneTicket(ticket, grantMaxBytes: 1),
            CloneTicket(ticket, grantMaxDurationMilliseconds: 1)
        };
        foreach (var candidate in altered)
        {
            var result = service.TryRedeem(candidate, binding);
            AssertEqual(TicketServiceResultKind.Rejected, result.Kind);
            AssertEqual("ticket-proof-invalid", result.ReasonCode);
            AssertTrue(result.Grant is null, "An authenticated-field alteration created a grant.");
        }
        AssertEqual(1, service.Snapshot.OutstandingGlobal);
        var redeemed = service.TryRedeem(ticket, binding);
        AssertEqual(TicketServiceResultKind.Success, redeemed.Kind);
        AssertTrue(redeemed.Grant is not null, "The unaltered ticket did not redeem after field-alteration checks.");
        AssertNotEqual(ticket.TicketId, redeemed.Grant!.GrantId);
        AssertNotEqual(ticket.Nonce, redeemed.Grant.GrantId);

        var activeGrantId = Guid.Parse("e2000000-0000-0000-0000-000000000003");
        var scripted = new ScriptedNonceProvider(
            Guid.Parse("e2000000-0000-0000-0000-000000000001"),
            Guid.Parse("e2000000-0000-0000-0000-000000000002"),
            activeGrantId,
            Guid.Parse("e2000000-0000-0000-0000-000000000004"),
            Guid.Parse("e2000000-0000-0000-0000-000000000005"),
            activeGrantId);
        var activeClock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var activeService = new OneTimeGateTicketService(activeClock, new TestAuditClock(sample.Start), scripted, new DeterministicTestTicketAuthenticator(sample.Boot), 7);
        var first = activeService.TryIssue(binding).Ticket!;
        var firstGrant = activeService.TryRedeem(first, binding);
        AssertEqual(TicketServiceResultKind.Success, firstGrant.Kind);
        var second = activeService.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid())).Ticket!;
        var collision = activeService.TryRedeem(second, TicketBinding(sample, intentId: second.IntentId));
        AssertEqual(TicketServiceResultKind.FailOpenCritical, collision.Kind);
        AssertEqual("ticket-grant-identifier-collision", collision.ReasonCode);
        AssertTrue(collision.Grant is null, "An active grant-ID collision created a second grant.");
        AssertEqual(1, activeService.Snapshot.ActiveGrantReservations);
        AssertEqual(OneTimeGateTicketService.MaximumActiveGrantsGlobal, activeService.Snapshot.ActiveGrantReservationCapacity);
        return Task.CompletedTask;
    }

    private static Task TestOneTimeTicketActiveGrantCapacityAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(new ServiceMonotonicTimestamp(1, sample.Clock, 10_000));
        using var service = CreateTicketService(sample, clock, new TestNonceProvider());

        for (var index = 0; index < OneTimeGateTicketService.MaximumActiveGrantsGlobal - 1; index++)
        {
            var binding = TicketBinding(sample, intentId: Guid.NewGuid());
            var ticket = service.TryIssue(binding).Ticket!;
            AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(ticket, binding).Kind);
        }
        AssertEqual(OneTimeGateTicketService.MaximumActiveGrantsGlobal - 1, service.Snapshot.ActiveGrantReservations);

        var capBinding = TicketBinding(sample, intentId: Guid.NewGuid());
        var postCapBinding = TicketBinding(sample, intentId: Guid.NewGuid());
        var capTicket = service.TryIssue(capBinding).Ticket!;
        var postCapTicket = service.TryIssue(postCapBinding).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(capTicket, capBinding).Kind);
        AssertEqual(OneTimeGateTicketService.MaximumActiveGrantsGlobal, service.Snapshot.ActiveGrantReservations);

        var consumedAtCapacity = service.TryRedeem(postCapTicket, postCapBinding);
        AssertEqual(TicketServiceResultKind.FailOpenCritical, consumedAtCapacity.Kind);
        AssertEqual("ticket-active-grant-capacity-exhausted", consumedAtCapacity.ReasonCode);
        AssertTrue(consumedAtCapacity.TicketConsumed, "A ticket reaching active-grant capacity was not consumed.");
        AssertTrue(consumedAtCapacity.Grant is null, "Active-grant capacity pressure created a grant.");
        AssertEqual(OneTimeGateTicketService.MaximumActiveGrantsGlobal, service.Snapshot.ActiveGrantReservations);
        AssertEqual("ticket-replay", service.TryRedeem(postCapTicket, postCapBinding).ReasonCode);

        var issuanceAtCapacity = service.TryIssue(TicketBinding(sample, intentId: Guid.NewGuid()));
        AssertEqual(TicketServiceResultKind.FailOpenCritical, issuanceAtCapacity.Kind);
        AssertEqual("ticket-active-grant-capacity-exhausted", issuanceAtCapacity.ReasonCode);
        AssertTrue(issuanceAtCapacity.CapacityFailure, "Active-grant issuance refusal was not marked as capacity pressure.");
        AssertTrue(issuanceAtCapacity.Ticket is null, "Active-grant capacity pressure issued a ticket.");
        AssertEqual(OneTimeGateTicketService.MaximumActiveGrantsGlobal, service.Snapshot.ActiveGrantReservations);

        clock.Set(new ServiceMonotonicTimestamp(1, sample.Clock, 309_999));
        service.PruneExpired();
        AssertEqual(OneTimeGateTicketService.MaximumActiveGrantsGlobal, service.Snapshot.ActiveGrantReservations);
        clock.Set(new ServiceMonotonicTimestamp(1, sample.Clock, 310_000));
        service.PruneExpired();
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);

        var afterExpiryBinding = TicketBinding(sample, intentId: Guid.NewGuid());
        var afterExpiryTicket = service.TryIssue(afterExpiryBinding).Ticket!;
        AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(afterExpiryTicket, afterExpiryBinding).Kind);
        AssertEqual(1, service.Snapshot.ActiveGrantReservations);
        return Task.CompletedTask;
    }

    private static async Task TestOneTimeTicketAuthorityRaceAsync()
    {
        var sample = OutboundGateSamples();
        await TestPolicyRaceAsync(sample).ConfigureAwait(false);
        await TestRestartRaceAsync(sample).ConfigureAwait(false);
    }

    private static Task TestChallengeAdmissionFailureAsync()
    {
        var sample = OutboundGateSamples();
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new ChallengeAdmissionFailure(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Subject, sample.DriverGeneration, ChallengeAdmissionFailureKind.Unspecified, sample.ReadWindow.StartedAt));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new ChallengeAdmissionFailure(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Subject, sample.DriverGeneration, (ChallengeAdmissionFailureKind)99, sample.ReadWindow.StartedAt));
        AssertThrows<ArgumentException>(() => _ = new ChallengeAdmissionFailure(1, Guid.Empty, sample.Intent.IntentId, sample.Subject, sample.DriverGeneration, ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted, sample.ReadWindow.StartedAt));
        AssertThrows<ArgumentException>(() => _ = new ChallengeAdmissionFailure(1, Guid.NewGuid(), Guid.Empty, sample.Subject, sample.DriverGeneration, ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted, sample.ReadWindow.StartedAt));
        AssertThrows<ArgumentException>(() => _ = new ChallengeAdmissionFailure(1, Guid.NewGuid(), sample.Intent.IntentId, sample.Subject, Guid.Empty, ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted, sample.ReadWindow.StartedAt));

        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var machine = CreateOutboundGateMachine(sample, clock, nonces);
        var liveIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 1_001);
        var live = PrepareToChallenge(machine, sample, clock, nonces, liveIntent);
        var rejectedIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 1_002);
        PrepareAwaitingChallenge(machine, sample, nonces, rejectedIntent);
        var before = machine.Counters;
        var alertCount = machine.CriticalAlerts.Count;
        var failure = ChallengeAdmissionFailureFor(sample, clock, nonces.NextNonce(), rejectedIntent);
        AssertEqual(1, failure.Version);
        AssertEqual(rejectedIntent.IntentId, failure.IntentId);
        AssertEqual(sample.DriverGeneration, failure.WfpGeneration);
        AssertEqual(ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted, failure.FailureKind);
        AssertEqual(clock.Now(), failure.ObservedAt);

        var rejected = machine.ReceiveChallengeAdmissionFailure(failure);
        AssertEqual(GateRuntimeState.FailedOpen, rejected.Status.State);
        AssertEqual("challenge-admission-held-flow-capacity-exhausted", rejected.Status.ReasonCode);
        AssertTrue(rejected.CriticalAlert is not null, "Targeted challenge admission failure omitted its Core Critical Alert.");
        AssertTrue(rejected.Challenge is null && rejected.Ticket is null && rejected.Grant is null, "Targeted challenge admission failure created authority.");
        AssertEqual(before.FailedOpenCount + 1, machine.Counters.FailedOpenCount);
        AssertEqual(before.OverflowCount + 1, machine.Counters.OverflowCount);
        AssertEqual(alertCount + 1, machine.CriticalAlerts.Count);
        AssertEqual(1, machine.Storage.ActiveContextCount);
        AssertEqual(1, machine.Storage.ChallengeMappingCount);
        AssertEqual(GateRuntimeState.AwaitingDecision, machine.ReceiveIntent(liveIntent).Status.State);
        var rejectedReplay = machine.ReceiveIntent(rejectedIntent);
        AssertTrue(rejectedReplay.IsDuplicate && rejectedReplay.Status.State == GateRuntimeState.FailedOpen, "Rejected intent was not terminal after targeted failure.");
        AssertTrue(rejectedReplay.Challenge is null && rejectedReplay.Ticket is null && rejectedReplay.Grant is null, "Rejected intent replay exposed authority.");

        var afterFirst = machine.Counters;
        var alertsAfterFirst = machine.CriticalAlerts.Count;
        var duplicate = machine.ReceiveChallengeAdmissionFailure(new ChallengeAdmissionFailure(failure.Version, failure.FailureId, failure.IntentId, failure.Subject, failure.WfpGeneration, failure.FailureKind, failure.ObservedAt));
        AssertTrue(duplicate.IsDuplicate, "Exact challenge admission failure duplicate was not idempotent.");
        AssertEqual(afterFirst, machine.Counters);
        AssertEqual(alertsAfterFirst, machine.CriticalAlerts.Count);

        var differentSubject = new GateSubject(1, new ProcessIdentity(90_001, sample.Start), "sha256:failure-mismatch", null, [new ProcessIdentity(90_001, sample.Start)]);
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallengeAdmissionFailure(new ChallengeAdmissionFailure(1, failure.FailureId, failure.IntentId, differentSubject, failure.WfpGeneration, failure.FailureKind, failure.ObservedAt)));
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, clock, nonces.NextNonce(), rejectedIntent)));
        AssertEqual(afterFirst, machine.Counters);
        AssertEqual(alertsAfterFirst, machine.CriticalAlerts.Count);

        var pendingIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 1_003);
        PrepareAwaitingChallenge(machine, sample, nonces, pendingIntent);
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallengeAdmissionFailure(new ChallengeAdmissionFailure(1, failure.FailureId, pendingIntent.IntentId, pendingIntent.Subject, sample.DriverGeneration, failure.FailureKind, clock.Now())));
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, clock, nonces.NextNonce(), pendingIntent, wfpGeneration: Guid.NewGuid())));
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, clock, nonces.NextNonce(), pendingIntent, subject: differentSubject)));
        var unknownIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 1_004);
        AssertThrows<InvalidOperationException>(() => machine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, clock, nonces.NextNonce(), unknownIntent)));
        AssertEqual(afterFirst.FailedOpenCount, machine.Counters.FailedOpenCount);
        AssertEqual(afterFirst.OverflowCount, machine.Counters.OverflowCount);
        AssertEqual(alertsAfterFirst, machine.CriticalAlerts.Count);
        AssertEqual(2, machine.Storage.ActiveContextCount);
        AssertEqual(1, machine.Storage.ChallengeMappingCount);

        var wrongPhaseClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var wrongPhaseNonces = new TestNonceProvider();
        using var wrongPhaseMachine = CreateOutboundGateMachine(sample, wrongPhaseClock, wrongPhaseNonces);
        var wrongPhaseIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 1_100);
        wrongPhaseMachine.ReceiveIntent(wrongPhaseIntent);
        AssertThrows<InvalidOperationException>(() => wrongPhaseMachine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, wrongPhaseClock, wrongPhaseNonces.NextNonce(), wrongPhaseIntent)));

        var authorityClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var authorityNonces = new TestNonceProvider();
        using var authorityMachine = CreateOutboundGateMachine(sample, authorityClock, authorityNonces);
        var authorityIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 1_101);
        var challenged = PrepareToChallenge(authorityMachine, sample, authorityClock, authorityNonces, authorityIntent);
        AssertThrows<InvalidOperationException>(() => authorityMachine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, authorityClock, authorityNonces.NextNonce(), authorityIntent)));
        var ticket = authorityMachine.ReceiveDecision(new UserDecision(1, authorityNonces.NextNonce(), challenged.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        AssertThrows<InvalidOperationException>(() => authorityMachine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, authorityClock, authorityNonces.NextNonce(), authorityIntent)));
        authorityMachine.RedeemTicket(ticket);
        AssertThrows<InvalidOperationException>(() => authorityMachine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, authorityClock, authorityNonces.NextNonce(), authorityIntent)));

        using var disabled = new OutboundGateStateMachine(clock, nonces, new TestAuditClock(sample.Start));
        AssertThrows<InvalidOperationException>(() => disabled.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, clock, nonces.NextNonce(), sample.Intent)));
        AssertEqual(new GateStateMachineCounters(0, 0, 0, 0), disabled.Counters);

        var boundedClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var boundedNonces = new TestNonceProvider();
        using var boundedMachine = CreateOutboundGateMachine(sample, boundedClock, boundedNonces);
        const int terminalAttempts = 300;
        for (var index = 0; index < terminalAttempts; index++)
        {
            var intent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 2_000 + index);
            PrepareAwaitingChallenge(boundedMachine, sample, boundedNonces, intent);
            var result = boundedMachine.ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailureFor(sample, boundedClock, boundedNonces.NextNonce(), intent));
            AssertEqual("challenge-admission-held-flow-capacity-exhausted", result.Status.ReasonCode);
        }
        AssertEqual(terminalAttempts, boundedMachine.Counters.FailedOpenCount);
        AssertEqual(terminalAttempts, boundedMachine.Counters.OverflowCount);
        AssertEqual(0, boundedMachine.Storage.ActiveContextCount);
        AssertEqual(0, boundedMachine.Storage.ChallengeMappingCount);
        AssertEqual(boundedMachine.Storage.TerminalHistoryCapacity, boundedMachine.Storage.TerminalHistoryCount);
        AssertEqual(boundedMachine.Storage.CriticalAlertCapacity, boundedMachine.Storage.CriticalAlertCount);
        return Task.CompletedTask;
    }

    private static Task TestPersistentDecisionResultContractAsync()
    {
        var sample = OutboundGateSamples();
        var decisionResult = new GateTransitionResult(sample.Status);
        var mutableStatuses = new List<GateStatus> { sample.Status };
        var result = new PersistentDecisionTransitionResult(1, decisionResult, mutableStatuses, 8, policyEpochAccepted: true);
        mutableStatuses.Clear();

        AssertEqual(1, result.Version);
        AssertEqual(decisionResult, result.DecisionResult);
        AssertEqual(1, result.InvalidatedStatuses.Count);
        AssertEqual(8L, result.PolicyEpoch);
        AssertTrue(result.PolicyEpochAccepted, "Accepted persistent result lost its epoch proof.");
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new PersistentDecisionTransitionResult(2, decisionResult, [], 8, true));
        AssertThrows<ArgumentNullException>(() => _ = new PersistentDecisionTransitionResult(1, null!, [], 8, true));
        AssertThrows<ArgumentException>(() => _ = new PersistentDecisionTransitionResult(1, new GateTransitionResult(null!), [], 8, true));
        AssertThrows<ArgumentOutOfRangeException>(() => _ = new PersistentDecisionTransitionResult(1, decisionResult, [], -1, true));
        AssertThrows<ArgumentException>(() => _ = new PersistentDecisionTransitionResult(1, decisionResult, null, 8, true));
        AssertThrows<ArgumentException>(() => _ = new PersistentDecisionTransitionResult(1, decisionResult, [null!], 8, true));
        AssertThrows<ArgumentException>(() => _ = new PersistentDecisionTransitionResult(1, decisionResult, [sample.Status], 7, false));
        AssertThrows<ArgumentException>(() => _ = new PersistentDecisionTransitionResult(
            1,
            decisionResult,
            Enumerable.Repeat(sample.Status, PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount + 1).ToArray(),
            8,
            true));

        var maximum = new PersistentDecisionTransitionResult(
            1,
            decisionResult,
            Enumerable.Repeat(sample.Status, PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount).ToArray(),
            8,
            true);
        AssertEqual(PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount, maximum.InvalidatedStatuses.Count);
        return Task.CompletedTask;
    }

    private static Task TestPersistentDecisionPrevalidationAsync()
    {
        var sample = OutboundGateSamples();
        var disabledDecision = PersistentDecisionFor(sample, sample.Challenge, Guid.NewGuid());
        using (var disabled = new OutboundGateStateMachine(new TestMonotonicClock(sample.ReadWindow.StartedAt), new TestNonceProvider(), new TestAuditClock(sample.Start)))
        {
            AssertThrows<ArgumentNullException>(() => disabled.ReceivePersistentDecision(null!, 1));
            AssertThrows<InvalidOperationException>(() => disabled.ReceivePersistentDecision(disabledDecision, 1));
            AssertEqual(0L, disabled.PolicyEpoch);
            AssertEqual(new GateStateMachineCounters(0, 0, 0, 0), disabled.Counters);
            AssertEqual(0, disabled.Storage.ActiveContextCount);
        }

        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var ticketService = CreateTicketService(sample, clock, nonces);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: ticketService);
        var prepared = PrepareToChallenge(machine, sample, clock, nonces);
        var valid = PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce());

        AssertThrows<ArgumentException>(() => _ = new UserDecision(1, Guid.NewGuid(), prepared.Challenge.ChallengeId, UserDecisionKind.AlwaysAllow, null, sample.Start, "test"));
        AssertThrows<ArgumentException>(() => _ = new RequestedPersistentScope(1, (PersistentAllowPolicyKind)99, sample.File, sample.Subject.ApplicationIdentity, sample.Destination));
        AssertPersistentPrevalidationRejected(machine, ticketService, new UserDecision(1, nonces.NextNonce(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test"), 8);

        var wrongFile = new FileVersionIdentity(1, sample.File.VolumeId, "other-file", sample.File.CreationTimeUtc, sample.File.SizeBytes, sample.File.LastWriteTimeUtc, sample.File.ChangeTimeUtc, sample.File.Usn, "other-version");
        AssertPersistentPrevalidationRejected(machine, ticketService, PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce(), file: wrongFile), 8);
        AssertPersistentPrevalidationRejected(machine, ticketService, PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce(), applicationIdentity: "sha256:other-application"), 8);
        var wrongDestination = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, sample.Destination.RemotePort + 1, sample.Destination.Protocol, NetworkTrafficDirection.Outbound, sample.Destination.NetworkCompartmentId, sample.Destination.InterfaceLuid, null, DomainEvidenceProvenance.None, null);
        AssertPersistentPrevalidationRejected(machine, ticketService, PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce(), destination: wrongDestination), 8);
        var wrongProtocol = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, sample.Destination.RemotePort, TransportProtocol.Udp, NetworkTrafficDirection.Outbound, sample.Destination.NetworkCompartmentId, sample.Destination.InterfaceLuid, null, DomainEvidenceProvenance.None, null);
        AssertPersistentPrevalidationRejected(machine, ticketService, PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce(), destination: wrongProtocol), 8);

        var unknown = PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce(), challengeId: Guid.NewGuid());
        var beforeUnknown = PersistentState(machine, ticketService);
        AssertThrows<InvalidOperationException>(() => machine.ReceivePersistentDecision(unknown, 8));
        AssertEqual(beforeUnknown, PersistentState(machine, ticketService));

        var subjectClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var subjectNonces = new TestNonceProvider();
        using var subjectService = CreateTicketService(sample, subjectClock, subjectNonces);
        using var subjectMachine = CreateOutboundGateMachine(sample, subjectClock, subjectNonces, ticketService: subjectService);
        var subjectIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 3_001);
        var subjectRead = PrepareAwaitingChallenge(subjectMachine, sample, subjectNonces, subjectIntent);
        var otherProcess = new ProcessIdentity(99, sample.Start);
        var wrongSubject = new GateSubject(1, otherProcess, sample.Subject.ApplicationIdentity, null, [otherProcess]);
        var wrongSubjectChallenge = new NetworkGateChallenge(1, subjectNonces.NextNonce(), subjectIntent.IntentId, wrongSubject, sample.Destination, 1, false, subjectRead.Request.RequiredCoverage, sample.Start, ServiceRange(subjectClock.Now().ClockInstanceId, subjectClock.Now().ElapsedMilliseconds, 15_000), "Simulation");
        AssertEqual(GateRuntimeState.FailedOpen, subjectMachine.ReceiveChallenge(wrongSubjectChallenge).Status.State);
        var subjectEpoch = subjectMachine.PolicyEpoch;
        AssertThrows<InvalidOperationException>(() => subjectMachine.ReceivePersistentDecision(PersistentDecisionFor(sample, wrongSubjectChallenge, subjectNonces.NextNonce()), 8));
        AssertEqual(subjectEpoch, subjectMachine.PolicyEpoch);
        AssertEqual(subjectEpoch, subjectService.PolicyEpoch);
        AssertEqual(0, subjectMachine.Storage.ActiveContextCount);

        foreach (var invalidEpoch in new[] { -1L, 7L, 6L, 9L })
        {
            var beforeEpoch = PersistentState(machine, ticketService);
            AssertThrows<ArgumentOutOfRangeException>(() => machine.ReceivePersistentDecision(valid, invalidEpoch));
            AssertEqual(beforeEpoch, PersistentState(machine, ticketService));
        }

        machine.ApplyPolicyEpoch(8);
        AssertEqual(0, machine.Storage.ActiveContextCount);

        var phaseClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var phaseNonces = new TestNonceProvider();
        using var phaseService = CreateTicketService(sample, phaseClock, phaseNonces);
        using var phaseMachine = CreateOutboundGateMachine(sample, phaseClock, phaseNonces, ticketService: phaseService);
        var phasePrepared = PrepareToChallenge(phaseMachine, sample, phaseClock, phaseNonces);
        phaseMachine.ReceiveDecision(new UserDecision(1, phaseNonces.NextNonce(), phasePrepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test"));
        var phaseBefore = PersistentState(phaseMachine, phaseService);
        AssertThrows<InvalidOperationException>(() => phaseMachine.ReceivePersistentDecision(PersistentDecisionFor(sample, phasePrepared.Challenge, phaseNonces.NextNonce()), 8));
        AssertEqual(phaseBefore, PersistentState(phaseMachine, phaseService));
        phaseMachine.ApplyPolicyEpoch(8);

        var overflowClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var overflowNonces = new TestNonceProvider();
        using var overflowService = CreateTicketService(sample, overflowClock, overflowNonces, long.MaxValue);
        using var overflowMachine = CreateOutboundGateMachine(sample, overflowClock, overflowNonces, long.MaxValue, ticketService: overflowService);
        var overflowPrepared = PrepareToChallenge(overflowMachine, sample, overflowClock, overflowNonces);
        var overflowBefore = PersistentState(overflowMachine, overflowService);
        AssertThrows<OverflowException>(() => overflowMachine.ReceivePersistentDecision(PersistentDecisionFor(sample, overflowPrepared.Challenge, overflowNonces.NextNonce()), long.MaxValue));
        AssertEqual(overflowBefore, PersistentState(overflowMachine, overflowService));
        overflowMachine.HandleServiceRestart(Guid.NewGuid());
        AssertEqual(0, overflowMachine.Storage.ActiveContextCount);
        return Task.CompletedTask;
    }

    private static Task TestPersistentDecisionDeadlineFailureAsync()
    {
        var sample = OutboundGateSamples();

        foreach (var offset in new[] { -1L, 0L, 1L })
        {
            var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
            var nonces = new TestNonceProvider();
            using var service = CreateTicketService(sample, clock, nonces);
            using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
            var selectedIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 5_000 + offset);
            var selected = PrepareToChallenge(machine, sample, clock, nonces, selectedIntent);
            var decision = PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce());

            if (offset < 0)
            {
                clock.Set(new ServiceMonotonicTimestamp(
                    1,
                    selected.Challenge.DecisionWindow.Deadline.ClockInstanceId,
                    selected.Challenge.DecisionWindow.Deadline.ElapsedMilliseconds + offset));
                var accepted = machine.ReceivePersistentDecision(decision, 8);
                AssertTrue(accepted.PolicyEpochAccepted, "A persistent decision immediately before the deadline was rejected.");
                AssertEqual(8L, accepted.PolicyEpoch);
                AssertEqual(8L, accepted.DecisionResult.Ticket!.PolicyEpoch);
                AssertEqual(8L, machine.PolicyEpoch);
                AssertEqual(0L, machine.Counters.FailedOpenCount);
                machine.ApplyPolicyEpoch(9);
                continue;
            }

            var unrelatedIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 6_000 + offset);
            clock.Advance(2);
            PrepareToChallenge(machine, sample, clock, nonces, unrelatedIntent);
            clock.Set(new ServiceMonotonicTimestamp(
                1,
                selected.Challenge.DecisionWindow.Deadline.ClockInstanceId,
                selected.Challenge.DecisionWindow.Deadline.ElapsedMilliseconds + offset));
            var beforeEpoch = machine.PolicyEpoch;
            var beforeServiceEpoch = service.PolicyEpoch;
            var failed = machine.ReceivePersistentDecision(decision, 8);

            AssertTrue(!failed.PolicyEpochAccepted, "A persistent decision at or after the deadline accepted its epoch.");
            AssertEqual(GateRuntimeState.FailedOpen, failed.DecisionResult.Status.State);
            AssertEqual("persistent-decision-clock-or-deadline-invalid", failed.DecisionResult.Status.ReasonCode);
            AssertTrue(failed.DecisionResult.CriticalAlert is not null, "Deadline failure did not publish a critical alert.");
            AssertTrue(failed.DecisionResult.Ticket is null && failed.DecisionResult.Grant is null, "Deadline failure created authority.");
            AssertEqual(beforeEpoch, failed.PolicyEpoch);
            AssertEqual(beforeEpoch, machine.PolicyEpoch);
            AssertEqual(beforeServiceEpoch, service.PolicyEpoch);
            AssertEqual(1L, machine.Counters.FailedOpenCount);
            AssertEqual(1, machine.CriticalAlerts.Count);
            AssertEqual(1, machine.Storage.ActiveContextCount);
            AssertEqual(1, machine.Storage.ChallengeMappingCount);
            AssertEqual(GateRuntimeState.AwaitingDecision, machine.ReceiveIntent(unrelatedIntent).Status.State);
            AssertEqual(GateRuntimeState.FailedOpen, machine.ReceiveIntent(selectedIntent).Status.State);
            AssertEqual(0, service.Snapshot.OutstandingGlobal);

            var stateAfterFailure = PersistentState(machine, service);
            var duplicate = machine.ReceivePersistentDecision(decision, 8);
            AssertTrue(duplicate.DecisionResult.IsDuplicate, "Repeated deadline failure was not identified as a duplicate.");
            AssertTrue(!duplicate.PolicyEpochAccepted, "Repeated deadline failure accepted its epoch.");
            AssertEqual(GateRuntimeState.FailedOpen, duplicate.DecisionResult.Status.State);
            AssertEqual(stateAfterFailure, PersistentState(machine, service));
            machine.ApplyPolicyEpoch(8);
        }

        var invalidClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var invalidNonces = new TestNonceProvider();
        using var invalidService = CreateTicketService(sample, invalidClock, invalidNonces);
        using var invalidMachine = CreateOutboundGateMachine(sample, invalidClock, invalidNonces, ticketService: invalidService);
        var invalidPrepared = PrepareToChallenge(invalidMachine, sample, invalidClock, invalidNonces);
        var invalidDecision = PersistentDecisionFor(sample, invalidPrepared.Challenge, invalidNonces.NextNonce());
        invalidClock.Set(new ServiceMonotonicTimestamp(1, Guid.NewGuid(), invalidClock.Now().ElapsedMilliseconds));
        var invalidResult = invalidMachine.ReceivePersistentDecision(invalidDecision, 8);
        AssertTrue(!invalidResult.PolicyEpochAccepted, "A clock-invalid persistent decision accepted its epoch.");
        AssertEqual(GateRuntimeState.FailedOpen, invalidResult.DecisionResult.Status.State);
        AssertEqual(7L, invalidMachine.PolicyEpoch);
        AssertEqual(7L, invalidService.PolicyEpoch);
        AssertEqual(0, invalidMachine.Storage.ActiveContextCount);
        AssertEqual(0, invalidMachine.Storage.ChallengeMappingCount);
        AssertEqual(1L, invalidMachine.Counters.FailedOpenCount);
        AssertEqual(1, invalidMachine.CriticalAlerts.Count);
        AssertEqual(0, invalidService.Snapshot.OutstandingGlobal);
        var invalidState = PersistentState(invalidMachine, invalidService);
        AssertTrue(invalidMachine.ReceivePersistentDecision(invalidDecision, 8).DecisionResult.IsDuplicate, "Clock-invalid replay was not idempotent.");
        AssertEqual(invalidState, PersistentState(invalidMachine, invalidService));
        return Task.CompletedTask;
    }

    private static Task TestRememberedDecisionCurrentEpochAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        var prepared = PrepareToChallenge(machine, sample, clock, nonces);
        var rememberedDecision = PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce());
        var issued = machine.ReceiveDecision(rememberedDecision);

        AssertTrue(issued.Ticket is not null, "An exact remembered AlwaysAllow decision did not issue a ticket.");
        AssertEqual(7L, issued.Ticket!.PolicyEpoch);
        AssertEqual(7L, machine.PolicyEpoch);
        AssertEqual(7L, service.PolicyEpoch);
        AssertEqual(1, service.Snapshot.OutstandingGlobal);
        AssertEqual(0, machine.Storage.ChallengeMappingCount);
        var duplicate = machine.ReceiveDecision(rememberedDecision);
        AssertTrue(duplicate.IsDuplicate, "An exact remembered decision duplicate was not detected.");
        AssertEqual(issued.Ticket.TicketId, duplicate.Ticket!.TicketId);
        AssertEqual(1, service.Snapshot.OutstandingGlobal);
        AssertThrows<InvalidOperationException>(() => machine.ReceiveDecision(PersistentDecisionFor(sample, prepared.Challenge, nonces.NextNonce())));
        AssertEqual(1, service.Snapshot.OutstandingGlobal);

        var bindingClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var bindingNonces = new TestNonceProvider();
        using var bindingService = CreateTicketService(sample, bindingClock, bindingNonces);
        using var bindingMachine = CreateOutboundGateMachine(sample, bindingClock, bindingNonces, ticketService: bindingService);
        var bindingPrepared = PrepareToChallenge(bindingMachine, sample, bindingClock, bindingNonces);
        var wrongFile = new FileVersionIdentity(1, sample.File.VolumeId, "wrong-file", sample.File.CreationTimeUtc, sample.File.SizeBytes, sample.File.LastWriteTimeUtc, sample.File.ChangeTimeUtc, sample.File.Usn, "wrong-version");
        var beforeBinding = PersistentState(bindingMachine, bindingService);
        AssertThrows<InvalidOperationException>(() => bindingMachine.ReceiveDecision(PersistentDecisionFor(sample, bindingPrepared.Challenge, bindingNonces.NextNonce(), file: wrongFile)));
        AssertEqual(beforeBinding, PersistentState(bindingMachine, bindingService));
        AssertEqual(7L, bindingMachine.ReceiveDecision(PersistentDecisionFor(sample, bindingPrepared.Challenge, bindingNonces.NextNonce())).Ticket!.PolicyEpoch);

        var allowClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var allowNonces = new TestNonceProvider();
        using var allowMachine = CreateOutboundGateMachine(sample, allowClock, allowNonces);
        var allowPrepared = PrepareToChallenge(allowMachine, sample, allowClock, allowNonces);
        var allowOnce = allowMachine.ReceiveDecision(new UserDecision(1, allowNonces.NextNonce(), allowPrepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test"));
        AssertEqual(7L, allowOnce.Ticket!.PolicyEpoch);

        var blockClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var blockNonces = new TestNonceProvider();
        using var blockMachine = CreateOutboundGateMachine(sample, blockClock, blockNonces);
        var blockPrepared = PrepareToChallenge(blockMachine, sample, blockClock, blockNonces);
        var blocked = blockMachine.ReceiveDecision(new UserDecision(1, blockNonces.NextNonce(), blockPrepared.Challenge.ChallengeId, UserDecisionKind.Block, null, sample.Start, "test"));
        AssertEqual(GateRuntimeState.Blocked, blocked.Status.State);
        AssertTrue(blocked.Ticket is null, "Block created a ticket.");

        var persistentClock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var persistentNonces = new TestNonceProvider();
        using var persistentService = CreateTicketService(sample, persistentClock, persistentNonces);
        using var persistentMachine = CreateOutboundGateMachine(sample, persistentClock, persistentNonces, ticketService: persistentService);
        var persistentPrepared = PrepareToChallenge(persistentMachine, sample, persistentClock, persistentNonces);
        var persistent = persistentMachine.ReceivePersistentDecision(PersistentDecisionFor(sample, persistentPrepared.Challenge, persistentNonces.NextNonce()), 8);
        AssertTrue(persistent.PolicyEpochAccepted, "The persistent transition regressed.");
        AssertEqual(8L, persistent.DecisionResult.Ticket!.PolicyEpoch);
        return Task.CompletedTask;
    }

    private static Task TestPersistentDecisionAtomicSuccessAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);

        var awaitingIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 4_001);
        PrepareToChallenge(machine, sample, clock, nonces, awaitingIntent);
        var ticketIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 4_002);
        var ticketChallenge = PrepareToChallenge(machine, sample, clock, nonces, ticketIntent);
        var oldTicket = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), ticketChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        var grantIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 4_003);
        var grantChallenge = PrepareToChallenge(machine, sample, clock, nonces, grantIntent);
        var grantTicket = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), grantChallenge.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "test")).Ticket!;
        var oldGrant = machine.RedeemTicket(grantTicket).Grant!;
        var selectedIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 4_004);
        var selected = PrepareToChallenge(machine, sample, clock, nonces, selectedIntent);

        var result = machine.ReceivePersistentDecision(PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce()), 8);
        AssertTrue(result.PolicyEpochAccepted, "Atomic transition did not prove epoch acceptance.");
        AssertEqual(8L, result.PolicyEpoch);
        AssertEqual(8L, machine.PolicyEpoch);
        AssertEqual(8L, service.PolicyEpoch);
        AssertEqual(3, result.InvalidatedStatuses.Count);
        AssertEqual(2, result.InvalidatedStatuses.Count(status => status.State == GateRuntimeState.FailedOpen));
        AssertEqual(1, result.InvalidatedStatuses.Count(status => status.State == GateRuntimeState.Blocked));
        AssertTrue(result.DecisionResult.Ticket is not null, "Selected context did not receive a ticket.");
        AssertEqual(8L, result.DecisionResult.Ticket!.PolicyEpoch);
        AssertEqual(1, machine.Storage.ActiveContextCount);
        AssertEqual(0, machine.Storage.ChallengeMappingCount);
        AssertEqual(1, service.Snapshot.OutstandingGlobal);
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);
        AssertThrows<InvalidOperationException>(() => machine.RedeemTicket(oldTicket));
        AssertThrows<InvalidOperationException>(() => machine.RedeemTicket(grantTicket));
        AssertEqual(TicketServiceResultKind.Rejected, service.TryRedeem(oldTicket, TicketBinding(sample, intentId: ticketIntent.IntentId, policyEpoch: 7)).Kind);
        AssertEqual(7L, oldGrant.PolicyEpoch);
        AssertEqual(8L, result.DecisionResult.Ticket.PolicyEpoch);

        AssertEqual(0, machine.ApplyPolicyEpoch(8).Count);
        AssertEqual(GateRuntimeState.AwaitingDecision, machine.ReceiveIntent(selectedIntent).Status.State);
        AssertEqual(GateRuntimeState.FailedOpen, machine.ApplyPolicyEpoch(9).Single().State);
        AssertEqual(0, machine.Storage.ActiveContextCount);
        AssertEqual(0, service.Snapshot.OutstandingGlobal);
        return Task.CompletedTask;
    }

    private static Task TestPersistentDecisionEffectiveEpochAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        var selected = PrepareToChallenge(machine, sample, clock, nonces);
        var decision = PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce());
        var accepted = machine.ReceivePersistentDecision(decision, 8);
        var ticket = accepted.DecisionResult.Ticket!;

        AssertEqual(7L, accepted.DecisionResult.ArmRequest!.PolicyEpoch);
        AssertEqual(8L, ticket.PolicyEpoch);
        AssertEqual(0, machine.ApplyPolicyEpoch(8).Count);
        AssertEqual(1, machine.Storage.ActiveContextCount);
        AssertEqual(GateRuntimeState.Granted, machine.RedeemTicket(ticket).Status.State);
        AssertEqual(0, machine.ApplyPolicyEpoch(8).Count);
        AssertEqual(GateRuntimeState.Blocked, machine.ApplyPolicyEpoch(9).Single().State);
        AssertEqual(0, machine.Storage.ActiveContextCount);
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);
        return Task.CompletedTask;
    }

    private static Task TestPersistentDecisionTicketCapacityAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        var policyEpoch = 7L;
        using var service = CreateTicketService(sample, clock, nonces, policyEpoch);
        for (var index = 0; index < OneTimeGateTicketService.MaximumReplayTombstonesGlobal; index++)
        {
            var binding = TicketBinding(sample, intentId: Guid.NewGuid(), policyEpoch: policyEpoch);
            var issued = service.TryIssue(binding);
            AssertEqual(TicketServiceResultKind.Success, issued.Kind);
            AssertEqual(TicketServiceResultKind.Success, service.TryRedeem(issued.Ticket!, binding).Kind);
            if ((index + 1) % OneTimeGateTicketService.MaximumActiveGrantsGlobal == 0
                && index + 1 < OneTimeGateTicketService.MaximumReplayTombstonesGlobal)
            {
                policyEpoch++;
                service.ApplyPolicyEpoch(policyEpoch);
            }
        }
        AssertEqual(OneTimeGateTicketService.MaximumReplayTombstonesGlobal, service.Snapshot.ReplayTombstones);

        using var machine = CreateOutboundGateMachine(sample, clock, nonces, policyEpoch, ticketService: service);
        var selected = PrepareToChallenge(machine, sample, clock, nonces);
        var before = machine.Counters;
        var result = machine.ReceivePersistentDecision(PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce()), checked(policyEpoch + 1));
        AssertTrue(result.PolicyEpochAccepted, "Ticket-capacity failure incorrectly rolled back the accepted epoch.");
        AssertEqual(policyEpoch + 1, result.PolicyEpoch);
        AssertEqual(policyEpoch + 1, machine.PolicyEpoch);
        AssertEqual(policyEpoch + 1, service.PolicyEpoch);
        AssertEqual(GateRuntimeState.FailedOpen, result.DecisionResult.Status.State);
        AssertTrue(result.DecisionResult.Status.TrafficFailedOpen, "Ticket-capacity failure did not report fail-open traffic.");
        AssertEqual("ticket-tombstone-capacity-exhausted", result.DecisionResult.Status.ReasonCode);
        AssertEqual(before.FailedOpenCount + 1, machine.Counters.FailedOpenCount);
        AssertEqual(before.OverflowCount + 1, machine.Counters.OverflowCount);
        AssertEqual(0, machine.Storage.ActiveContextCount);
        AssertEqual(0, service.Snapshot.OutstandingGlobal);
        AssertEqual(0, service.Snapshot.ActiveGrantReservations);
        machine.HandleServiceRestart(Guid.NewGuid());
        AssertEqual(0, service.Snapshot.ReplayTombstones);
        return Task.CompletedTask;
    }

    private static async Task TestPersistentDecisionConcurrencyAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        var selected = PrepareToChallenge(machine, sample, clock, nonces);
        var decision = PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce());
        using var barrier = new Barrier(3);

        var firstTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            return machine.ReceivePersistentDecision(decision, 8);
        });
        var secondTask = Task.Run(() =>
        {
            barrier.SignalAndWait();
            return machine.ReceivePersistentDecision(decision, 8);
        });
        barrier.SignalAndWait();
        var results = await Task.WhenAll(firstTask, secondTask).ConfigureAwait(false);

        AssertEqual(1, results.Count(result => !result.DecisionResult.IsDuplicate));
        AssertEqual(1, results.Count(result => result.DecisionResult.IsDuplicate));
        AssertTrue(results.All(result => result.PolicyEpochAccepted && result.PolicyEpoch == 8), "Concurrent exact calls disagreed on epoch acceptance.");
        AssertEqual(results[0].DecisionResult.Ticket!.TicketId, results[1].DecisionResult.Ticket!.TicketId);
        AssertEqual(8L, machine.PolicyEpoch);
        AssertEqual(1, service.Snapshot.OutstandingGlobal);
        AssertEqual(0L, machine.Counters.FailedOpenCount);
        AssertEqual(0, machine.CriticalAlerts.Count);

        var beforeMismatch = PersistentState(machine, service);
        AssertThrows<InvalidOperationException>(() => machine.ReceivePersistentDecision(PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce()), 8));
        AssertThrows<InvalidOperationException>(() => machine.ReceivePersistentDecision(decision, 9));
        AssertEqual(beforeMismatch, PersistentState(machine, service));
        machine.ApplyPolicyEpoch(9);
        AssertEqual(0, machine.Storage.ActiveContextCount);
    }

    private static Task TestPersistentDecisionInvalidationBoundAsync()
    {
        var sample = OutboundGateSamples();
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var service = CreateTicketService(sample, clock, nonces);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        for (var index = 0; index < PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount; index++)
        {
            var intent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 10_000 + index);
            PrepareAwaitingChallenge(machine, sample, nonces, intent);
        }
        var selectedIntent = IntentFor(sample, Guid.NewGuid(), sample.Subject, 20_000);
        var selected = PrepareToChallenge(machine, sample, clock, nonces, selectedIntent);
        AssertEqual(256, machine.Storage.ActiveContextCount);

        var result = machine.ReceivePersistentDecision(PersistentDecisionFor(sample, selected.Challenge, nonces.NextNonce()), 8);
        AssertEqual(PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount, result.InvalidatedStatuses.Count);
        AssertTrue(result.InvalidatedStatuses.All(status => status.State == GateRuntimeState.FailedOpen), "Bounded invalidation returned a non-fail-open old context.");
        AssertEqual(1, machine.Storage.ActiveContextCount);
        AssertEqual(0, machine.Storage.ChallengeMappingCount);
        AssertEqual(PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount, machine.Counters.FailedOpenCount);
        machine.ApplyPolicyEpoch(9);
        AssertEqual(0, machine.Storage.ActiveContextCount);
        AssertEqual(0, service.Snapshot.OutstandingGlobal);
        return Task.CompletedTask;
    }

    private static async Task TestOutboundGateSimulatorAcceptanceAsync()
    {
        string[] expectedNames =
        [
            "disabled-default-zero-state", "happy-new-tcp", "happy-new-udp", "release-requires-full-ack", "completion-requires-exact-binding", "existing-tcp-reconnect-required", "existing-udp-reconnect-required", "existing-quic-reconnect-required", "delay-before-deadline-succeeds", "delay-at-deadline-fails-open", "drop-times-out-deterministically", "minifilter-crash-restart-cleans", "wfp-crash-restart-cleans", "service-restart-cleans", "stale-wfp-generation-rejected", "stale-minifilter-generation-rejected", "pending-read-subject-cap", "pending-read-global-cap", "challenge-subject-cap", "challenge-global-cap", "endpoint-channel-boundaries", "held-flow-entry-boundaries", "held-data-flow-cap", "held-data-global-cap", "scheduler-cap", "fault-plan-cap", "pump-dispatch-budget", "ticket-replay-through-endpoint", "ticket-capacity-through-endpoint", "grant-expiry-and-byte-count", "policy-change-cleans-endpoints", "privacy-metadata-only", "no-wall-clock-or-event-workers", "all-faults-finish-zero-owned-state"
        ];
        var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var simulatorDirectory = Path.Combine(repositoryRoot, "tools", "EgressGuard.OutboundGateSimulator");
        var simulatorExecutable = Path.Combine(simulatorDirectory, "bin", "Release", "net8.0-windows", "EgressGuard.OutboundGateSimulator.exe");
        AssertTrue(File.Exists(simulatorExecutable), "The independently built simulator executable was not found.");

        var disabled = await RunSimulatorAsync(simulatorExecutable).ConfigureAwait(false);
        AssertEqual(0, disabled.ExitCode);
        AssertTrue(string.IsNullOrEmpty(disabled.StandardError), "Disabled-default invocation wrote stderr.");
        using (var disabledJson = JsonDocument.Parse(disabled.StandardOutput))
        {
            var root = disabledJson.RootElement;
            AssertEqual(0, root.GetProperty("Mode").GetInt32());
            AssertEqual(0, root.GetProperty("OwnedOperationCount").GetInt32());
            AssertEqual(0, root.GetProperty("CoreActiveContextCount").GetInt32());
            AssertEqual(0, root.GetProperty("InstalledGrantCount").GetInt32());
        }

        var firstSuite = await RunSimulatorAsync(simulatorExecutable, "--acceptance-suite", "--json").ConfigureAwait(false);
        var secondSuite = await RunSimulatorAsync(simulatorExecutable, "--acceptance-suite", "--json").ConfigureAwait(false);
        AssertEqual(0, firstSuite.ExitCode);
        AssertEqual(0, secondSuite.ExitCode);
        AssertTrue(string.IsNullOrEmpty(firstSuite.StandardError) && string.IsNullOrEmpty(secondSuite.StandardError), "Acceptance suite wrote stderr.");
        AssertEqual(firstSuite.StandardOutput, secondSuite.StandardOutput);
        using (var suiteJson = JsonDocument.Parse(firstSuite.StandardOutput))
        {
            var root = suiteJson.RootElement;
            AssertEqual(expectedNames.Length, root.GetProperty("Total").GetInt32());
            AssertEqual(expectedNames.Length, root.GetProperty("Passed").GetInt32());
            var scenarios = root.GetProperty("Scenarios").EnumerateArray().ToArray();
            AssertTrue(scenarios.Select(item => item.GetProperty("Name").GetString()).SequenceEqual(expectedNames), "Simulator scenario names/order differ from the 34 locked cases.");
            AssertTrue(scenarios.All(item => item.GetProperty("Passed").GetBoolean()), "The simulator acceptance suite contained a failing scenario.");
            var snapshots = scenarios.ToDictionary(
                item => item.GetProperty("Name").GetString() ?? throw new InvalidOperationException("Simulator scenario omitted its name."),
                item => item.GetProperty("Snapshot"),
                StringComparer.Ordinal);

            var challengeSubject = snapshots["challenge-subject-cap"];
            AssertEqual(1L, challengeSubject.GetProperty("OverflowCount").GetInt64());
            AssertTrue(challengeSubject.GetProperty("CriticalAlertCount").GetInt64() > 0, "Subject challenge cap omitted Critical Alert evidence.");
            AssertEqual(5L, challengeSubject.GetProperty("AcceptedReadCount").GetInt64());
            AssertEqual(5L, challengeSubject.GetProperty("ReleasedReadCount").GetInt64());
            AssertEqual(4L, challengeSubject.GetProperty("AcceptedFlowCount").GetInt64());
            AssertEqual(4L, challengeSubject.GetProperty("ReleasedFlowCount").GetInt64());
            AssertEqual(4L, challengeSubject.GetProperty("ChallengeCreatedCount").GetInt64());
            AssertEqual(4L, challengeSubject.GetProperty("ChallengeDeliveredCount").GetInt64());
            AssertEqual(1L, challengeSubject.GetProperty("ServiceRestartCount").GetInt64());
            AssertSimulatorSnapshotClean(challengeSubject, "subject challenge cap cleanup");

            var challengeGlobal = snapshots["challenge-global-cap"];
            AssertEqual(1L, challengeGlobal.GetProperty("OverflowCount").GetInt64());
            AssertTrue(challengeGlobal.GetProperty("CriticalAlertCount").GetInt64() > 0, "Global challenge cap omitted Critical Alert evidence.");
            AssertEqual(129L, challengeGlobal.GetProperty("AcceptedReadCount").GetInt64());
            AssertEqual(129L, challengeGlobal.GetProperty("ReleasedReadCount").GetInt64());
            AssertEqual(128L, challengeGlobal.GetProperty("AcceptedFlowCount").GetInt64());
            AssertEqual(128L, challengeGlobal.GetProperty("ReleasedFlowCount").GetInt64());
            AssertEqual(128L, challengeGlobal.GetProperty("ChallengeCreatedCount").GetInt64());
            AssertEqual(128L, challengeGlobal.GetProperty("ChallengeDeliveredCount").GetInt64());
            AssertEqual(1L, challengeGlobal.GetProperty("ServiceRestartCount").GetInt64());
            AssertSimulatorSnapshotClean(challengeGlobal, "global challenge cap cleanup");

            var serviceRestart = snapshots["service-restart-cleans"];
            AssertEqual(0, serviceRestart.GetProperty("FaultPlanCount").GetInt32());
            AssertEqual(8L, serviceRestart.GetProperty("ServiceRestartCount").GetInt64());
            AssertEqual(2L, serviceRestart.GetProperty("AcceptedReadCount").GetInt64());
            AssertEqual(2L, serviceRestart.GetProperty("ReleasedReadCount").GetInt64());
            AssertSimulatorSnapshotClean(serviceRestart, "service restart cleanup");

            var endpointChannels = snapshots["endpoint-channel-boundaries"];
            AssertEqual(1L, endpointChannels.GetProperty("OverflowCount").GetInt64());
            AssertTrue(endpointChannels.GetProperty("CriticalAlertCount").GetInt64() > 0, "Endpoint channel cap omitted Critical Alert evidence.");
            AssertEqual(1L, endpointChannels.GetProperty("ServiceRestartCount").GetInt64());
            AssertSimulatorSnapshotClean(endpointChannels, "endpoint channel cleanup");

            var scheduler = snapshots["scheduler-cap"];
            AssertEqual(1L, scheduler.GetProperty("OverflowCount").GetInt64());
            AssertTrue(scheduler.GetProperty("CriticalAlertCount").GetInt64() > 0, "Scheduler cap omitted Critical Alert evidence.");
            AssertEqual(1L, scheduler.GetProperty("ServiceRestartCount").GetInt64());
            AssertSimulatorSnapshotClean(scheduler, "scheduler cap cleanup");

            var faultPlan = snapshots["fault-plan-cap"];
            AssertEqual(0, faultPlan.GetProperty("FaultPlanCount").GetInt32());
            AssertEqual(1L, faultPlan.GetProperty("OverflowCount").GetInt64());
            AssertTrue(faultPlan.GetProperty("CriticalAlertCount").GetInt64() > 0, "Fault-plan cap omitted Critical Alert evidence.");
            AssertEqual(1L, faultPlan.GetProperty("ServiceRestartCount").GetInt64());
            AssertSimulatorSnapshotClean(faultPlan, "fault-plan cleanup");

            var ticketCapacity = snapshots["ticket-capacity-through-endpoint"];
            AssertEqual(1L, ticketCapacity.GetProperty("AcceptedReadCount").GetInt64());
            AssertEqual(1L, ticketCapacity.GetProperty("ReleasedReadCount").GetInt64());
            AssertEqual(1L, ticketCapacity.GetProperty("AcceptedFlowCount").GetInt64());
            AssertEqual(1L, ticketCapacity.GetProperty("ReleasedFlowCount").GetInt64());
            AssertEqual(1L, ticketCapacity.GetProperty("FailedOpenOperationCount").GetInt64());
            AssertTrue(ticketCapacity.GetProperty("CriticalAlertCount").GetInt64() > 0, "Ticket capacity omitted Critical Alert evidence.");
            AssertEqual(1L, ticketCapacity.GetProperty("ServiceRestartCount").GetInt64());
            AssertSimulatorSnapshotClean(ticketCapacity, "ticket/grant capacity cleanup");

            var allFaults = snapshots["all-faults-finish-zero-owned-state"];
            AssertEqual(300L, allFaults.GetProperty("OverflowCount").GetInt64());
            AssertEqual(300L, allFaults.GetProperty("FailedOpenOperationCount").GetInt64());
            AssertTrue(allFaults.GetProperty("CriticalAlertCount").GetInt64() > 0, "All-fault fixture omitted Critical Alert evidence.");
            AssertSimulatorSnapshotClean(allFaults, "all-fault common cleanup");

            var final = root.GetProperty("FinalSnapshot");
            AssertEqual(0, final.GetProperty("PendingReadCount").GetInt32());
            AssertEqual(0, final.GetProperty("HeldFlowCount").GetInt32());
            AssertEqual(0, final.GetProperty("ScheduledCount").GetInt32());
            AssertEqual(0, final.GetProperty("OwnedOperationCount").GetInt32());
            AssertEqual(expectedNames.Length, final.GetProperty("AcceptanceResultCount").GetInt32());
        }

        foreach (var scenarioName in new[] { "happy-new-tcp", "challenge-subject-cap", "challenge-global-cap", "privacy-metadata-only", "all-faults-finish-zero-owned-state" })
        {
            var scenario = await RunSimulatorAsync(simulatorExecutable, "--scenario", scenarioName, "--json").ConfigureAwait(false);
            AssertEqual(0, scenario.ExitCode);
            AssertTrue(string.IsNullOrEmpty(scenario.StandardError), $"Scenario {scenarioName} wrote stderr.");
            using var scenarioJson = JsonDocument.Parse(scenario.StandardOutput);
            AssertEqual(scenarioName, scenarioJson.RootElement.GetProperty("Name").GetString());
            AssertTrue(scenarioJson.RootElement.GetProperty("Passed").GetBoolean(), $"Scenario {scenarioName} failed.");
        }

        var invalid = await RunSimulatorAsync(simulatorExecutable, "--invalid").ConfigureAwait(false);
        AssertEqual(2, invalid.ExitCode);
        AssertTrue(string.IsNullOrWhiteSpace(invalid.StandardOutput), "Invalid arguments wrote JSON/stdout.");
        AssertTrue(invalid.StandardError.Contains("Usage:", StringComparison.Ordinal), "Invalid arguments omitted usage stderr.");

        var simulatorSource = File.ReadAllText(Path.Combine(simulatorDirectory, "Program.cs"));
        foreach (var forbiddenField in new[] { "Payload", "Content", "RawPath", "FilePath", "Packet", "Buffer", "TicketSecret" })
        {
            AssertTrue(!Regex.IsMatch(simulatorSource, $@"\b{Regex.Escape(forbiddenField)}\b", RegexOptions.CultureInvariant), $"Simulator source declares forbidden field {forbiddenField}.");
            AssertTrue(!Regex.IsMatch(firstSuite.StandardOutput, $"\\\"{Regex.Escape(forbiddenField)}\\\"\\s*:", RegexOptions.CultureInvariant), $"Simulator JSON exposes forbidden field {forbiddenField}.");
        }
        AssertTrue(!firstSuite.StandardOutput.Contains("AuthenticatorProof", StringComparison.Ordinal), "Simulator JSON exposed ticket proof material.");
        AssertTrue(!firstSuite.StandardOutput.Contains("SimulationStepResult", StringComparison.Ordinal), "Simulator JSON exposed internal transition results.");
        AssertTrue(!firstSuite.StandardOutput.Contains("real enforcement", StringComparison.OrdinalIgnoreCase), "Simulator output claimed real enforcement.");
        AssertTrue(!simulatorSource.Contains("Guid.NewGuid", StringComparison.Ordinal), "Simulator source uses nondeterministic identifiers.");
        AssertTrue(!simulatorSource.Contains("Task.Delay", StringComparison.Ordinal) && !simulatorSource.Contains("Thread.Sleep", StringComparison.Ordinal) && !simulatorSource.Contains("DateTimeOffset.UtcNow", StringComparison.Ordinal), "Simulator source uses wall-clock scheduling.");
        var submitFlowStart = simulatorSource.IndexOf("private SimulationStepResult SubmitFlowCore", StringComparison.Ordinal);
        var submitFlowEnd = simulatorSource.IndexOf("public SimulationStepResult SubmitDecision", submitFlowStart, StringComparison.Ordinal);
        AssertTrue(submitFlowStart >= 0 && submitFlowEnd > submitFlowStart, "Simulator SubmitFlowCore source boundary was not found.");
        var submitFlowSource = simulatorSource[submitFlowStart..submitFlowEnd];
        var wfpReservation = submitFlowSource.IndexOf("_wfp.ObserveFlow(flow)", StringComparison.Ordinal);
        var challengeCreation = submitFlowSource.IndexOf("new NetworkGateChallenge", StringComparison.Ordinal);
        AssertTrue(wfpReservation >= 0 && challengeCreation > wfpReservation, "SubmitFlowCore must reserve the held flow before creating a Core challenge.");
        AssertTrue(!submitFlowSource[..wfpReservation].Contains("NetworkGateChallenge", StringComparison.Ordinal), "SubmitFlowCore created challenge material before WFP reservation.");
        AssertTrue(!submitFlowSource.Contains("RejectAtChallengeCapacity", StringComparison.Ordinal), "Simulator retained the pre-reservation fake challenge transition.");
    }

    private static void AssertSimulatorSnapshotClean(JsonElement snapshot, string context)
    {
        foreach (var countName in new[]
        {
            "PendingReadCount", "ActiveChallengeCount", "HeldFlowCount", "ScheduledCount", "OwnedOperationCount",
            "HostOwnershipCount", "SchedulerOwnerCount", "CoreActiveContextCount", "OutstandingTicketCount",
            "ActiveGrantReservationCount", "InstalledGrantCount", "FaultPlanCount", "MinifilterIntentOutboxCount",
            "MinifilterDispositionInboxCount", "MinifilterCompletionAckOutboxCount", "WfpGateArmInboxCount",
            "WfpGateAckOutboxCount", "WfpFlowObservationInboxCount", "WfpChallengeOutboxCount"
        })
            AssertTrue(snapshot.GetProperty(countName).GetInt32() == 0, $"{context} retained {countName}.");
        AssertTrue(snapshot.GetProperty("HeldByteCount").GetInt64() == 0, $"{context} retained held bytes.");
        AssertTrue(snapshot.GetProperty("AcceptedReadCount").GetInt64() == snapshot.GetProperty("ReleasedReadCount").GetInt64(), $"{context} left read counters unbalanced.");
        AssertTrue(snapshot.GetProperty("AcceptedFlowCount").GetInt64() == snapshot.GetProperty("ReleasedFlowCount").GetInt64(), $"{context} left flow counters unbalanced.");
    }

    private static async Task<(int ExitCode, string StandardOutput, string StandardError)> RunSimulatorAsync(string executable, params string[] arguments)
    {
        var startInfo = new ProcessStartInfo(executable)
        {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };
        foreach (var argument in arguments)
            startInfo.ArgumentList.Add(argument);
        using var process = Process.Start(startInfo) ?? throw new InvalidOperationException("Unable to start the simulator executable.");
        var standardOutput = process.StandardOutput.ReadToEndAsync();
        var standardError = process.StandardError.ReadToEndAsync();
        try
        {
            await process.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45)).ConfigureAwait(false);
        }
        catch (TimeoutException)
        {
            process.Kill(entireProcessTree: true);
            throw new InvalidOperationException("Simulator executable exceeded the safety timeout.");
        }
        return (process.ExitCode, await standardOutput.ConfigureAwait(false), await standardError.ConfigureAwait(false));
    }

    private static async Task TestPolicyRaceAsync(OutboundGateSample sample)
    {
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var authenticator = new BlockingTestTicketAuthenticator(sample.Boot);
        using var service = new OneTimeGateTicketService(clock, new TestAuditClock(sample.Start), nonces, authenticator, 7);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        var prepared = PrepareToChallenge(machine, sample, clock, nonces, IntentFor(sample, Guid.NewGuid(), sample.Subject, 902));
        var issued = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "policy-race"));
        authenticator.BlockVerification();
        var redemptionTask = Task.Run(() => machine.RedeemTicket(issued.Ticket!));
        authenticator.VerificationEntered.Wait();
        var policyTask = Task.Run(() => machine.ApplyPolicyEpoch(8));
        authenticator.ReleaseVerification();
        var redeemed = await redemptionTask.ConfigureAwait(false);
        var policyStatuses = await policyTask.ConfigureAwait(false);
        AssertEqual(GateRuntimeState.Granted, redeemed.Status.State);
        AssertEqual(1, policyStatuses.Count);
        AssertEqual(GateRuntimeState.Blocked, policyStatuses[0].State);
        AssertEqual(8L, machine.PolicyEpoch);
    }

    private static async Task TestRestartRaceAsync(OutboundGateSample sample)
    {
        var clock = new TestMonotonicClock(sample.ReadWindow.StartedAt);
        var nonces = new TestNonceProvider();
        using var authenticator = new BlockingTestTicketAuthenticator(sample.Boot);
        using var service = new OneTimeGateTicketService(clock, new TestAuditClock(sample.Start), nonces, authenticator, 7);
        using var machine = CreateOutboundGateMachine(sample, clock, nonces, ticketService: service);
        var prepared = PrepareToChallenge(machine, sample, clock, nonces, IntentFor(sample, Guid.NewGuid(), sample.Subject, 903));
        var issued = machine.ReceiveDecision(new UserDecision(1, nonces.NextNonce(), prepared.Challenge.ChallengeId, UserDecisionKind.AllowOnce, null, sample.Start, "restart-race"));
        authenticator.BlockVerification();
        var redemptionTask = Task.Run(() => machine.RedeemTicket(issued.Ticket!));
        authenticator.VerificationEntered.Wait();
        var newRuntime = new OutboundGateTrustedRuntimeState(Guid.NewGuid(), sample.DriverGeneration, sample.MinifilterGeneration);
        var restartTask = Task.Run(() => machine.HandleServiceRestart(newRuntime));
        authenticator.ReleaseVerification();
        var redeemed = await redemptionTask.ConfigureAwait(false);
        var restartStatuses = await restartTask.ConfigureAwait(false);
        AssertEqual(GateRuntimeState.Granted, redeemed.Status.State);
        AssertEqual(1, restartStatuses.Count);
        AssertEqual(GateRuntimeState.Blocked, restartStatuses[0].State);
        AssertEqual(newRuntime.BootInstance, machine.TrustedRuntime!.BootInstance);
    }

    private static OneTimeGateTicketService CreateTicketService(OutboundGateSample sample, TestMonotonicClock clock, TestNonceProvider nonces, long policyEpoch = 7) =>
        new(clock, new TestAuditClock(sample.Start), nonces, new DeterministicTestTicketAuthenticator(sample.Boot), policyEpoch);

    private static UserDecision PersistentDecisionFor(
        OutboundGateSample sample,
        NetworkGateChallenge challenge,
        Guid decisionId,
        Guid? challengeId = null,
        FileVersionIdentity? file = null,
        string? applicationIdentity = null,
        DestinationBinding? destination = null)
    {
        var scope = new RequestedPersistentScope(
            1,
            PersistentAllowPolicyKind.RememberFor30Days,
            file ?? sample.File,
            applicationIdentity ?? challenge.Subject.ApplicationIdentity,
            destination ?? challenge.Destination);
        return new UserDecision(1, decisionId, challengeId ?? challenge.ChallengeId, UserDecisionKind.AlwaysAllow, scope, sample.Start, "test");
    }

    private static void AssertPersistentPrevalidationRejected(
        OutboundGateStateMachine machine,
        OneTimeGateTicketService ticketService,
        UserDecision decision,
        long nextPolicyEpoch)
    {
        var before = PersistentState(machine, ticketService);
        var result = machine.ReceivePersistentDecision(decision, nextPolicyEpoch);
        AssertTrue(!result.PolicyEpochAccepted, "Prevalidation rejection incorrectly accepted the policy epoch.");
        AssertEqual(before.MachinePolicyEpoch, result.PolicyEpoch);
        AssertEqual(0, result.InvalidatedStatuses.Count);
        AssertEqual(GateRuntimeState.AwaitingDecision, result.DecisionResult.Status.State);
        AssertEqual(before, PersistentState(machine, ticketService));
    }

    private static PersistentStateSnapshot PersistentState(OutboundGateStateMachine machine, OneTimeGateTicketService ticketService) =>
        new(machine.PolicyEpoch, ticketService.PolicyEpoch, machine.Counters, machine.Storage, ticketService.Snapshot, machine.CriticalAlerts.Count);

    private static TicketAuthorizationBinding TicketBinding(OutboundGateSample sample, Guid? intentId = null, GateSubject? subject = null, FileVersionIdentity? file = null, DestinationBinding? destination = null, long flowGeneration = 1, Guid? bootInstance = null, long? policyEpoch = null) =>
        new(1, intentId ?? sample.Intent.IntentId, subject ?? sample.Subject, file ?? sample.File, destination ?? sample.Destination, flowGeneration, bootInstance ?? sample.Boot, policyEpoch ?? 7, OutboundGateLimits.MaximumGrantBytes, (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);

    private static OneTimeTicket CloneTicket(OneTimeTicket ticket, Guid? ticketId = null, Guid? nonce = null, Guid? intentId = null, GateSubject? subject = null, FileVersionIdentity? file = null, DestinationBinding? destination = null, long? flowGeneration = null, long? policyEpoch = null, Guid? bootInstance = null, DateTimeOffset? issuedAtUtc = null, DateTimeOffset? expiresAtUtc = null, ServiceMonotonicTimeRange? validityWindow = null, long? grantMaxBytes = null, long? grantMaxDurationMilliseconds = null) =>
        new(ticket.Version, ticketId ?? ticket.TicketId, nonce ?? ticket.Nonce, intentId ?? ticket.IntentId, subject ?? ticket.Subject, file ?? ticket.File, destination ?? ticket.Destination, flowGeneration ?? ticket.FlowGeneration, policyEpoch ?? ticket.PolicyEpoch, bootInstance ?? ticket.BootInstance, issuedAtUtc ?? ticket.IssuedAtUtc, expiresAtUtc ?? ticket.ExpiresAtUtc, validityWindow ?? ticket.ValidityWindow, grantMaxBytes ?? ticket.GrantMaxBytes, grantMaxDurationMilliseconds ?? ticket.GrantMaxDurationMilliseconds, ticket.AuthenticatorProof);

    private static OutboundGateStateMachine CreateOutboundGateMachine(OutboundGateSample sample, TestMonotonicClock clock, TestNonceProvider nonces, long policyEpoch = 7, TestAuditClock? auditClock = null, OneTimeGateTicketService? ticketService = null) =>
        new(clock, nonces, auditClock ?? new TestAuditClock(sample.Start), OutboundGateMode.Simulation, policyEpoch, new OutboundGateTrustedRuntimeState(sample.Boot, sample.DriverGeneration, sample.MinifilterGeneration), ticketService);

    private static PreparedRead PrepareToDisposition(OutboundGateStateMachine machine, OutboundGateSample sample, TestNonceProvider nonces, FileReadIntent? intent = null)
    {
        intent ??= sample.Intent;
        var request = machine.ReceiveIntent(intent).ArmRequest!;
        machine.ReceiveGateArmAck(AckFor(sample, request, nonces, intent));
        var disposition = machine.ReleaseAfterGateArmed(intent.IntentId).Disposition!;
        return new PreparedRead(request, disposition);
    }

    private static PreparedChallenge PrepareToChallenge(OutboundGateStateMachine machine, OutboundGateSample sample, TestMonotonicClock clock, TestNonceProvider nonces, FileReadIntent? intent = null)
    {
        intent ??= sample.Intent;
        var prepared = PrepareAwaitingChallenge(machine, sample, nonces, intent);
        var challenge = ChallengeFor(sample, prepared.Request, clock, nonces, intent, prepared.Request.RequiredCoverage);
        var result = machine.ReceiveChallenge(challenge);
        return new PreparedChallenge(challenge, result);
    }

    private static PreparedRead PrepareAwaitingChallenge(OutboundGateStateMachine machine, OutboundGateSample sample, TestNonceProvider nonces, FileReadIntent? intent = null)
    {
        intent ??= sample.Intent;
        var prepared = PrepareToDisposition(machine, sample, nonces, intent);
        machine.AcceptCompletion(CompletionFor(sample, prepared.Disposition, nonces, sample.MinifilterGeneration, intent));
        return prepared;
    }

    private static ChallengeAdmissionFailure ChallengeAdmissionFailureFor(
        OutboundGateSample sample,
        TestMonotonicClock clock,
        Guid failureId,
        FileReadIntent intent,
        GateSubject? subject = null,
        Guid? wfpGeneration = null) =>
        new(
            1,
            failureId,
            intent.IntentId,
            subject ?? intent.Subject,
            wfpGeneration ?? sample.DriverGeneration,
            ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted,
            clock.Now());

    private static GateArmAck AckFor(OutboundGateSample sample, GateArmRequest request, TestNonceProvider nonces, FileReadIntent? intent = null) =>
        new(1, nonces.NextNonce(), request.IntentId, (intent ?? sample.Intent).Subject, request.RequiredCoverage, request.RequiredCoverage, request.PolicyEpoch, sample.DriverGeneration, request.RequestNonce, nonces.NextNonce(), sample.Start, request.ArmWindow, null);

    private static FileReadCompletionAck CompletionFor(OutboundGateSample sample, FileReadDisposition disposition, TestNonceProvider nonces, Guid minifilterGeneration, FileReadIntent? intent = null)
    {
        intent ??= sample.Intent;
        return new FileReadCompletionAck(1, nonces.NextNonce(), intent.IntentId, intent.Subject.ProcessIdentity, intent.File, disposition.Sequence, disposition.Disposition, disposition.GateAckId, FileReadCompletionResult.Released, "released", 1, minifilterGeneration);
    }

    private static NetworkGateChallenge ChallengeFor(OutboundGateSample sample, GateArmRequest request, TestMonotonicClock clock, TestNonceProvider nonces, FileReadIntent intent, GateCoverage coverage) =>
        new(1, nonces.NextNonce(), intent.IntentId, intent.Subject, sample.Destination, 1, false, coverage, sample.Start, ServiceRange(clock.Now().ClockInstanceId, clock.Now().ElapsedMilliseconds, 15_000), "Simulation");

    private static FileReadIntent IntentFor(OutboundGateSample sample, Guid intentId, GateSubject subject, long sequence) =>
        new(1, intentId, subject, sample.File, FileActivityOperation.Read, sample.Start, sample.ReadWindow, sample.Boot, sequence);

    private static FileReadIntent CloneIntent(FileReadIntent intent)
    {
        var subject = new GateSubject(1, intent.Subject.ProcessIdentity, intent.Subject.ApplicationIdentity, intent.Subject.ProcessGroupId, intent.Subject.GroupMembers.ToArray());
        return new FileReadIntent(intent.Version, intent.IntentId, subject, intent.File, intent.Operation, intent.ObservedAtUtc, intent.ReadWindow, intent.BootInstance, intent.Sequence);
    }

    private sealed record PreparedRead(GateArmRequest Request, FileReadDisposition Disposition);
    private sealed record PreparedChallenge(NetworkGateChallenge Challenge, GateTransitionResult Result);
    private sealed record PersistentStateSnapshot(
        long MachinePolicyEpoch,
        long TicketPolicyEpoch,
        GateStateMachineCounters Counters,
        GateStateMachineStorageSnapshot Storage,
        TicketServiceSnapshot Tickets,
        int CriticalAlertCount);

    private sealed class TestMonotonicClock : IOutboundGateMonotonicClock
    {
        public TestMonotonicClock(ServiceMonotonicTimestamp current) => Current = current;
        public ServiceMonotonicTimestamp Current { get; private set; }
        public ServiceMonotonicTimestamp Now() => Current;
        public void Set(ServiceMonotonicTimestamp timestamp) => Current = timestamp;
        public void Advance(long milliseconds) => Set(new ServiceMonotonicTimestamp(1, Current.ClockInstanceId, Current.ElapsedMilliseconds + milliseconds));
    }

    private sealed class TestNonceProvider : IOutboundGateNonceProvider
    {
        private int _counter;
        public Guid NextNonce() => Guid.Parse($"{++_counter:x8}-0000-0000-0000-000000000000");
    }

    private sealed class ScriptedNonceProvider : IOutboundGateNonceProvider
    {
        private readonly Queue<Guid> _values;

        public ScriptedNonceProvider(params Guid[] values) => _values = new Queue<Guid>(values);

        public Guid NextNonce()
        {
            if (_values.Count == 0)
                throw new InvalidOperationException("The scripted nonce sequence was exhausted.");
            return _values.Dequeue();
        }
    }

    private sealed class BlockingTestTicketAuthenticator : IOneTimeTicketAuthenticator
    {
        private readonly DeterministicTestTicketAuthenticator _inner;
        private readonly ManualResetEventSlim _verificationEntered = new(false);
        private readonly ManualResetEventSlim _releaseVerification = new(false);
        private int _blockVerification;
        private int _disposed;

        public BlockingTestTicketAuthenticator(Guid bootInstance) => _inner = new DeterministicTestTicketAuthenticator(bootInstance);

        public Guid BootInstance => _inner.BootInstance;
        public int ProofSizeBytes => _inner.ProofSizeBytes;
        public ManualResetEventSlim VerificationEntered => _verificationEntered;
        public byte[] CreateProof(ReadOnlySpan<byte> canonicalClaims) => _inner.CreateProof(canonicalClaims);

        public bool VerifyProof(ReadOnlySpan<byte> canonicalClaims, ReadOnlySpan<byte> presentedProof)
        {
            if (Volatile.Read(ref _blockVerification) != 0)
            {
                _verificationEntered.Set();
                _releaseVerification.Wait();
            }
            return _inner.VerifyProof(canonicalClaims, presentedProof);
        }

        public void BlockVerification() => Volatile.Write(ref _blockVerification, 1);
        public void ReleaseVerification() => _releaseVerification.Set();

        public void Dispose()
        {
            if (Interlocked.Exchange(ref _disposed, 1) != 0)
                return;
            _inner.Dispose();
            _verificationEntered.Dispose();
            _releaseVerification.Dispose();
        }
    }

    private sealed class TestAuditClock : IOutboundGateAuditClock
    {
        public TestAuditClock(DateTimeOffset current) => Current = current;
        public DateTimeOffset Current { get; private set; }
        public DateTimeOffset NowUtc() => Current;
        public void Set(DateTimeOffset timestamp) => Current = timestamp;
    }

    private sealed class FailingGrantFactory : IEphemeralFlowGrantFactory
    {
        public bool TryCreate(TicketGrantParameters parameters, out EphemeralFlowGrant? grant)
        {
            _ = parameters;
            grant = null;
            return false;
        }
    }

    private static OutboundGateSample OutboundGateSamples()
    {
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var process = new ProcessIdentity(42, start);
        var boot = Guid.Parse("10000000-0000-0000-0000-000000000001");
        var driver = Guid.Parse("20000000-0000-0000-0000-000000000002");
        var minifilter = Guid.Parse("21000000-0000-0000-0000-000000000002");
        var clock = Guid.Parse("22000000-0000-0000-0000-000000000002");
        var intentId = Guid.Parse("30000000-0000-0000-0000-000000000003");
        var requestNonce = Guid.Parse("40000000-0000-0000-0000-000000000004");
        var subject = new GateSubject(1, process, "sha256:application", null, [process]);
        var file = new FileVersionIdentity(1, "volume-1", "file-42", start, 1024, start.AddMinutes(1), start.AddMinutes(2), 42, "version-token-1");
        var destination = new DestinationBinding(1, IPAddress.Loopback, IpVersion.IPv4, 5050, TransportProtocol.Tcp, NetworkTrafficDirection.Outbound, 12, 34, "localhost", DomainEvidenceProvenance.DnsObservation, start);
        var coverage = new GateCoverage(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);
        var readWindow = ServiceRange(clock, 1_000, 2_000);
        var decisionWindow = ServiceRange(clock, 3_000, 15_000);
        var ticketWindow = ServiceRange(clock, 18_000, 5_000);
        var grantWindow = ServiceRange(clock, 23_000, 300_000);
        var intent = new FileReadIntent(1, intentId, subject, file, FileActivityOperation.Read, start, readWindow, boot, 1);
        var request = new GateArmRequest(1, intentId, subject, coverage, 7, driver, requestNonce, start, readWindow);
        var acknowledgedAt = new ServiceMonotonicTimestamp(1, clock, 1_500);
        var ack = new GateArmAck(1, Guid.Parse("50000000-0000-0000-0000-000000000005"), intentId, subject, coverage, coverage, 7, driver, requestNonce, Guid.Parse("60000000-0000-0000-0000-000000000006"), start.AddMilliseconds(10), readWindow, null);
        var disposition = new FileReadDisposition(1, intentId, process, file, FileReadDispositionKind.ReleaseAfterGateArmed, ack.AckId, readWindow, "gate-armed", 2);
        var completion = new FileReadCompletionAck(1, Guid.Parse("70000000-0000-0000-0000-000000000007"), intentId, process, file, 2, disposition.Disposition, disposition.GateAckId, FileReadCompletionResult.Released, "read-released", 3, minifilter);
        var challenge = new NetworkGateChallenge(1, Guid.Parse("80000000-0000-0000-0000-000000000008"), intentId, subject, destination, 1, false, coverage, start, decisionWindow, null);
        var persistentScope = new RequestedPersistentScope(1, PersistentAllowPolicyKind.RememberFor30Days, file, subject.ApplicationIdentity, destination);
        var decision = new UserDecision(1, Guid.Parse("90000000-0000-0000-0000-000000000009"), challenge.ChallengeId, UserDecisionKind.AlwaysAllow, persistentScope, start, "interactive-user");
        var ticket = new OneTimeTicket(1, Guid.Parse("a0000000-0000-0000-0000-00000000000a"), Guid.Parse("b0000000-0000-0000-0000-00000000000b"), intentId, subject, file, destination, 1, 7, boot, start, start.AddSeconds(5), ticketWindow, 512L * 1024 * 1024, 300_000, Enumerable.Range(1, 32).Select(value => (byte)value).ToArray());
        var grant = new EphemeralFlowGrant(1, Guid.Parse("c0000000-0000-0000-0000-00000000000c"), ticket.TicketId, intentId, subject, destination, 1, 7, boot, ticket.GrantMaxBytes, grantWindow);
        var affectedScope = new GateAffectedScope(1, GateAffectedScopeKind.Intent, intentId, subject);
        var status = new GateStatus(1, OutboundGateMode.Simulation, GateRuntimeState.Armed, coverage, "simulation-armed", affectedScope, start, acknowledgedAt, 0, 0, false);
        var criticalAlert = new CriticalAlert(1, Guid.Parse("d0000000-0000-0000-0000-00000000000d"), "gate-overflow", affectedScope, start, acknowledgedAt, 2, 1, true);
        return new OutboundGateSample(start, process, boot, driver, minifilter, clock, readWindow, coverage, file, subject, destination, intent, request, ack, disposition, completion, challenge, persistentScope, decision, ticket, grant, affectedScope, status, criticalAlert);
    }

    private static ServiceMonotonicTimeRange ServiceRange(Guid clockInstanceId, long startedAtMilliseconds, long durationMilliseconds) =>
        new(1,
            new ServiceMonotonicTimestamp(1, clockInstanceId, startedAtMilliseconds),
            new ServiceMonotonicTimestamp(1, clockInstanceId, checked(startedAtMilliseconds + durationMilliseconds)));

    private sealed record OutboundGateSample(
        DateTimeOffset Start,
        ProcessIdentity Process,
        Guid Boot,
        Guid DriverGeneration,
        Guid MinifilterGeneration,
        Guid Clock,
        ServiceMonotonicTimeRange ReadWindow,
        GateCoverage Coverage,
        FileVersionIdentity File,
        GateSubject Subject,
        DestinationBinding Destination,
        FileReadIntent Intent,
        GateArmRequest Request,
        GateArmAck Ack,
        FileReadDisposition Disposition,
        FileReadCompletionAck Completion,
        NetworkGateChallenge Challenge,
        RequestedPersistentScope PersistentScope,
        UserDecision Decision,
        OneTimeTicket Ticket,
        EphemeralFlowGrant Grant,
        GateAffectedScope AffectedScope,
        GateStatus Status,
        CriticalAlert CriticalAlert);

    private static async Task TestConfiguredPipeNameAsync()
    {
        var original = Environment.GetEnvironmentVariable("EGRESSGUARD_PIPE_NAME");
        try
        {
            var requestPipeName = $"{ProtocolConstants.PipeName}.Configured.Request.{Guid.NewGuid():N}";
            Environment.SetEnvironmentVariable("EGRESSGUARD_PIPE_NAME", requestPipeName);
            using (var server = new NamedPipeServerStream(requestPipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous))
            {
                var serverTask = Task.Run(async () =>
                {
                    await server.WaitForConnectionAsync().ConfigureAwait(false);
                    var handshake = await MessageFraming.ReadAsync(server, CancellationToken.None).ConfigureAwait(false);
                    AssertEqual(MessageTypes.Handshake, handshake?.Type);
                    await MessageFraming.WriteAsync(
                        server,
                        MessageEnvelope.Create(MessageTypes.Success, new SuccessMessage("configured request pipe accepted")),
                        CancellationToken.None).ConfigureAwait(false);
                });
                await using var client = new EgressGuardPipeClient();
                await client.ConnectAsync(TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(false);
                await serverTask.ConfigureAwait(false);
            }

            var eventPipeName = $"{ProtocolConstants.PipeName}.Configured.Events.{Guid.NewGuid():N}";
            Environment.SetEnvironmentVariable("EGRESSGUARD_PIPE_NAME", eventPipeName);
            using var eventServer = new NamedPipeServerStream(eventPipeName, PipeDirection.InOut, 1, PipeTransmissionMode.Byte, PipeOptions.Asynchronous);
            var eventServerTask = Task.Run(async () =>
            {
                await eventServer.WaitForConnectionAsync().ConfigureAwait(false);
                var handshake = await MessageFraming.ReadAsync(eventServer, CancellationToken.None).ConfigureAwait(false);
                AssertEqual(MessageTypes.Handshake, handshake?.Type);
                await MessageFraming.WriteAsync(
                    eventServer,
                    MessageEnvelope.Create(MessageTypes.Success, new SuccessMessage("configured event pipe accepted")),
                    CancellationToken.None).ConfigureAwait(false);
                var subscribe = await MessageFraming.ReadAsync(eventServer, CancellationToken.None).ConfigureAwait(false);
                AssertEqual(MessageTypes.SubscribeEvents, subscribe?.Type);
                await MessageFraming.WriteAsync(
                    eventServer,
                    MessageEnvelope.Create(MessageTypes.Success, new SuccessMessage("subscription accepted")),
                    CancellationToken.None).ConfigureAwait(false);
            });
            await using var eventClient = new EgressGuardEventClient();
            var subscribed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
            var subscribeTask = eventClient.SubscribeAsync(
                0,
                _ => ValueTask.CompletedTask,
                () => subscribed.TrySetResult(),
                CancellationToken.None);
            await subscribed.Task.WaitAsync(TimeSpan.FromSeconds(3)).ConfigureAwait(false);
            await eventServerTask.ConfigureAwait(false);
            await eventClient.DisconnectAsync().ConfigureAwait(false);
            try { await subscribeTask.ConfigureAwait(false); }
            catch (Exception exception) when (exception is EndOfStreamException or IOException or ObjectDisposedException) { }
        }
        finally
        {
            Environment.SetEnvironmentVariable("EGRESSGUARD_PIPE_NAME", original);
        }
    }

    private static async Task TestFileCorrelationProtocolAsync()
    {
        var flow = SampleFlow();
        var engine = NewCorrelationEngine(maxEvidence: 20);
        for (var index = 0; index < 20; index++)
        {
            _ = engine.Add(FileEvent(flow, index, -index, FileActivityOperation.Read, $"C:\\Synthetic\\protocol-{index}.txt"));
        }

        var status = new FileSensorStatus(FileSensorState.OverflowDegraded, 1_999, "Controlled overflow.", DateTimeOffset.UtcNow);
        var message = MessageEnvelope.Create(MessageTypes.GetFileCorrelations, new FileCorrelationsMessage(flow.Id, engine.Correlate(flow), status));
        await using var stream = new MemoryStream();
        await MessageFraming.WriteAsync(stream, message, CancellationToken.None).ConfigureAwait(false);
        AssertTrue(stream.Length < ProtocolConstants.MaximumMessageBytes, "Bounded correlation response exceeded protocol framing limit.");
        stream.Position = 0;
        var result = await MessageFraming.ReadAsync(stream, CancellationToken.None).ConfigureAwait(false);
        var payload = result!.ReadPayload<FileCorrelationsMessage>();
        AssertEqual(20, payload.Correlations.Count);
        AssertEqual(1_999L, payload.SensorStatus.DroppedEvents);

        var legacyJson = """{"mode":1,"isRunning":true,"activeFlowCount":0,"droppedEvents":0,"databasePath":"test.db","timestamp":"2026-01-01T00:00:00Z"}""";
        var legacyStatus = System.Text.Json.JsonSerializer.Deserialize<ServiceStatusMessage>(legacyJson, JsonDefaults.Options);
        AssertTrue(legacyStatus is not null && legacyStatus.FileSensor is null && !legacyStatus.FileCorrelationEnabled, "Legacy status payload was not backward compatible.");
    }

    private static async Task TestUiCorrelationRefreshAsync()
    {
        var fetchCount = 0;
        var inFlight = 0;
        var maximumInFlight = 0;
        var applied = new List<string>();
        await using var refresh = new BoundedSelectionRefresh<string>(
            async (flowId, cancellationToken) =>
            {
                var current = Interlocked.Increment(ref inFlight);
                maximumInFlight = Math.Max(maximumInFlight, current);
                var sequence = Interlocked.Increment(ref fetchCount);
                try
                {
                    await Task.Delay(flowId == "old" ? 200 : 10, cancellationToken).ConfigureAwait(false);
                    return $"{flowId}:{sequence}";
                }
                finally
                {
                    Interlocked.Decrement(ref inFlight);
                }
            },
            (flowId, value) => applied.Add($"{flowId}|{value}"),
            exception => throw new TestFailureException($"Refresh failed: {exception.Message}"),
            TimeSpan.FromMilliseconds(50));

        refresh.Select("old");
        await Task.Delay(20).ConfigureAwait(false);
        refresh.Select("new");
        for (var index = 0; index < 100; index++) refresh.NotifyFlowUpdated("new");
        await Task.Delay(180).ConfigureAwait(false);
        AssertTrue(applied.Count >= 1, "Selected flow was not refreshed.");
        AssertTrue(applied.All(item => item.StartsWith("new|", StringComparison.Ordinal)), "A stale selection overwrote current evidence.");
        AssertEqual(1, maximumInFlight);
        AssertTrue(fetchCount <= 3, "FlowUpdated burst created a request storm.");

        var beforeTrailing = applied.Count;
        refresh.NotifyFlowUpdated("new");
        await Task.Delay(100).ConfigureAwait(false);
        AssertTrue(applied.Count > beforeTrailing, "Evidence arriving after selection did not trigger a throttled refresh.");
    }

    private static async Task TestDatabaseLockAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-LockTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "lock.db");
        try
        {
            var database = new EgressGuardDatabase(path);
            await database.InitializeAsync().ConfigureAwait(false);
            await using var blocker = new SqliteConnection($"Data Source={path};Pooling=False");
            await blocker.OpenAsync().ConfigureAwait(false);
            await using var transaction = (SqliteTransaction)await blocker.BeginTransactionAsync().ConfigureAwait(false);
            var lockCommand = blocker.CreateCommand();
            lockCommand.Transaction = transaction;
            lockCommand.CommandText = "INSERT INTO settings(key,value,updated_at) VALUES('lock','held','now');";
            _ = await lockCommand.ExecuteNonQueryAsync().ConfigureAwait(false);
            using var timeout = new CancellationTokenSource(TimeSpan.FromMilliseconds(250));
            await AssertThrowsAnyAsync(
                () => database.SetSettingAsync("blocked", "value", timeout.Token),
                typeof(OperationCanceledException),
                typeof(SqliteException)).ConfigureAwait(false);
            await transaction.RollbackAsync().ConfigureAwait(false);
            await database.SetSettingAsync("after_lock", "ok").ConfigureAwait(false);
            AssertEqual("ok", await database.GetSettingAsync("after_lock").ConfigureAwait(false));
        }
        finally
        {
            SqliteConnection.ClearAllPools();
            Directory.Delete(directory, recursive: true);
        }
    }

    private static async Task TestGracefulCancellationAsync()
    {
        var directory = Path.Combine(Path.GetTempPath(), "EgressGuard-CancellationTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var databasePath = Path.Combine(directory, "cancellation.db");
        var logger = new ListLogger<FlowCoordinator>();
        UnobservedTaskExceptionEventArgs? unobserved = null;
        EventHandler<UnobservedTaskExceptionEventArgs> handler = (_, args) => unobserved = args;
        TaskScheduler.UnobservedTaskException += handler;
        var coordinator = new FlowCoordinator(
            new EmptyFlowSensor(),
            new EgressGuardDatabase(databasePath),
            new RiskEngine(),
            new BaselineTracker(),
            new FakeFirewallRuleManager(),
            new ServiceState(),
            new EventHub(),
            logger);
        try
        {
            await coordinator.StartAsync(CancellationToken.None).ConfigureAwait(false);
            using var startupTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            while (!File.Exists(databasePath))
            {
                await Task.Delay(25, startupTimeout.Token).ConfigureAwait(false);
            }

            var stopwatch = Stopwatch.StartNew();
            using var shutdownTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await coordinator.StopAsync(shutdownTimeout.Token).ConfigureAwait(false);
            stopwatch.Stop();

            AssertTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(5), "Graceful cancellation did not finish within the timeout.");
            AssertTrue(
                logger.Entries.All(entry => !entry.Message.Contains("Database initialization failed", StringComparison.Ordinal)),
                "Graceful cancellation was logged as database initialization failure.");
            AssertTrue(
                logger.Entries.All(entry => !entry.Message.Contains("Flow persistence batch failed", StringComparison.Ordinal)),
                "Graceful cancellation was logged as persistence failure.");
            AssertEqual(null, unobserved);
        }
        finally
        {
            coordinator.Dispose();
            TaskScheduler.UnobservedTaskException -= handler;
            SqliteConnection.ClearAllPools();
            await DeleteDirectoryWithRetryAsync(directory).ConfigureAwait(false);
        }
    }

    private static async Task TestAutomaticRuleRollbackAsync()
    {
        var flow = SampleFlow();
        var rule = SampleRule(FirewallAction.Block, flow);
        var foreignRuleId = Guid.NewGuid();
        var firewall = new FakeFirewallRuleManager();
        firewall.ForeignRuleIds.Add(foreignRuleId);
        var logger = new ListLogger<FirewallRuleCreateCoordinator>();
        var applier = new FirewallRuleCreateCoordinator(
            firewall,
            (_, _) => Task.FromException(new InvalidOperationException("controlled database failure")),
            logger);

        await applier.ApplyAsync(rule, CancellationToken.None).ConfigureAwait(false);

        AssertTrue(!firewall.OwnedRuleIds.Contains(rule.Id), "The newly created rule remained after database failure.");
        AssertTrue(firewall.ForeignRuleIds.Contains(foreignRuleId), "Rollback modified a foreign firewall rule.");
        AssertEqual(rule.Id, firewall.DeletedRuleIds.Single());
        AssertTrue(logger.Entries.Any(entry => entry.Message.Contains("persistence failed", StringComparison.Ordinal)), "The original persistence failure was not logged.");

        var existingRule = rule with { Id = Guid.NewGuid() };
        var existingFirewall = new FakeFirewallRuleManager { CreateChangesState = false };
        existingFirewall.OwnedRuleIds.Add(existingRule.Id);
        var existingApplier = new FirewallRuleCreateCoordinator(
            existingFirewall,
            (_, _) => Task.FromException(new InvalidOperationException("controlled database failure")),
            new ListLogger<FirewallRuleCreateCoordinator>());
        await existingApplier.ApplyAsync(existingRule, CancellationToken.None).ConfigureAwait(false);
        AssertTrue(existingFirewall.OwnedRuleIds.Contains(existingRule.Id), "Rollback deleted an owned rule that predated this create request.");
        AssertEqual(0, existingFirewall.DeletedRuleIds.Count);
    }

    private static async Task TestAutomaticRuleCancellationRollbackAsync()
    {
        var rule = SampleRule(FirewallAction.Block, SampleFlow());
        var firewall = new FakeFirewallRuleManager();
        var logger = new ListLogger<FirewallRuleCreateCoordinator>();
        using var cancellation = new CancellationTokenSource();
        var applier = new FirewallRuleCreateCoordinator(
            firewall,
            (_, _) =>
            {
                cancellation.Cancel();
                return Task.FromCanceled(cancellation.Token);
            },
            logger);

        await AssertThrowsAsync<OperationCanceledException>(() => applier.ApplyAsync(rule, cancellation.Token)).ConfigureAwait(false);

        AssertTrue(!firewall.OwnedRuleIds.Contains(rule.Id), "The created rule remained after cancellation.");
        AssertEqual(rule.Id, firewall.DeletedRuleIds.Single());
        AssertEqual(0, logger.Entries.Count);
    }

    private static async Task TestAutomaticRuleRollbackFailureLoggingAsync()
    {
        var rule = SampleRule(FirewallAction.Block, SampleFlow());
        var firewall = new FakeFirewallRuleManager { DeleteFails = true };
        var logger = new ListLogger<FirewallRuleCreateCoordinator>();
        var applier = new FirewallRuleCreateCoordinator(
            firewall,
            (_, _) => Task.FromException(new InvalidOperationException("controlled database failure")),
            logger);

        await applier.ApplyAsync(rule, CancellationToken.None).ConfigureAwait(false);

        AssertTrue(firewall.OwnedRuleIds.Contains(rule.Id), "The rollback-failure fixture unexpectedly removed the rule.");
        AssertTrue(logger.Entries.Any(entry => entry.Exception?.Message == "controlled database failure"), "The original failure was not logged.");
        AssertTrue(logger.Entries.Any(entry => entry.Exception?.Message == "controlled rollback failure"), "The rollback failure was not logged.");
    }

    private static async Task TestOversizedMessageAsync()
    {
        var message = MessageEnvelope.Create(MessageTypes.Error, new ErrorMessage("BIG", new string('x', ProtocolConstants.MaximumMessageBytes + 1)));
        await using var stream = new MemoryStream();
        await AssertThrowsAsync<InvalidDataException>(() => MessageFraming.WriteAsync(stream, message, CancellationToken.None)).ConfigureAwait(false);
    }

    private static async Task TestProtocolDisconnectAsync()
    {
        await using var stream = new MemoryStream();
        AssertEqual(null, await MessageFraming.ReadAsync(stream, CancellationToken.None).ConfigureAwait(false));
    }

    private static Task TestEventBufferAsync()
    {
        var buffer = new SequencedEventBuffer(3);
        AssertTrue(buffer.Enqueue(StreamEvent(10)), "First event was rejected.");
        AssertTrue(buffer.Enqueue(StreamEvent(11)), "Second event was rejected.");
        var firstBatch = buffer.Drain(9, 1);
        AssertEqual(1, firstBatch.Events.Count);
        AssertEqual(10L, firstBatch.LastSequence);
        AssertTrue(!firstBatch.RequiresResync, "Ordered batch unexpectedly requested resync.");
        var secondBatch = buffer.Drain(firstBatch.LastSequence, 10);
        AssertEqual(11L, secondBatch.LastSequence);

        buffer.Enqueue(StreamEvent(13));
        AssertTrue(buffer.Drain(11).RequiresResync, "Sequence gap was not detected.");

        buffer.Enqueue(StreamEvent(20));
        buffer.Enqueue(StreamEvent(21));
        buffer.Enqueue(StreamEvent(22));
        AssertTrue(!buffer.Enqueue(StreamEvent(23)), "Overflowing event was unexpectedly accepted.");
        var overflow = buffer.Drain(19);
        AssertTrue(overflow.RequiresResync && overflow.Overflowed, "Overflow did not force resync.");
        return Task.CompletedTask;
    }

    private static StreamEventMessage StreamEvent(long sequence) =>
        new(sequence, StreamEventKind.FlowUpdated, SampleFlow() with { Id = $"flow-{sequence}" }, $"flow-{sequence}", null, null, false);

    private static async Task TestSlowSubscriberAsync()
    {
        var hub = new EventHub();
        await using var subscription = hub.Subscribe(0);
        var stopwatch = Stopwatch.StartNew();
        for (var index = 0; index < 600; index++)
        {
            hub.PublishFlow(StreamEventKind.FlowUpdated, SampleFlow(), "slow-flow");
        }

        stopwatch.Stop();
        AssertTrue(stopwatch.Elapsed < TimeSpan.FromSeconds(2), "A slow subscriber blocked event publishing.");
        AssertEqual(600L, hub.CurrentSequence);
        if (!subscription.Reader.TryRead(out var overflow))
        {
            throw new TestFailureException("Slow subscriber received no resync marker.");
        }
        AssertTrue(overflow.RequiresResync && overflow.Kind == StreamEventKind.ResyncRequired, "Slow subscriber did not receive a resync marker.");

        var mismatchHub = new EventHub();
        mismatchHub.PublishFlow(StreamEventKind.FlowAdded, SampleFlow(), "initial");
        await using var mismatch = mismatchHub.Subscribe(99);
        AssertTrue(mismatch.Reader.TryRead(out var resync) && resync.RequiresResync, "A reconnect sequence mismatch did not request resync.");
    }

    private static Task TestFlowStateTransitionsAsync()
    {
        var state = new ServiceState();
        var first = SampleFlow();
        var added = state.ReplaceSnapshot([first]);
        AssertEqual(StreamEventKind.FlowAdded, added.Single().Kind);
        AssertEqual(0, state.ReplaceSnapshot([first]).Count);
        var updated = state.ReplaceSnapshot([first with { LastSeen = first.LastSeen.AddSeconds(3) }]);
        AssertEqual(StreamEventKind.FlowUpdated, updated.Single().Kind);
        var removed = state.ReplaceSnapshot([]);
        AssertEqual(StreamEventKind.FlowRemoved, removed.Single().Kind);
        AssertEqual(first.Id, removed.Single().FlowId);
        return Task.CompletedTask;
    }

    private static Task TestServicePipeAclAsync()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var serviceIdentity = identity.User ?? throw new TestFailureException("Current Windows identity has no SID.");
        var security = PipeServer.CreatePipeSecurity(serviceIdentity);
        var rules = security.GetAccessRules(includeExplicit: true, includeInherited: false, typeof(SecurityIdentifier))
            .OfType<PipeAccessRule>()
            .ToArray();

        AssertTrue(security.AreAccessRulesProtected, "Pipe ACL unexpectedly inherits access rules.");
        AssertPipeAccess(rules, serviceIdentity, PipeAccessRights.FullControl);
        AssertPipeAccess(rules, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null), PipeAccessRights.FullControl);
        AssertPipeAccess(rules, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null), PipeAccessRights.FullControl);
        var interactiveIdentity = new SecurityIdentifier(WellKnownSidType.InteractiveSid, null);
        var interactiveAllowRules = rules
            .Where(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Equals(interactiveIdentity))
            .ToArray();
        AssertTrue(interactiveAllowRules.Length > 0, "Pipe ACL has no allow rule for INTERACTIVE.");

        var interactiveRights = interactiveAllowRules.Aggregate(
            (PipeAccessRights)0,
            (combined, rule) => combined | rule.PipeAccessRights);
        var expectedInteractiveRights = PipeAccessRights.ReadWrite | PipeAccessRights.Synchronize;
        AssertEqual(expectedInteractiveRights, interactiveRights);

        var forbiddenInteractiveRights = PipeAccessRights.ChangePermissions
            | PipeAccessRights.TakeOwnership
            | PipeAccessRights.Delete
            | PipeAccessRights.CreateNewInstance
            | PipeAccessRights.AccessSystemSecurity;
        AssertEqual((PipeAccessRights)0, interactiveRights & forbiddenInteractiveRights);
        AssertEqual(
            (PipeAccessRights)0,
            interactiveRights & (PipeAccessRights.FullControl & ~expectedInteractiveRights));

        var expectedIdentities = new HashSet<string>(StringComparer.Ordinal)
        {
            serviceIdentity.Value,
            new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null).Value,
            new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null).Value,
            interactiveIdentity.Value
        };
        AssertTrue(
            rules.All(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference is SecurityIdentifier sid &&
                expectedIdentities.Contains(sid.Value)),
            "Pipe ACL grants access to an unexpected identity.");
        return Task.CompletedTask;
    }

    private static void AssertPipeAccess(PipeAccessRule[] rules, SecurityIdentifier identity, PipeAccessRights expectedRights)
    {
        AssertTrue(
            rules.Any(rule =>
                rule.AccessControlType == AccessControlType.Allow &&
                rule.IdentityReference.Equals(identity) &&
                (rule.PipeAccessRights & expectedRights) == expectedRights),
            $"Pipe ACL is missing {expectedRights} for {identity.Value}.");
    }

    private static async Task TestServicePipeReconnectAsync()
    {
        var servicePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "EgressGuard.Service", "bin", "Release", "net8.0-windows", "EgressGuard.Service.exe"));
        if (!File.Exists(servicePath))
        {
            throw new TestFailureException($"Service apphost not found: {servicePath}");
        }

        var dataDirectory = Path.Combine(Path.GetTempPath(), "EgressGuard-ServiceTests-" + Guid.NewGuid().ToString("N"));
        var pipeName = $"{ProtocolConstants.PipeName}.Tests.{Environment.ProcessId}.{Guid.NewGuid():N}";
        Directory.CreateDirectory(dataDirectory);
        var startInfo = new ProcessStartInfo(servicePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.Environment["EGRESSGUARD_DATA_DIR"] = dataDirectory;
        startInfo.Environment["EGRESSGUARD_TEST_DURATION_SECONDS"] = "40";
        startInfo.Environment["EGRESSGUARD_PIPE_NAME"] = pipeName;
        using var service = Process.Start(startInfo) ?? throw new TestFailureException("Service process failed to start.");
        var stage = "first connect";
        try
        {
            await using (var first = new EgressGuardPipeClient(pipeName))
            {
                await ConnectWithRetryAsync(first).ConfigureAwait(false);
                stage = "first status request";
                var response = await first.SendAsync(MessageEnvelope.Create(MessageTypes.GetStatus, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(false);
                AssertTrue(response.ReadPayload<ServiceStatusMessage>().IsRunning, "Service did not report running state.");
            }

            long snapshotSequence;
            stage = "second connect";
            await using (var second = new EgressGuardPipeClient(pipeName))
            {
                await ConnectWithRetryAsync(second).ConfigureAwait(false);
                stage = "second flows request";
                var response = await second.SendAsync(MessageEnvelope.Create(MessageTypes.GetActiveFlows, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(false);
                snapshotSequence = response.ReadPayload<ActiveFlowsMessage>().Sequence;
            }

            stage = "event subscription";
            using (var subscriptionCancellation = new CancellationTokenSource())
            await using (var eventClient = new EgressGuardEventClient(pipeName))
            {
                var observed = new TaskCompletionSource<StreamEventMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
                var subscriptionReady = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
                var subscribeTask = eventClient.SubscribeAsync(snapshotSequence, streamEvent =>
                {
                    if (streamEvent.Flow?.ProcessIdentity?.ProcessId == Environment.ProcessId)
                    {
                        observed.TrySetResult(streamEvent);
                    }

                    return ValueTask.CompletedTask;
                }, () => subscriptionReady.TrySetResult(), subscriptionCancellation.Token);
                using var readinessTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                var readinessResult = await Task.WhenAny(subscriptionReady.Task, subscribeTask)
                    .WaitAsync(readinessTimeout.Token)
                    .ConfigureAwait(false);
                if (ReferenceEquals(readinessResult, subscribeTask))
                {
                    await subscribeTask.ConfigureAwait(false);
                }

                await subscriptionReady.Task.ConfigureAwait(false);
                using var eventTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(30));
                var listener = new TcpListener(IPAddress.Loopback, 0);
                listener.Start();
                try
                {
                    using var controlledClient = new TcpClient(AddressFamily.InterNetwork);
                    var acceptTask = listener.AcceptTcpClientAsync(eventTimeout.Token);
                    await controlledClient.ConnectAsync((IPEndPoint)listener.LocalEndpoint, eventTimeout.Token).ConfigureAwait(false);
                    using var accepted = await acceptTask.ConfigureAwait(false);
                    var eventResult = await Task.WhenAny(observed.Task, subscribeTask)
                        .WaitAsync(eventTimeout.Token)
                        .ConfigureAwait(false);
                    if (ReferenceEquals(eventResult, subscribeTask))
                    {
                        await subscribeTask.ConfigureAwait(false);
                    }

                    var streamEvent = await observed.Task.ConfigureAwait(false);
                    AssertTrue(streamEvent.Kind is StreamEventKind.FlowAdded or StreamEventKind.FlowUpdated, "Controlled flow produced the wrong event kind.");
                    AssertTrue(streamEvent.Sequence > snapshotSequence, "Stream event sequence did not advance beyond the snapshot.");
                }
                finally
                {
                    listener.Stop();
                    subscriptionCancellation.Cancel();
                    await eventClient.DisconnectAsync().ConfigureAwait(false);
                    try { await subscribeTask.ConfigureAwait(false); }
                    catch (Exception exception) when (exception is OperationCanceledException or IOException or ObjectDisposedException) { }
                }
            }

            stage = "service lifetime check";
            AssertTrue(!service.HasExited, "Service exited when clients disconnected.");
            await service.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(45)).ConfigureAwait(false);
            AssertEqual(0, service.ExitCode);
        }
        catch (Exception exception)
        {
            throw new TestFailureException($"Stage '{stage}' failed: {exception.Message}");
        }
        finally
        {
            if (!service.HasExited)
            {
                service.Kill(entireProcessTree: true);
                await service.WaitForExitAsync().ConfigureAwait(false);
            }

            SqliteConnection.ClearAllPools();
            await DeleteDirectoryWithRetryAsync(dataDirectory).ConfigureAwait(false);
        }
    }

    private static async Task TestRealFileCorrelationServiceIntegrationAsync()
    {
        if (!WindowsFirewallManager.IsAdministrator())
        {
            throw new TestFailureException("The real file-correlation integration requires an Administrator token.");
        }

        var repositoryRoot = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
        var servicePath = Path.Combine(repositoryRoot, "src", "EgressGuard.Service", "bin", "Release", "net8.0-windows", "EgressGuard.Service.exe");
        var serverPath = Path.Combine(repositoryRoot, "tools", "EgressGuard.TestServer", "bin", "Release", "net8.0-windows", "EgressGuard.TestServer.exe");
        var simulatorPath = Path.Combine(repositoryRoot, "tools", "EgressGuard.Simulator", "bin", "Release", "net8.0-windows", "EgressGuard.Simulator.exe");
        foreach (var path in new[] { servicePath, serverPath, simulatorPath })
        {
            if (!File.Exists(path)) throw new TestFailureException($"Integration executable not found: {path}");
        }

        var dataDirectory = Path.Combine(Path.GetTempPath(), "EgressGuard-CorrelationService-" + Guid.NewGuid().ToString("N"));
        var pipeName = $"{ProtocolConstants.PipeName}.Correlation.{Environment.ProcessId}.{Guid.NewGuid():N}";
        var portProbe = new TcpListener(IPAddress.Loopback, 0);
        portProbe.Start();
        var port = ((IPEndPoint)portProbe.LocalEndpoint).Port;
        portProbe.Stop();
        Directory.CreateDirectory(dataDirectory);
        var ownershipDirectory = Path.Combine(dataDirectory, "etw-ownership");
        var ownershipMarkerPath = Path.Combine(ownershipDirectory, "file-activity-session-owner.json");
        var sessionRegistry = new TraceEventSessionRegistry();
        AssertEqual(
            0,
            TraceEventSession.GetActiveSessionNames().Count(name => name.StartsWith(EtwSessionOwnershipManager.SessionPrefix, StringComparison.Ordinal)));

        using var service = StartIntegrationProcess(servicePath, [], redirectOutput: false, new Dictionary<string, string>
        {
            ["EGRESSGUARD_DATA_DIR"] = dataDirectory,
            ["EGRESSGUARD_TEST_DURATION_SECONDS"] = "45",
            ["EGRESSGUARD_PIPE_NAME"] = pipeName,
            ["EGRESSGUARD_ENABLE_FILE_CORRELATION"] = "true"
        });
        using var server = StartIntegrationProcess(serverPath, ["--port", port.ToString(System.Globalization.CultureInfo.InvariantCulture), "--protocol", "tcp", "--duration-seconds", "45"], redirectOutput: true);
        Process? simulator = null;
        string? ownedSessionName = null;
        try
        {
            await using var client = new EgressGuardPipeClient(pipeName);
            await ConnectWithRetryAsync(client).ConfigureAwait(false);
            ownedSessionName = await ReadEtwSessionNameFromMarkerAsync(ownershipMarkerPath).ConfigureAwait(false);
            AssertTrue(sessionRegistry.IsActive(ownedSessionName), "The service-owned exact ETW session was not active after startup.");
            await Task.Delay(500).ConfigureAwait(false);
            simulator = StartIntegrationProcess(simulatorPath, ["--file-correlation-test", "--port", port.ToString(System.Globalization.CultureInfo.InvariantCulture), "--hold-seconds", "30"], redirectOutput: true);

            FileCorrelationsMessage? evidence = null;
            NetworkFlow? simulatorFlow = null;
            ServiceStatusMessage? lastStatus = null;
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(25));
            try
            {
                while (!timeout.IsCancellationRequested)
                {
                    var statusResponse = await client.SendAsync(MessageEnvelope.Create(MessageTypes.GetStatus, new { }), TimeSpan.FromSeconds(3), timeout.Token).ConfigureAwait(false);
                    lastStatus = statusResponse.ReadPayload<ServiceStatusMessage>();
                    var flowsResponse = await client.SendAsync(MessageEnvelope.Create(MessageTypes.GetActiveFlows, new { }), TimeSpan.FromSeconds(3), timeout.Token).ConfigureAwait(false);
                    var lastFlows = flowsResponse.ReadPayload<ActiveFlowsMessage>().Flows;
                    simulatorFlow = lastFlows.FirstOrDefault(flow => flow.ProcessIdentity?.ProcessId == simulator.Id);
                    if (simulatorFlow is not null)
                    {
                        var correlationsResponse = await client.SendAsync(
                            MessageEnvelope.Create(MessageTypes.GetFileCorrelations, new GetFileCorrelationsMessage(simulatorFlow.Id, 20)),
                            TimeSpan.FromSeconds(3),
                            timeout.Token).ConfigureAwait(false);
                        evidence = correlationsResponse.ReadPayload<FileCorrelationsMessage>();
                        if (evidence.Correlations.Count > 0) break;
                    }

                    await Task.Delay(250, timeout.Token).ConfigureAwait(false);
                }
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            {
                var simulatorState = simulator is null ? "not-started" : simulator.HasExited ? $"exited:{simulator.ExitCode}" : "running";
                string simulatorDiagnostics = string.Empty;
                if (simulator is not null)
                {
                    if (!simulator.HasExited) { simulator.Kill(entireProcessTree: true); await simulator.WaitForExitAsync().ConfigureAwait(false); }
                    simulatorDiagnostics = await simulator.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
                }

                throw new TestFailureException($"Pre-flow correlation timed out. FlowObserved={simulatorFlow is not null}; Simulator={simulatorState}; ActiveFlows={lastStatus?.ActiveFlowCount}; FileSensor={lastStatus?.FileSensor?.State}/{lastStatus?.FileSensor?.DroppedEvents}/{lastStatus?.FileSensor?.Detail}; FileCorrelationEnabled={lastStatus?.FileCorrelationEnabled}; SimulatorOutput={simulatorDiagnostics}");
            }


            var observedFlow = simulatorFlow ?? throw new TestFailureException("The service did not observe the Simulator loopback flow.");
            var observedEvidence = evidence is { Correlations.Count: > 0 }
                ? evidence
                : throw new TestFailureException("The service IPC response did not expose correlated file activity.");
            AssertTrue(observedEvidence.Correlations.All(item => item.ProcessIdentity == observedFlow.ProcessIdentity), "Correlation process identity did not match PID + process start time.");
            AssertTrue(observedEvidence.Correlations.Any(item =>
                item.Extension == ".egfixture"
                && item.TimeDeltaSeconds < 0
                && item.TimeDeltaSeconds >= -30
                && item.TimeDeltaSeconds <= 5),
                "The synthetic .egfixture read before the first network flow was not correlated inside the -30/+5 second window.");
            AssertTrue(observedEvidence.Correlations.All(item => !item.DisplayPath.Contains("EgressGuard-FileCorrelation-", StringComparison.OrdinalIgnoreCase)), "IPC leaked the synthetic raw path.");

            await simulator.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(40)).ConfigureAwait(false);
            AssertEqual(0, simulator.ExitCode);
            var simulatorOutput = await simulator.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            AssertTrue(simulatorOutput.Contains("without transmitting file contents", StringComparison.Ordinal), "Simulator did not report connect-only behavior.");
            await server.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(50)).ConfigureAwait(false);
            AssertEqual(0, server.ExitCode);
            var serverOutput = await server.StandardOutput.ReadToEndAsync().ConfigureAwait(false);
            AssertTrue(serverOutput.Contains("closed after 0 test bytes", StringComparison.Ordinal), "Test server observed transmitted bytes during the file-correlation fixture.");
            await service.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(15)).ConfigureAwait(false);
            AssertEqual(0, service.ExitCode);
            AssertTrue(!sessionRegistry.IsActive(ownedSessionName), "The service exited normally but left its exact ETW session active.");
            AssertTrue(!File.Exists(ownershipMarkerPath), "The service exited normally but left its ETW ownership marker.");
            AssertEqual(
                0,
                TraceEventSession.GetActiveSessionNames().Count(name => name.StartsWith(EtwSessionOwnershipManager.SessionPrefix, StringComparison.Ordinal)));

            await using var connection = new SqliteConnection($"Data Source={Path.Combine(dataDirectory, "egressguard.db")};Mode=ReadOnly");
            await connection.OpenAsync().ConfigureAwait(false);
            await using var command = connection.CreateCommand();
            command.CommandText = "SELECT protected_file_id, display_path FROM file_correlations;";
            await using var reader = await command.ExecuteReaderAsync().ConfigureAwait(false);
            var persisted = 0;
            while (await reader.ReadAsync().ConfigureAwait(false))
            {
                persisted++;
                AssertTrue(!reader.GetString(0).Contains("EgressGuard-FileCorrelation-", StringComparison.OrdinalIgnoreCase), "Database protected identifier leaked the synthetic raw path.");
                AssertTrue(!reader.GetString(1).Contains("EgressGuard-FileCorrelation-", StringComparison.OrdinalIgnoreCase), "Database display identifier leaked the synthetic raw path.");
            }

            AssertTrue(persisted > 0, "No correlated evidence was persisted.");
        }
        finally
        {
            foreach (var process in new[] { simulator, server, service })
            {
                if (process is not null && !process.HasExited)
                {
                    process.Kill(entireProcessTree: true);
                    await process.WaitForExitAsync().ConfigureAwait(false);
                }
            }

            // Failure-path recovery only. Any success-path leak is asserted
            // above before this exact-marker recovery can return the machine
            // to a clean state; the original test failure still propagates.
            if (File.Exists(ownershipMarkerPath))
            {
                await using var orphanReclaimer = new EtwFileActivitySensor([ownershipDirectory], ownershipDirectory: ownershipDirectory);
                await orphanReclaimer.StartAsync(CancellationToken.None).ConfigureAwait(false);
                await orphanReclaimer.StopAsync(CancellationToken.None).ConfigureAwait(false);
            }

            SqliteConnection.ClearAllPools();
            await DeleteDirectoryWithRetryAsync(dataDirectory).ConfigureAwait(false);
        }
    }

    private static async Task<string> ReadEtwSessionNameFromMarkerAsync(string markerPath)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        while (!File.Exists(markerPath))
        {
            await Task.Delay(50, timeout.Token).ConfigureAwait(false);
        }

        using var document = System.Text.Json.JsonDocument.Parse(await File.ReadAllTextAsync(markerPath, timeout.Token).ConfigureAwait(false));
        var sessionName = document.RootElement.GetProperty("SessionName").GetString();
        return string.IsNullOrWhiteSpace(sessionName)
            ? throw new TestFailureException("The ETW ownership marker did not contain an exact session name.")
            : sessionName;
    }

    private static Process StartIntegrationProcess(
        string path,
        IReadOnlyList<string> arguments,
        bool redirectOutput,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        var startInfo = new ProcessStartInfo(path)
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            RedirectStandardOutput = redirectOutput,
            RedirectStandardError = redirectOutput
        };
        foreach (var argument in arguments) startInfo.ArgumentList.Add(argument);
        if (environment is not null)
        {
            foreach (var item in environment) startInfo.Environment[item.Key] = item.Value;
        }

        return Process.Start(startInfo) ?? throw new TestFailureException($"Process failed to start: {path}");
    }

    private static async Task TestRealFirewallCancellationIntegrationAsync()
    {
        if (!WindowsFirewallManager.IsAdministrator())
        {
            throw new TestFailureException("Real firewall cancellation integration requires an Administrator token.");
        }

        var executablePath = Environment.ProcessPath ?? throw new TestFailureException("Test executable path is unavailable.");
        var rule = TestRuleForExecutable(executablePath);
        var startedProcesses = new List<(int Id, DateTime StartTimeUtc)>();
        var processSync = new object();
        var runner = new PowerShellProcessRunner(
            TimeSpan.FromSeconds(30),
            TimeSpan.FromSeconds(5),
            startInfo =>
            {
                var process = Process.Start(startInfo);
                if (process is not null)
                {
                    lock (processSync)
                    {
                        startedProcesses.Add((process.Id, process.StartTime.ToUniversalTime()));
                    }
                }

                return process;
            });
        var manager = new OwnedFirewallRuleManager(new DelayAfterCreateRunner(runner), () => true);
        using var unrelated = Process.Start(new ProcessStartInfo("powershell.exe")
        {
            UseShellExecute = false,
            CreateNoWindow = true,
            ArgumentList = { "-NoProfile", "-NonInteractive", "-Command", "Start-Sleep -Seconds 30" }
        }) ?? throw new TestFailureException("Unable to start unrelated PowerShell integration fixture.");
        try
        {
            using var cancellation = new CancellationTokenSource();
            var createTask = manager.CreateAsync(rule, cancellation.Token);
            using var observationTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            while (!await manager.ExistsAsync(rule.Id, observationTimeout.Token).ConfigureAwait(false))
            {
                await Task.Delay(100, observationTimeout.Token).ConfigureAwait(false);
            }

            cancellation.Cancel();
            await AssertThrowsAsync<OperationCanceledException>(() => createTask).ConfigureAwait(false);
            AssertTrue(!await manager.ExistsAsync(rule.Id, CancellationToken.None).ConfigureAwait(false), "Cancelled real firewall create left an orphan rule.");
            AssertTrue(!unrelated.HasExited, "Firewall reconciliation killed an unrelated PowerShell process.");

            List<(int Id, DateTime StartTimeUtc)> snapshot;
            lock (processSync)
            {
                snapshot = [.. startedProcesses];
            }

            foreach (var started in snapshot)
            {
                AssertTrue(!IsSameProcessRunning(started.Id, started.StartTimeUtc), $"Owned PowerShell process {started.Id} remained after integration cleanup.");
            }
        }
        finally
        {
            try
            {
                await manager.DeleteAsync(rule.Id, CancellationToken.None).ConfigureAwait(false);
            }
            finally
            {
                if (!unrelated.HasExited)
                {
                    unrelated.Kill(entireProcessTree: true);
                    await unrelated.WaitForExitAsync().ConfigureAwait(false);
                }
            }
        }
    }

    private static FirewallRule TestRuleForExecutable(string executablePath)
    {
        using var stream = new FileStream(executablePath, FileMode.Open, FileAccess.Read, FileShare.Read);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        return new FirewallRule(
            Guid.NewGuid(),
            "Phase 3.5.1 cancellation integration",
            FirewallAction.Block,
            RuleSource.User,
            executablePath,
            hash,
            "203.0.113.1",
            9,
            TransportProtocol.Tcp,
            true,
            DateTimeOffset.UtcNow,
            null);
    }

    private static async Task WaitForFileAsync(string path)
    {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
        while (!File.Exists(path))
        {
            await Task.Delay(25, timeout.Token).ConfigureAwait(false);
        }
    }

    private static async Task AssertProcessExitedAsync(int processId)
    {
        for (var attempt = 0; attempt < 40; attempt++)
        {
            if (!IsProcessRunning(processId))
            {
                return;
            }

            await Task.Delay(50).ConfigureAwait(false);
        }

        throw new TestFailureException($"Process {processId} remained after cleanup.");
    }

    private static bool IsProcessRunning(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited;
        }
        catch (ArgumentException)
        {
            return false;
        }
    }

    private static bool IsSameProcessRunning(int processId, DateTime startTimeUtc)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited && process.StartTime.ToUniversalTime() == startTimeUtc;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private static async Task DeleteDirectoryWithRetryAsync(string path)
    {
        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                Directory.Delete(path, recursive: true);
                return;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException)
            {
                if (attempt == 9)
                {
                    throw;
                }

                await Task.Delay(250).ConfigureAwait(false);
            }
        }
    }

    private static async Task ConnectWithRetryAsync(EgressGuardPipeClient client)
    {
        Exception? lastError = null;
        for (var attempt = 0; attempt < 10; attempt++)
        {
            try
            {
                await client.ConnectAsync(TimeSpan.FromSeconds(1), CancellationToken.None).ConfigureAwait(false);
                return;
            }
            catch (Exception exception) when (exception is IOException or TimeoutException or OperationCanceledException)
            {
                lastError = exception;
                await Task.Delay(250).ConfigureAwait(false);
            }
        }

        throw new TestFailureException($"Could not connect to service pipe: {lastError?.Message}");
    }

    private static async Task TestProcessChurnAsync()
    {
        var processes = new List<Process>();
        for (var index = 0; index < 10; index++)
        {
            processes.Add(Process.Start(new ProcessStartInfo("cmd.exe", "/c exit") { CreateNoWindow = true, UseShellExecute = false })!);
        }

        _ = new ProcessSnapshotCollector().Capture();
        await Task.WhenAll(processes.Select(process => process.WaitForExitAsync())).ConfigureAwait(false);
        foreach (var process in processes) process.Dispose();
    }

    private static RiskSignals Signals(
        bool isUnsigned = false,
        bool isInTemp = false,
        bool appData = false,
        bool isFirstSeen = false,
        bool unknownPublisher = false,
        bool firstDestination = false,
        bool destinationBlocked = false,
        bool suspiciousParent = false,
        bool sufficientBaseline = true,
        bool deviates = false) =>
        new(isUnsigned, isInTemp, appData, isFirstSeen, unknownPublisher, firstDestination, destinationBlocked, suspiciousParent, sufficientBaseline, deviates, "test.exe", "127.0.0.1", "parent.exe");

    private static NetworkFlow SampleFlow(RiskAssessment? risk = null)
    {
        var start = new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
        var executable = new ExecutableInfo("C:\\Tests\\EgressGuard.Simulator.exe", new string('A', 64), SignatureVerificationStatus.Unsigned, null, 100, start, false, false);
        return new NetworkFlow("test-flow", new ProcessIdentity(42, start), "EgressGuard.Simulator", executable, 1, TransportProtocol.Tcp, IpVersion.IPv4, new NetworkEndpoint(IPAddress.Loopback, 50000), new DestinationInfo(IPAddress.Loopback, 5050, "localhost", "controlled test"), start, start.AddSeconds(1), "ESTABLISHED", null, null, false, risk);
    }

    private static FirewallRule SampleRule(FirewallAction action, NetworkFlow flow) =>
        new(Guid.NewGuid(), action.ToString(), action, RuleSource.User, flow.Executable!.Path, flow.Executable.Sha256, flow.Destination!.Address.ToString(), flow.Destination.Port, flow.Protocol, true, DateTimeOffset.UtcNow, null);

    private static void AssertTrue(bool condition, string message)
    {
        if (!condition)
        {
            throw new TestFailureException(message);
        }
    }

    private static void AssertEqual<T>(T expected, T actual)
    {
        if (!EqualityComparer<T>.Default.Equals(expected, actual))
        {
            throw new TestFailureException($"Expected '{expected}', got '{actual}'.");
        }
    }

    private static void AssertNotEqual<T>(T left, T right)
    {
        if (EqualityComparer<T>.Default.Equals(left, right))
        {
            throw new TestFailureException($"Expected values to differ, but both were '{left}'.");
        }
    }

    private static void AssertThrows<TException>(Action action) where TException : Exception
    {
        try
        {
            action();
        }
        catch (TException)
        {
            return;
        }

        throw new TestFailureException($"Expected {typeof(TException).Name}.");
    }

    private static async Task AssertThrowsAsync<TException>(Func<Task> action) where TException : Exception
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (TException)
        {
            return;
        }

        throw new TestFailureException($"Expected {typeof(TException).Name}.");
    }

    private static async Task AssertThrowsAnyAsync(Func<Task> action, params Type[] exceptionTypes)
    {
        try
        {
            await action().ConfigureAwait(false);
        }
        catch (Exception exception) when (exceptionTypes.Contains(exception.GetType()) || exceptionTypes.Any(type => type.IsAssignableFrom(exception.GetType())))
        {
            return;
        }

        throw new TestFailureException("Expected one of: " + string.Join(", ", exceptionTypes.Select(type => type.Name)));
    }

    private sealed class TestFailureException(string message) : Exception(message);

    private sealed class EmptyFlowSensor : INetworkFlowSensor
    {
        public IReadOnlyList<NetworkFlow> Capture() => [];
    }

    private sealed class AccessDeniedFileSensor : IFileActivitySensor
    {
        private FileSensorStatus _status = new(FileSensorState.Stopped, 0, null, DateTimeOffset.UtcNow);
        public FileSensorStatus Status => _status;
        public event EventHandler<FileSensorStatus>? StatusChanged;
        public Task StartAsync(CancellationToken cancellationToken)
        {
            _status = new FileSensorStatus(FileSensorState.AccessDenied, 0, "Controlled test.", DateTimeOffset.UtcNow);
            StatusChanged?.Invoke(this, _status);
            return Task.CompletedTask;
        }

        public Task StopAsync(CancellationToken cancellationToken)
        {
            _status = new FileSensorStatus(FileSensorState.Stopped, 0, null, DateTimeOffset.UtcNow);
            StatusChanged?.Invoke(this, _status);
            return Task.CompletedTask;
        }

        public async IAsyncEnumerable<FileActivity> ReadAllAsync([System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Delay(Timeout.InfiniteTimeSpan, cancellationToken).ConfigureAwait(false);
            yield break;
        }

        public ValueTask DisposeAsync() => ValueTask.CompletedTask;
    }

    private sealed class FixedProcessIdentityResolver(ProcessIdentity identity, string processName) : IProcessIdentityResolver
    {
        public ResolvedProcessIdentity Value { get; } = new(identity, processName);
        public ResolvedProcessIdentity? Resolve(int processId) => processId == Value.Identity.ProcessId ? Value : null;
    }

    private sealed class MutableProcessIdentityResolver : IProcessIdentityResolver
    {
        public Dictionary<int, ResolvedProcessIdentity> Values { get; } = [];
        public int ResolveCalls { get; private set; }
        public ResolvedProcessIdentity? Resolve(int processId)
        {
            ResolveCalls++;
            return Values.GetValueOrDefault(processId);
        }
    }

    private sealed class FakeEtwSessionRegistry : IEtwSessionRegistry
    {
        public HashSet<string> Active { get; } = new(StringComparer.Ordinal);
        public List<string> Stopped { get; } = [];
        public bool IsActive(string sessionName) => Active.Contains(sessionName);
        public void StopExact(string sessionName)
        {
            if (!Active.Remove(sessionName)) throw new InvalidOperationException("Session was not active.");
            Stopped.Add(sessionName);
        }
    }

    private sealed class FakeFirewallRuleManager : IFirewallRuleManager
    {
        public HashSet<Guid> OwnedRuleIds { get; } = [];
        public HashSet<Guid> ForeignRuleIds { get; } = [];
        public List<Guid> DeletedRuleIds { get; } = [];
        public bool CreateChangesState { get; init; } = true;
        public bool DeleteFails { get; init; }
        public int CreateCallCount { get; private set; }

        public Task<FirewallMutationStatus> CreateAsync(FirewallRule rule, CancellationToken cancellationToken)
        {
            cancellationToken.ThrowIfCancellationRequested();
            CreateCallCount++;
            if (CreateChangesState)
            {
                OwnedRuleIds.Add(rule.Id);
            }

            return Task.FromResult(CreateChangesState ? FirewallMutationStatus.Created : FirewallMutationStatus.Unchanged);
        }

        public Task DeleteAsync(Guid ruleId, CancellationToken cancellationToken)
        {
            DeletedRuleIds.Add(ruleId);
            if (DeleteFails)
            {
                throw new InvalidOperationException("controlled rollback failure");
            }

            OwnedRuleIds.Remove(ruleId);
            return Task.CompletedTask;
        }

        public Task SetEnabledAsync(Guid ruleId, bool enabled, CancellationToken cancellationToken) => Task.CompletedTask;

        public Task ResetOwnedRulesAsync(CancellationToken cancellationToken)
        {
            OwnedRuleIds.Clear();
            return Task.CompletedTask;
        }

        public Task<bool> ExistsAsync(Guid ruleId, CancellationToken cancellationToken) => Task.FromResult(OwnedRuleIds.Contains(ruleId));
    }

    private enum FakeExactRuleState
    {
        Absent,
        Match,
        Mismatch
    }

    private sealed class StatefulFirewallPowerShellRunner : IPowerShellProcessRunner
    {
        public FakeExactRuleState State { get; set; }
        public bool CancelCreateAfterMutation { get; init; }
        public CancellationTokenSource? Cancellation { get; set; }
        public int CreateCount { get; private set; }
        public int ExactDeleteCount { get; private set; }
        public int InvocationCount { get; private set; }

        public Task<PowerShellProcessResult> RunAsync(
            string script,
            IReadOnlyDictionary<string, string> environment,
            CancellationToken cancellationToken)
        {
            InvocationCount++;
            cancellationToken.ThrowIfCancellationRequested();
            if (script.Contains("EGRESSGUARD_EXACT_RULE_QUERY", StringComparison.Ordinal))
            {
                return Task.FromResult(Result(State switch
                {
                    FakeExactRuleState.Absent => "ABSENT",
                    FakeExactRuleState.Match => "MATCH",
                    _ => "MISMATCH"
                }));
            }

            if (script.Contains("EGRESSGUARD_CREATE_MUTATION", StringComparison.Ordinal))
            {
                CreateCount++;
                State = FakeExactRuleState.Match;
                if (CancelCreateAfterMutation)
                {
                    Cancellation?.Cancel();
                    return Task.FromCanceled<PowerShellProcessResult>(Cancellation?.Token ?? new CancellationToken(canceled: true));
                }

                return Task.FromResult(Result("CREATED"));
            }

            if (script.Contains("EGRESSGUARD_EXACT_RULE_DELETE", StringComparison.Ordinal))
            {
                ExactDeleteCount++;
                State = FakeExactRuleState.Absent;
                return Task.FromResult(Result("DELETED"));
            }

            return Task.FromResult(Result(string.Empty));
        }

        private static PowerShellProcessResult Result(string output) => new(output, string.Empty, 0);
    }

    private sealed class MockFirewallSemanticsRunner(IReadOnlyDictionary<string, string> overrides) : IPowerShellProcessRunner
    {
        private readonly PowerShellProcessRunner _inner = new();

        public int QueryCount { get; private set; }
        public int CreateCount { get; private set; }
        public int DeleteCount { get; private set; }
        public IReadOnlyDictionary<string, string>? LastEnvironment { get; private set; }

        public Task<PowerShellProcessResult> RunAsync(
            string script,
            IReadOnlyDictionary<string, string> environment,
            CancellationToken cancellationToken)
        {
            if (script.Contains("EGRESSGUARD_EXACT_RULE_QUERY", StringComparison.Ordinal)) QueryCount++;
            if (script.Contains("EGRESSGUARD_CREATE_MUTATION", StringComparison.Ordinal)) CreateCount++;
            if (script.Contains("EGRESSGUARD_EXACT_RULE_DELETE", StringComparison.Ordinal)) DeleteCount++;

            var fixture = new Dictionary<string, string>(environment, StringComparer.OrdinalIgnoreCase)
            {
                ["EG_ACTUAL_DESCRIPTION"] = environment["EG_RULE_DESCRIPTION"],
                ["EG_ACTUAL_PROGRAM"] = environment["EG_PROGRAM"],
                ["EG_ACTUAL_REMOTE_ADDRESS"] = environment["EG_REMOTE_ADDRESS"],
                ["EG_ACTUAL_REMOTE_PORT"] = environment["EG_REMOTE_PORT"],
                ["EG_ACTUAL_PROTOCOL"] = environment["EG_PROTOCOL"],
                ["EG_ACTUAL_ENABLED"] = environment["EG_ENABLED"],
                ["EG_ACTUAL_PROFILE"] = environment["EG_PROFILE"]
            };
            foreach (var item in overrides)
            {
                fixture[item.Key] = item.Value;
            }

            LastEnvironment = fixture;
            return _inner.RunAsync(MockFunctions + script, fixture, cancellationToken);
        }

        private const string MockFunctions = """
            function Get-NetFirewallRule {
              [CmdletBinding()] param()
              [pscustomobject]@{DisplayName=$env:EG_RULE_NAME;Description=$env:EG_ACTUAL_DESCRIPTION;Direction='Outbound';Action=$env:EG_ACTION;Enabled=$env:EG_ACTUAL_ENABLED;Profile=$env:EG_ACTUAL_PROFILE}
            }
            function Get-NetFirewallApplicationFilter {
              [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Rule)
              process { [pscustomobject]@{Program=$env:EG_ACTUAL_PROGRAM} }
            }
            function Get-NetFirewallAddressFilter {
              [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Rule)
              process { [pscustomobject]@{RemoteAddress=$env:EG_ACTUAL_REMOTE_ADDRESS} }
            }
            function Get-NetFirewallPortFilter {
              [CmdletBinding()] param([Parameter(ValueFromPipeline)]$Rule)
              process { [pscustomobject]@{RemotePort=$env:EG_ACTUAL_REMOTE_PORT;Protocol=$env:EG_ACTUAL_PROTOCOL} }
            }
            """;
    }

    private sealed class DelayAfterCreateRunner(IPowerShellProcessRunner inner) : IPowerShellProcessRunner
    {
        public Task<PowerShellProcessResult> RunAsync(
            string script,
            IReadOnlyDictionary<string, string> environment,
            CancellationToken cancellationToken)
        {
            if (script.Contains("EGRESSGUARD_CREATE_MUTATION", StringComparison.Ordinal))
            {
                script = script.Replace(
                    "# EGRESSGUARD_AFTER_CREATE",
                    "# EGRESSGUARD_AFTER_CREATE\nStart-Sleep -Seconds 30",
                    StringComparison.Ordinal);
            }

            return inner.RunAsync(script, environment, cancellationToken);
        }
    }

    private sealed record LogEntry(LogLevel Level, string Message, Exception? Exception);

    private sealed class ListLogger<T> : ILogger<T>
    {
        public List<LogEntry> Entries { get; } = [];

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel,
            EventId eventId,
            TState state,
            Exception? exception,
            Func<TState, Exception?, string> formatter) => Entries.Add(new LogEntry(logLevel, formatter(state, exception), exception));
    }

    private sealed class NullScope : IDisposable
    {
        public static NullScope Instance { get; } = new();

        public void Dispose()
        {
        }
    }
}
