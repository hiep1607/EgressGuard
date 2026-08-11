using System.Diagnostics;
using System.IO.Pipes;
using System.Net;
using System.Net.Sockets;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;
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
            ("Disabled and degraded file sensors remain bounded", TestFileSensorStatesAsync),
            ("File sensor publishes coalesced final dropped count", TestFileSensorDroppedCountNotificationsAsync),
            ("File sensor rejects events older than resolved process identity", TestFileSensorPidReuseProjectionAsync),
            ("Process identity cache is bounded, expires, and rejects PID reuse", TestProcessIdentityCacheAsync),
            ("Pre-flow raw events promote through the production interest path", TestPreFlowRawPromotionAsync),
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
