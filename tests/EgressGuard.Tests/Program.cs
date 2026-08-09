using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using EgressGuard.Core;
using EgressGuard.Persistence;
using EgressGuard.Protocol;
using EgressGuard.Windows;
using Microsoft.Data.Sqlite;

namespace EgressGuard.Tests;

internal static class Program
{
    public static async Task<int> Main()
    {
        var tests = new (string Name, Func<Task> Run)[]
        {
            ("Process identity includes start time", TestProcessIdentityAsync),
            ("Native port conversion", TestPortConversionAsync),
            ("Endpoint formatting", TestEndpointFormattingAsync),
            ("Executable metadata hashes and caches", TestExecutableMetadataAsync),
            ("Firewall path validation is simulator-only", TestFirewallPathValidationAsync),
            ("Controlled TCP connection maps to current process", TestControlledTcpMappingAsync),
            ("Controlled IPv6 TCP maps to current process", TestControlledIPv6MappingAsync),
            ("Controlled UDP endpoint maps to current process", TestControlledUdpMappingAsync),
            ("Windows flow sensor preserves process identity", TestWindowsFlowSensorAsync),
            ("Risk score boundaries and determinism", TestRiskEngineAsync),
            ("Policy conflict priority", TestPolicyPriorityAsync),
            ("Baseline minimum samples and reset", TestBaselineAsync),
            ("SQLite migration and flow persistence", TestPersistenceAsync),
            ("SQLite lock fails without unsafe fallback", TestDatabaseLockAsync),
            ("Protocol frame roundtrip", TestProtocolRoundTripAsync),
            ("Protocol rejects oversized message", TestOversizedMessageAsync),
            ("Protocol handles disconnect", TestProtocolDisconnectAsync),
            ("Service pipe disconnect and reconnect", TestServicePipeReconnectAsync),
            ("Process churn does not crash collector", TestProcessChurnAsync)
        };

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
            var bytes = "EgressGuard synthetic executable bytes"u8.ToArray();
            File.WriteAllBytes(testPath, bytes);
            var provider = new ExecutableMetadataProvider();
            var first = provider.GetMetadata(testPath) ?? throw new TestFailureException("Metadata was null.");
            var second = provider.GetMetadata(testPath) ?? throw new TestFailureException("Cached metadata was null.");
            AssertEqual(Convert.ToHexString(SHA256.HashData(bytes)), first.Sha256);
            AssertTrue(ReferenceEquals(first, second), "Expected the unchanged file metadata to come from cache.");
            AssertEqual(false, first.HasDigitalSignature);
        }
        finally
        {
            Directory.Delete(testDirectory, recursive: true);
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
        }
        finally
        {
            Directory.Delete(testDirectory, recursive: true);
        }

        return Task.CompletedTask;
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

    private static async Task TestServicePipeReconnectAsync()
    {
        var servicePath = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "..", "src", "EgressGuard.Service", "bin", "Release", "net8.0-windows", "EgressGuard.Service.exe"));
        if (!File.Exists(servicePath))
        {
            throw new TestFailureException($"Service apphost not found: {servicePath}");
        }

        var dataDirectory = Path.Combine(Path.GetTempPath(), "EgressGuard-ServiceTests-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(dataDirectory);
        var startInfo = new ProcessStartInfo(servicePath)
        {
            UseShellExecute = false,
            CreateNoWindow = true
        };
        startInfo.Environment["EGRESSGUARD_DATA_DIR"] = dataDirectory;
        startInfo.Environment["EGRESSGUARD_TEST_DURATION_SECONDS"] = "20";
        using var service = Process.Start(startInfo) ?? throw new TestFailureException("Service process failed to start.");
        var stage = "first connect";
        try
        {
            await using (var first = new EgressGuardPipeClient())
            {
                await ConnectWithRetryAsync(first).ConfigureAwait(false);
                stage = "first status request";
                var response = await first.SendAsync(MessageEnvelope.Create(MessageTypes.GetStatus, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(false);
                AssertTrue(response.ReadPayload<ServiceStatusMessage>().IsRunning, "Service did not report running state.");
            }

            stage = "second connect";
            await using (var second = new EgressGuardPipeClient())
            {
                await ConnectWithRetryAsync(second).ConfigureAwait(false);
                stage = "second flows request";
                var response = await second.SendAsync(MessageEnvelope.Create(MessageTypes.GetActiveFlows, new { }), TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(false);
                _ = response.ReadPayload<ActiveFlowsMessage>();
            }

            stage = "service lifetime check";
            AssertTrue(!service.HasExited, "Service exited when clients disconnected.");
            await service.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(25)).ConfigureAwait(false);
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
            Directory.Delete(dataDirectory, recursive: true);
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
        var executable = new ExecutableInfo("C:\\Tests\\EgressGuard.Simulator.exe", new string('A', 64), false, null, 100, start, false, false);
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
}
