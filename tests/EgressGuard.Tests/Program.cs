using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using EgressGuard.Core;
using EgressGuard.Persistence;
using EgressGuard.Protocol;
using EgressGuard.Service;
using EgressGuard.Windows;
using Microsoft.Data.Sqlite;
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

        var tests = new (string Name, Func<Task> Run)[]
        {
            ("Process identity includes start time", TestProcessIdentityAsync),
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
            ("SQLite lock fails without unsafe fallback", TestDatabaseLockAsync),
            ("Service graceful cancellation completes without failure logs", TestGracefulCancellationAsync),
            ("Automatic firewall rule rolls back on persistence failure", TestAutomaticRuleRollbackAsync),
            ("Automatic firewall rule rolls back on cancellation", TestAutomaticRuleCancellationRollbackAsync),
            ("Automatic firewall rollback logs original and rollback failures", TestAutomaticRuleRollbackFailureLoggingAsync),
            ("Protocol frame roundtrip", TestProtocolRoundTripAsync),
            ("Protocol rejects oversized message", TestOversizedMessageAsync),
            ("Protocol handles disconnect", TestProtocolDisconnectAsync),
            ("Event buffer preserves order and detects gaps and overflow", TestEventBufferAsync),
            ("Slow event subscriber cannot block publisher", TestSlowSubscriberAsync),
            ("Flow state emits add update and remove transitions", TestFlowStateTransitionsAsync),
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
        startInfo.Environment["EGRESSGUARD_TEST_DURATION_SECONDS"] = "20";
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
                using var eventTimeout = new CancellationTokenSource(TimeSpan.FromSeconds(15));
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
            await DeleteDirectoryWithRetryAsync(dataDirectory).ConfigureAwait(false);
        }
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
