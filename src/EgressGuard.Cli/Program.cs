using EgressGuard.Core;
using System.Globalization;
using EgressGuard.Protocol;

namespace EgressGuard.Cli;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            if (args.Length > 0 && string.Equals(args[0], "firewall", StringComparison.OrdinalIgnoreCase))
            {
                return RunFirewall(args[1..]);
            }

            if (args.Length > 0 && string.Equals(args[0], "service", StringComparison.OrdinalIgnoreCase))
            {
                return await RunServiceAsync(args[1..]).ConfigureAwait(false);
            }

            if (args.Length > 0 && args[0] is "help" or "--help" or "-h")
            {
                PrintHelp();
                return 0;
            }

            return await RunWatchAsync(args).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is ArgumentException
            or FileNotFoundException
            or UnauthorizedAccessException
            or InvalidOperationException
            or System.ComponentModel.Win32Exception)
        {
            var detail = string.IsNullOrWhiteSpace(exception.Message) ? exception.ToString() : exception.Message;
            Console.Error.WriteLine($"Error: {detail}");
            return 1;
        }
    }

    private static async Task<int> RunWatchAsync(string[] args)
    {
        var interval = TimeSpan.FromSeconds(2);
        var runOnce = false;
        string? processFilter = null;

        for (var index = args.Length > 0 && string.Equals(args[0], "watch", StringComparison.OrdinalIgnoreCase) ? 1 : 0;
             index < args.Length;
             index++)
        {
            switch (args[index])
            {
                case "--interval-ms" when index + 1 < args.Length:
                    interval = TimeSpan.FromMilliseconds(ParsePositiveInt(args[++index], "--interval-ms"));
                    break;
                case "--process" when index + 1 < args.Length:
                    processFilter = args[++index];
                    break;
                case "--once":
                    runOnce = true;
                    break;
                default:
                    throw new ArgumentException($"Unknown or incomplete argument: {args[index]}");
            }
        }

        using var cancellation = new CancellationTokenSource();
        Console.CancelKeyPress += (_, eventArgs) =>
        {
            eventArgs.Cancel = true;
            cancellation.Cancel();
        };

        var service = new ConnectionSnapshotService();
        do
        {
            var snapshot = service.Capture();
            Render(snapshot, processFilter, clearScreen: !runOnce);
            if (runOnce)
            {
                break;
            }

            try
            {
                await Task.Delay(interval, cancellation.Token).ConfigureAwait(false);
            }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested)
            {
                break;
            }
        }
        while (!cancellation.IsCancellationRequested);

        Console.WriteLine("EgressGuard CLI stopped cleanly.");
        return 0;
    }

    private static int RunFirewall(string[] args)
    {
        if (args.Length == 0)
        {
            throw new ArgumentException("Specify firewall status, block, or unblock.");
        }

        FirewallOperationResult result;
        switch (args[0].ToLowerInvariant())
        {
            case "status":
                result = WindowsFirewallManager.GetStatus();
                break;
            case "block":
                var path = ReadOption(args[1..], "--path")
                    ?? throw new ArgumentException("firewall block requires --path <EgressGuard.Simulator.exe>.");
                Console.WriteLine("Administrator rights are required. EgressGuard will not request elevation or bypass UAC.");
                result = WindowsFirewallManager.BlockSimulator(path);
                break;
            case "unblock":
                Console.WriteLine("Administrator rights are required. EgressGuard will not request elevation or bypass UAC.");
                result = WindowsFirewallManager.UnblockSimulator();
                break;
            default:
                throw new ArgumentException($"Unknown firewall command: {args[0]}");
        }

        Console.WriteLine(result.Message);
        return 0;
    }

    private static async Task<int> RunServiceAsync(string[] args)
    {
        if (args.Length == 0)
        {
            throw new ArgumentException("Specify a service command.");
        }

        await using var client = new EgressGuardPipeClient();
        await client.ConnectAsync(TimeSpan.FromSeconds(3), CancellationToken.None).ConfigureAwait(false);
        MessageEnvelope request;
        switch (args[0])
        {
            case "status":
                request = MessageEnvelope.Create(MessageTypes.GetStatus, new { });
                break;
            case "flows":
                request = MessageEnvelope.Create(MessageTypes.GetActiveFlows, new { });
                break;
            case "reset-rules":
                request = MessageEnvelope.Create(MessageTypes.ResetOwnedRules, new { });
                break;
            case "mode" when args.Length == 2 && Enum.TryParse<ProtectionMode>(args[1], true, out var mode):
                request = MessageEnvelope.Create(MessageTypes.SetProtectionMode, new SetProtectionModeMessage(mode));
                break;
            case "block" or "allow":
                var path = ReadOption(args[1..], "--path") ?? throw new ArgumentException("service block/allow requires --path <executable>.");
                var fullPath = Path.GetFullPath(path);
                var metadata = new ExecutableMetadataProvider().GetMetadata(fullPath) ?? throw new FileNotFoundException("Executable metadata is unavailable.", fullPath);
                var action = args[0] == "block" ? FirewallAction.Block : FirewallAction.Allow;
                var rule = new FirewallRule(Guid.NewGuid(), $"CLI user {action}", action, RuleSource.User, fullPath, metadata.Sha256, null, null, null, true, DateTimeOffset.UtcNow, null);
                request = MessageEnvelope.Create(MessageTypes.CreateRule, new CreateRuleMessage(rule));
                break;
            default:
                throw new ArgumentException("Unknown service command.");
        }

        var response = await client.SendAsync(request, TimeSpan.FromSeconds(10), CancellationToken.None).ConfigureAwait(false);
        if (request.Type == MessageTypes.GetStatus)
        {
            var status = response.ReadPayload<ServiceStatusMessage>();
            Console.WriteLine($"Running={status.IsRunning} Mode={status.Mode} Active={status.ActiveFlowCount} Dropped={status.DroppedEvents} Database={status.DatabasePath}");
        }
        else if (request.Type == MessageTypes.GetActiveFlows)
        {
            foreach (var flow in response.ReadPayload<ActiveFlowsMessage>().Flows)
            {
                Console.WriteLine($"{flow.ProcessName} {flow.Protocol}/{flow.IpVersion} {NetworkValueConverter.FormatEndpoint(flow.LocalEndpoint)} -> {(flow.Destination is null ? "*:*" : $"{flow.Destination.Address}:{flow.Destination.Port}")}");
            }
        }
        else if (response.Type == MessageTypes.Error)
        {
            throw new InvalidOperationException(response.ReadPayload<ErrorMessage>().Message);
        }
        else
        {
            Console.WriteLine(response.ReadPayload<SuccessMessage>().Message);
        }

        return 0;
    }

    private static void Render(
        IReadOnlyList<ObservedConnection> snapshot,
        string? processFilter,
        bool clearScreen)
    {
        if (clearScreen && !Console.IsOutputRedirected)
        {
            Console.Clear();
        }

        var filtered = snapshot
            .Where(item => processFilter is null
                || (item.Process?.Name.Contains(processFilter, StringComparison.OrdinalIgnoreCase) ?? false))
            .OrderBy(item => item.Process?.Name ?? string.Empty, StringComparer.OrdinalIgnoreCase)
            .ThenBy(item => item.Connection.ProcessId)
            .ThenBy(item => item.Connection.LocalEndpoint.Port)
            .ToArray();

        Console.WriteLine($"EgressGuard Stage 0 - {DateTimeOffset.Now:yyyy-MM-dd HH:mm:ss zzz}");
        Console.WriteLine("PID     PROCESS                 PROTOCOL   LOCAL                          REMOTE                         STATE");
        Console.WriteLine(new string('-', 124));
        foreach (var item in filtered)
        {
            var connection = item.Connection;
            var processName = Truncate(item.Process?.Name ?? "<exited/inaccessible>", 23);
            var protocol = $"{connection.Protocol.ToString().ToUpperInvariant()}/{connection.IpVersion}";
            Console.WriteLine(
                $"{connection.ProcessId,-7} {processName,-23} {protocol,-10} " +
                $"{Truncate(NetworkValueConverter.FormatEndpoint(connection.LocalEndpoint), 30),-30} " +
                $"{Truncate(NetworkValueConverter.FormatEndpoint(connection.RemoteEndpoint), 30),-30} " +
                $"{connection.State ?? "-"}");
        }

        Console.WriteLine();
        Console.WriteLine($"Connections: {filtered.Length}. UDP owner tables do not expose a remote peer; UDP remote is shown as *:*.");

        foreach (var process in filtered
                     .Where(item => item.Process is not null)
                     .Select(item => item.Process!)
                     .DistinctBy(item => item.Identity)
                     .OrderBy(item => item.Identity.ProcessId))
        {
            Console.WriteLine();
            Console.WriteLine($"Process {process.Identity.ProcessId}: {process.Name}");
            Console.WriteLine($"  Identity start: {process.Identity.StartTime:O}");
            Console.WriteLine($"  Parent PID:     {process.ParentProcessId?.ToString(CultureInfo.InvariantCulture) ?? "unavailable"}");
            Console.WriteLine($"  Executable:     {process.ExecutablePath ?? "unavailable"}");
            Console.WriteLine($"  SHA-256:        {process.ExecutableMetadata?.Sha256 ?? "unavailable"}");
            Console.WriteLine("  Signature:      not inspected in Stage 0");
        }

        if (clearScreen)
        {
            Console.WriteLine();
            Console.WriteLine("Refreshing automatically. Press Ctrl+C to stop.");
        }
    }

    private static string? ReadOption(string[] args, string option)
    {
        for (var index = 0; index < args.Length - 1; index++)
        {
            if (string.Equals(args[index], option, StringComparison.OrdinalIgnoreCase))
            {
                return args[index + 1];
            }
        }

        return null;
    }

    private static int ParsePositiveInt(string value, string option)
    {
        if (!int.TryParse(value, out var result) || result <= 0)
        {
            throw new ArgumentException($"{option} must be a positive integer.");
        }

        return result;
    }

    private static string Truncate(string value, int maximumLength) =>
        value.Length <= maximumLength ? value : value[..(maximumLength - 1)] + "…";

    private static void PrintHelp()
    {
        Console.WriteLine("""
            EgressGuard Stage 0 CLI

              watch [--interval-ms 2000] [--process name] [--once]
              firewall status
              firewall block --path <full-path-to-EgressGuard.Simulator.exe>
              firewall unblock
              service status
              service flows
              service mode <Monitor|Learning|Protect>
              service block --path <executable>
              service allow --path <executable>
              service reset-rules

            Firewall block/unblock must run in an Administrator terminal. The CLI never elevates itself.
            """);
    }
}
