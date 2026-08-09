using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;

namespace EgressGuard.Simulator;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = SimulatorOptions.Parse(args);
            using var cancellation = new CancellationTokenSource();
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            Console.WriteLine("EgressGuard Simulator: TEST TRAFFIC ONLY.");
            Console.WriteLine("Payload bytes are generated in memory. No user files or credentials are read.");
            Console.WriteLine($"Target: {options.Address}:{options.Port} via {options.Protocol}; mode={options.Mode}; connect-only={options.ConnectOnly}.");

            if (options.Protocol == SimulatorProtocol.Tcp)
            {
                for (var connection = 1; connection <= options.Connections; connection++)
                {
                    Console.WriteLine($"Synthetic connection {connection}/{options.Connections}.");
                    await RunTcpAsync(options, cancellation.Token).ConfigureAwait(false);
                    if (connection < options.Connections)
                    {
                        await Task.Delay(options.ConnectionIntervalMilliseconds, cancellation.Token).ConfigureAwait(false);
                    }
                }
            }
            else
            {
                await RunUdpAsync(options, cancellation.Token).ConfigureAwait(false);
            }

            return 0;
        }
        catch (OperationCanceledException)
        {
            Console.WriteLine("Simulator stopped cleanly.");
            return 0;
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 1;
        }
        catch (SocketException exception)
        {
            Console.Error.WriteLine($"Connection failed as expected when a firewall block is active: {exception.Message}");
            return 2;
        }
        catch (IOException exception)
        {
            Console.Error.WriteLine($"Network I/O failed: {exception.Message}");
            return 2;
        }
    }

    private static async Task RunTcpAsync(SimulatorOptions options, CancellationToken cancellationToken)
    {
        using var client = new TcpClient(options.Address.AddressFamily);
        await client.ConnectAsync(options.Address, options.Port, cancellationToken).ConfigureAwait(false);
        Console.WriteLine($"Connected from {client.Client.LocalEndPoint} to {client.Client.RemoteEndPoint}.");
        if (options.ConnectOnly)
        {
            await HoldForObservationAsync(options.HoldSeconds, cancellationToken).ConfigureAwait(false);
            return;
        }

        await using var stream = client.GetStream();
        await SendTestBytesAsync(
            options,
            (buffer, token) => stream.WriteAsync(buffer, token).AsTask(),
            cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
        await HoldForObservationAsync(options.HoldSeconds, cancellationToken).ConfigureAwait(false);
    }

    private static async Task RunUdpAsync(SimulatorOptions options, CancellationToken cancellationToken)
    {
        using var client = new UdpClient(AddressFamily.InterNetwork);
        client.Connect(options.Address, options.Port);
        Console.WriteLine($"UDP local endpoint will be assigned on first send; target is {options.Address}:{options.Port}.");
        await SendTestBytesAsync(
            options,
            async (buffer, token) =>
            {
                _ = await client.SendAsync(buffer, token).ConfigureAwait(false);
            },
            cancellationToken).ConfigureAwait(false);
        Console.WriteLine($"UDP local endpoint: {client.Client.LocalEndPoint}.");
        await HoldForObservationAsync(options.HoldSeconds, cancellationToken).ConfigureAwait(false);
    }

    private static async Task SendTestBytesAsync(
        SimulatorOptions options,
        Func<ReadOnlyMemory<byte>, CancellationToken, Task> send,
        CancellationToken cancellationToken)
    {
        var remaining = options.TotalBytes;
        var chunkSize = options.Mode == SendMode.Small ? Math.Min(1024, remaining) : Math.Min(64 * 1024, remaining);
        long sent = 0;
        while (remaining > 0)
        {
            var currentSize = Math.Min(chunkSize, remaining);
            var payload = new byte[currentSize];
            RandomNumberGenerator.Fill(payload);
            await send(payload, cancellationToken).ConfigureAwait(false);
            sent += currentSize;
            remaining -= currentSize;
            Console.WriteLine($"Sent {sent:N0}/{options.TotalBytes:N0} generated test bytes.");

            if (options.Mode == SendMode.Small && remaining > 0)
            {
                await Task.Delay(options.DelayMilliseconds, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private static async Task HoldForObservationAsync(int seconds, CancellationToken cancellationToken)
    {
        if (seconds <= 0)
        {
            return;
        }

        Console.WriteLine($"Keeping the socket open for {seconds} seconds so the CLI can observe it.");
        await Task.Delay(TimeSpan.FromSeconds(seconds), cancellationToken).ConfigureAwait(false);
    }

    private enum SimulatorProtocol
    {
        Tcp,
        Udp
    }

    private enum SendMode
    {
        Small,
        Burst
    }

    private sealed record SimulatorOptions(
        IPAddress Address,
        int Port,
        SimulatorProtocol Protocol,
        SendMode Mode,
        int TotalBytes,
        int DelayMilliseconds,
        int HoldSeconds,
        int Connections,
        int ConnectionIntervalMilliseconds,
        bool ConnectOnly)
    {
        internal static SimulatorOptions Parse(string[] args)
        {
            var port = 5050;
            var address = IPAddress.Loopback;
            var protocol = SimulatorProtocol.Tcp;
            var mode = SendMode.Small;
            var totalBytes = 5 * 1024;
            var delayMilliseconds = 500;
            var holdSeconds = 15;
            var connections = 1;
            var connectionIntervalMilliseconds = 1000;
            var connectOnly = false;

            for (var index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--host" when index + 1 < args.Length:
                        if (!IPAddress.TryParse(args[++index], out address))
                        {
                            throw new ArgumentException("--host must be an explicit IPv4 or IPv6 address.");
                        }

                        break;
                    case "--port" when index + 1 < args.Length:
                        port = ParseRange(args[++index], "--port", 1, 65535);
                        break;
                    case "--protocol" when index + 1 < args.Length:
                        if (!Enum.TryParse(args[++index], ignoreCase: true, out protocol))
                        {
                            throw new ArgumentException("--protocol must be tcp or udp.");
                        }

                        break;
                    case "--mode" when index + 1 < args.Length:
                        if (!Enum.TryParse(args[++index], ignoreCase: true, out mode))
                        {
                            throw new ArgumentException("--mode must be small or burst.");
                        }

                        break;
                    case "--bytes" when index + 1 < args.Length:
                        totalBytes = ParseRange(args[++index], "--bytes", 1, 100 * 1024 * 1024);
                        break;
                    case "--delay-ms" when index + 1 < args.Length:
                        delayMilliseconds = ParseRange(args[++index], "--delay-ms", 0, 60_000);
                        break;
                    case "--hold-seconds" when index + 1 < args.Length:
                        holdSeconds = ParseRange(args[++index], "--hold-seconds", 0, 3600);
                        break;
                    case "--connections" when index + 1 < args.Length:
                        connections = ParseRange(args[++index], "--connections", 1, 1000);
                        break;
                    case "--connection-interval-ms" when index + 1 < args.Length:
                        connectionIntervalMilliseconds = ParseRange(args[++index], "--connection-interval-ms", 10, 60_000);
                        break;
                    case "--connect-only":
                        connectOnly = true;
                        break;
                    default:
                        throw new ArgumentException($"Unknown or incomplete argument: {args[index]}");
                }
            }

            if (connectOnly && protocol != SimulatorProtocol.Tcp)
            {
                throw new ArgumentException("--connect-only is supported only for TCP.");
            }

            return new SimulatorOptions(address, port, protocol, mode, totalBytes, delayMilliseconds, holdSeconds, connections, connectionIntervalMilliseconds, connectOnly);
        }

        private static int ParseRange(string value, string option, int minimum, int maximum)
        {
            if (!int.TryParse(value, out var result) || result < minimum || result > maximum)
            {
                throw new ArgumentException($"{option} must be between {minimum} and {maximum}.");
            }

            return result;
        }
    }
}
