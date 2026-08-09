using System.Net;
using System.Net.Sockets;

namespace EgressGuard.TestServer;

internal static class Program
{
    public static async Task<int> Main(string[] args)
    {
        try
        {
            var options = ServerOptions.Parse(args);
            using var cancellation = new CancellationTokenSource();
            if (options.DurationSeconds > 0)
            {
                cancellation.CancelAfter(TimeSpan.FromSeconds(options.DurationSeconds));
            }
            Console.CancelKeyPress += (_, eventArgs) =>
            {
                eventArgs.Cancel = true;
                cancellation.Cancel();
            };

            Console.WriteLine("EgressGuard local test server. It records byte counts only, never payload content.");
            Console.WriteLine($"Binding only to 127.0.0.1:{options.Port} ({options.Protocol}). Press Ctrl+C to stop.");

            var tasks = new List<Task>();
            if (options.Protocol is ServerProtocol.Tcp or ServerProtocol.Both)
            {
                tasks.Add(RunTcpAsync(options.Port, cancellation.Token));
            }

            if (options.Protocol is ServerProtocol.Udp or ServerProtocol.Both)
            {
                tasks.Add(RunUdpAsync(options.Port, cancellation.Token));
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
            Console.WriteLine("Test server stopped cleanly.");
            return 0;
        }
        catch (ArgumentException exception)
        {
            Console.Error.WriteLine($"Error: {exception.Message}");
            return 1;
        }
        catch (SocketException exception)
        {
            Console.Error.WriteLine($"Socket error: {exception.Message}");
            return 2;
        }
    }

    private static async Task RunTcpAsync(int port, CancellationToken cancellationToken)
    {
        var listener = new TcpListener(IPAddress.Loopback, port);
        listener.Start();
        try
        {
            while (!cancellationToken.IsCancellationRequested)
            {
                TcpClient client;
                try
                {
                    client = await listener.AcceptTcpClientAsync(cancellationToken).ConfigureAwait(false);
                }
                catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
                {
                    break;
                }

                _ = CountTcpBytesAsync(client, cancellationToken);
            }
        }
        finally
        {
            listener.Stop();
        }
    }

    private static async Task CountTcpBytesAsync(TcpClient client, CancellationToken cancellationToken)
    {
        using (client)
        {
            var remote = client.Client.RemoteEndPoint;
            long total = 0;
            var buffer = new byte[16 * 1024];
            try
            {
                await using var stream = client.GetStream();
                while (true)
                {
                    var count = await stream.ReadAsync(buffer, cancellationToken).ConfigureAwait(false);
                    if (count == 0)
                    {
                        break;
                    }

                    total += count;
                    Console.WriteLine($"TCP {remote}: received {total:N0} test bytes.");
                }
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
            }
            catch (IOException exception)
            {
                Console.Error.WriteLine($"TCP {remote}: {exception.Message}");
            }
            finally
            {
                Console.WriteLine($"TCP {remote}: closed after {total:N0} test bytes.");
            }
        }
    }

    private static async Task RunUdpAsync(int port, CancellationToken cancellationToken)
    {
        using var udp = new UdpClient(new IPEndPoint(IPAddress.Loopback, port));
        long total = 0;
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                var datagram = await udp.ReceiveAsync(cancellationToken).ConfigureAwait(false);
                total += datagram.Buffer.Length;
                Console.WriteLine($"UDP {datagram.RemoteEndPoint}: received {datagram.Buffer.Length:N0} test bytes ({total:N0} total).");
            }
            catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    private enum ServerProtocol
    {
        Tcp,
        Udp,
        Both
    }

    private sealed record ServerOptions(int Port, ServerProtocol Protocol, int DurationSeconds)
    {
        internal static ServerOptions Parse(string[] args)
        {
            var port = 5050;
            var protocol = ServerProtocol.Both;
            var durationSeconds = 0;
            for (var index = 0; index < args.Length; index++)
            {
                switch (args[index])
                {
                    case "--port" when index + 1 < args.Length:
                        if (!int.TryParse(args[++index], out port) || port is < 1 or > 65535)
                        {
                            throw new ArgumentException("--port must be between 1 and 65535.");
                        }

                        break;
                    case "--protocol" when index + 1 < args.Length:
                        if (!Enum.TryParse(args[++index], ignoreCase: true, out protocol))
                        {
                            throw new ArgumentException("--protocol must be tcp, udp, or both.");
                        }

                        break;
                    case "--duration-seconds" when index + 1 < args.Length:
                        if (!int.TryParse(args[++index], out durationSeconds) || durationSeconds is < 0 or > 3600)
                        {
                            throw new ArgumentException("--duration-seconds must be between 0 and 3600.");
                        }

                        break;
                    default:
                        throw new ArgumentException($"Unknown or incomplete argument: {args[index]}");
                }
            }

            return new ServerOptions(port, protocol, durationSeconds);
        }
    }
}
