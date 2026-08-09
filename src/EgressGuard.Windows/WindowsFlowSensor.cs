using System.Collections.Concurrent;
using EgressGuard.Core;

namespace EgressGuard.Windows;

public interface INetworkFlowSensor
{
    IReadOnlyList<NetworkFlow> Capture();
}

public sealed class WindowsFlowSensor : INetworkFlowSensor
{
    private readonly ConnectionSnapshotService _snapshotService;
    private readonly ConcurrentDictionary<string, DateTimeOffset> _firstSeen = new(StringComparer.Ordinal);

    public WindowsFlowSensor(ConnectionSnapshotService? snapshotService = null)
    {
        _snapshotService = snapshotService ?? new ConnectionSnapshotService();
    }

    public IReadOnlyList<NetworkFlow> Capture()
    {
        return _snapshotService.Capture().Select(Map).ToArray();
    }

    private NetworkFlow Map(ObservedConnection observed)
    {
        var connection = observed.Connection;
        var process = observed.Process;
        var identity = process?.Identity;
        var destination = connection.RemoteEndpoint is null
            ? null
            : new DestinationInfo(
                connection.RemoteEndpoint.Address,
                connection.RemoteEndpoint.Port,
                Domain: null,
                DomainEvidence: "No process-correlated DNS evidence is available.");
        var executable = CreateExecutableInfo(process);
        var id = CreateFlowId(connection, identity);
        var firstSeen = _firstSeen.GetOrAdd(id, connection.DetectedAt);

        return new NetworkFlow(
            id,
            identity,
            process?.Name ?? "<exited/inaccessible>",
            executable,
            process?.ParentProcessId,
            connection.Protocol,
            connection.IpVersion,
            connection.LocalEndpoint,
            destination,
            firstSeen,
            connection.DetectedAt,
            connection.State,
            BytesSent: null,
            BytesReceived: null,
            IsBlocked: false,
            Risk: null);
    }

    private static ExecutableInfo? CreateExecutableInfo(ProcessSnapshot? process)
    {
        if (process?.ExecutablePath is null || process.ExecutableMetadata is null)
        {
            return null;
        }

        var path = process.ExecutablePath;
        var temp = Path.GetFullPath(Path.GetTempPath()).TrimEnd(Path.DirectorySeparatorChar);
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData).TrimEnd(Path.DirectorySeparatorChar);
        var localAppData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData).TrimEnd(Path.DirectorySeparatorChar);
        return new ExecutableInfo(
            path,
            process.ExecutableMetadata.Sha256,
            process.ExecutableMetadata.HasDigitalSignature,
            process.ExecutableMetadata.Publisher,
            process.ExecutableMetadata.FileSize,
            process.ExecutableMetadata.LastWriteTime,
            IsUnder(path, temp),
            IsUnder(path, appData) || IsUnder(path, localAppData));
    }

    private static bool IsUnder(string path, string directory) =>
        !string.IsNullOrWhiteSpace(directory)
        && (string.Equals(path, directory, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));

    private static string CreateFlowId(NetworkConnection connection, ProcessIdentity? identity) =>
        string.Join(
            '|',
            identity?.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? connection.ProcessId.ToString(System.Globalization.CultureInfo.InvariantCulture),
            identity?.StartTime.UtcTicks.ToString(System.Globalization.CultureInfo.InvariantCulture) ?? "unknown",
            connection.Protocol,
            connection.IpVersion,
            NetworkValueConverter.FormatEndpoint(connection.LocalEndpoint),
            NetworkValueConverter.FormatEndpoint(connection.RemoteEndpoint));
}
