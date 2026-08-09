namespace EgressGuard.Core;

public sealed class ConnectionSnapshotService
{
    private readonly ProcessSnapshotCollector _processCollector;
    public ConnectionSnapshotService(ProcessSnapshotCollector? processCollector = null)
    {
        _processCollector = processCollector ?? new ProcessSnapshotCollector();
    }

    public IReadOnlyList<ObservedConnection> Capture()
    {
        var processes = _processCollector.Capture();
        var connections = NativeNetworkTableReader.Capture();

        return connections
            .Select(connection => new ObservedConnection(
                connection,
                processes.GetValueOrDefault(connection.ProcessId)))
            .ToArray();
    }
}
