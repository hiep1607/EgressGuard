using System.Collections.Concurrent;
using EgressGuard.Core;

namespace EgressGuard.Service;

public sealed class ServiceState
{
    private readonly ConcurrentDictionary<string, NetworkFlow> _flows = new(StringComparer.Ordinal);
    private long _droppedEvents;
    private int _mode = (int)ProtectionMode.Learning;

    public ProtectionMode Mode
    {
        get => (ProtectionMode)Volatile.Read(ref _mode);
        set => Volatile.Write(ref _mode, (int)value);
    }

    public long DroppedEvents => Interlocked.Read(ref _droppedEvents);
    public int ActiveFlowCount => _flows.Count;

    public IReadOnlyList<NetworkFlow> Snapshot() => _flows.Values.OrderByDescending(flow => flow.LastSeen).ToArray();

    public void ReplaceSnapshot(IEnumerable<NetworkFlow> flows)
    {
        ArgumentNullException.ThrowIfNull(flows);
        var current = new Dictionary<string, NetworkFlow>(StringComparer.Ordinal);
        foreach (var flow in flows)
        {
            // Windows can report duplicate UDP owner rows for an identical bound endpoint.
            // The newest observation represents the same logical flow identity.
            current[flow.Id] = flow;
        }
        foreach (var item in current)
        {
            _flows[item.Key] = item.Value;
        }

        foreach (var stale in _flows.Keys.Except(current.Keys, StringComparer.Ordinal).ToArray())
        {
            _flows.TryRemove(stale, out _);
        }
    }

    public void RecordDroppedEvent() => Interlocked.Increment(ref _droppedEvents);
}
