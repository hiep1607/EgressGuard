using System.Collections.Concurrent;
using EgressGuard.Core;
using EgressGuard.Protocol;

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

    public IReadOnlyList<FlowStateChange> ReplaceSnapshot(IEnumerable<NetworkFlow> flows)
    {
        ArgumentNullException.ThrowIfNull(flows);
        var current = new Dictionary<string, NetworkFlow>(StringComparer.Ordinal);
        foreach (var flow in flows)
        {
            // Windows can report duplicate UDP owner rows for an identical bound endpoint.
            // The newest observation represents the same logical flow identity.
            current[flow.Id] = flow;
        }
        var changes = new List<FlowStateChange>();
        foreach (var item in current)
        {
            if (!_flows.TryGetValue(item.Key, out var previous))
            {
                changes.Add(new FlowStateChange(StreamEventKind.FlowAdded, item.Value, item.Key));
            }
            else if (HasMeaningfulUpdate(previous, item.Value))
            {
                changes.Add(new FlowStateChange(StreamEventKind.FlowUpdated, item.Value, item.Key));
            }

            _flows[item.Key] = item.Value;
        }

        foreach (var stale in _flows.Keys.Except(current.Keys, StringComparer.Ordinal).ToArray())
        {
            _flows.TryRemove(stale, out _);
            changes.Add(new FlowStateChange(StreamEventKind.FlowRemoved, null, stale));
        }

        return changes;
    }

    public void RecordDroppedEvent() => Interlocked.Increment(ref _droppedEvents);

    private static bool HasMeaningfulUpdate(NetworkFlow previous, NetworkFlow current) =>
        current.LastSeen - previous.LastSeen >= TimeSpan.FromSeconds(2)
        || !string.Equals(previous.State, current.State, StringComparison.Ordinal)
        || previous.IsBlocked != current.IsBlocked
        || previous.Risk?.Score != current.Risk?.Score;
}

public sealed record FlowStateChange(StreamEventKind Kind, NetworkFlow? Flow, string FlowId);
