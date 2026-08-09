using System.Collections.Concurrent;

namespace EgressGuard.Core;

public sealed record BaselineAssessment(bool HasSufficientSamples, bool IsKnownDestination, int SampleCount, string Message);

public sealed class BaselineTracker
{
    public const int CurrentVersion = 1;
    private readonly int _minimumSamples;
    private readonly ConcurrentDictionary<string, BaselineState> _states = new(StringComparer.OrdinalIgnoreCase);

    public BaselineTracker(int minimumSamples = 5)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(minimumSamples, 1);
        _minimumSamples = minimumSamples;
    }

    public void Observe(NetworkFlow flow, bool wasBlocked, bool clearlyDangerous)
    {
        if (wasBlocked || clearlyDangerous || flow.Executable is null || flow.Destination is null)
        {
            return;
        }

        var state = _states.GetOrAdd(flow.Executable.Sha256, _ => new BaselineState());
        lock (state)
        {
            state.SampleCount++;
            state.Destinations.Add(DestinationKey(flow));
            state.ProtocolPorts.Add($"{flow.Protocol}:{flow.Destination.Port}");
            state.LastObserved = flow.LastSeen;
        }
    }

    public BaselineAssessment Assess(NetworkFlow flow)
    {
        if (flow.Executable is null || flow.Destination is null || !_states.TryGetValue(flow.Executable.Sha256, out var state))
        {
            return new BaselineAssessment(false, false, 0, "insufficient baseline");
        }

        lock (state)
        {
            var sufficient = state.SampleCount >= _minimumSamples;
            var known = state.Destinations.Contains(DestinationKey(flow));
            return new BaselineAssessment(
                sufficient,
                known,
                state.SampleCount,
                sufficient ? (known ? "destination is in baseline" : "destination differs from baseline") : "insufficient baseline");
        }
    }

    public bool Reset(string executableSha256) => _states.TryRemove(executableSha256, out _);

    public void Seed(
        string executableSha256,
        string destinationKey,
        string protocolPort,
        int sampleCount,
        DateTimeOffset lastObserved)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(executableSha256);
        ArgumentException.ThrowIfNullOrWhiteSpace(destinationKey);
        ArgumentOutOfRangeException.ThrowIfNegative(sampleCount);
        var state = _states.GetOrAdd(executableSha256, _ => new BaselineState());
        lock (state)
        {
            state.SampleCount += sampleCount;
            state.Destinations.Add(destinationKey);
            state.ProtocolPorts.Add(protocolPort);
            if (lastObserved > state.LastObserved)
            {
                state.LastObserved = lastObserved;
            }
        }
    }

    private static string DestinationKey(NetworkFlow flow) =>
        $"{flow.Destination!.Address}:{flow.Destination.Port}/{flow.Protocol}";

    private sealed class BaselineState
    {
        internal int SampleCount { get; set; }
        internal HashSet<string> Destinations { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal HashSet<string> ProtocolPorts { get; } = new(StringComparer.OrdinalIgnoreCase);
        internal DateTimeOffset LastObserved { get; set; }
    }
}
