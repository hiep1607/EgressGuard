namespace EgressGuard.Protocol;

public sealed record EventBatchResult(
    IReadOnlyList<StreamEventMessage> Events,
    long LastSequence,
    bool RequiresResync,
    bool Overflowed);

public sealed class SequencedEventBuffer
{
    private readonly object _sync = new();
    private readonly Queue<StreamEventMessage> _events = new();
    private readonly int _capacity;
    private bool _overflowed;

    public SequencedEventBuffer(int capacity = 2048)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _capacity = capacity;
    }

    public bool Enqueue(StreamEventMessage streamEvent)
    {
        ArgumentNullException.ThrowIfNull(streamEvent);
        lock (_sync)
        {
            if (_events.Count >= _capacity)
            {
                _events.Clear();
                _overflowed = true;
                return false;
            }

            if (!_overflowed)
            {
                _events.Enqueue(streamEvent);
            }

            return true;
        }
    }

    public EventBatchResult Drain(long lastSequence, int maximumEvents = 500)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(maximumEvents, 1);
        lock (_sync)
        {
            if (_overflowed)
            {
                _overflowed = false;
                _events.Clear();
                return new EventBatchResult([], lastSequence, true, true);
            }

            var result = new List<StreamEventMessage>(Math.Min(maximumEvents, _events.Count));
            var sequence = lastSequence;
            var resync = false;
            while (result.Count < maximumEvents && _events.TryDequeue(out var streamEvent))
            {
                if (streamEvent.RequiresResync
                    || (sequence != 0 && streamEvent.Sequence != sequence + 1)
                    || streamEvent.Sequence <= sequence)
                {
                    resync = true;
                    _events.Clear();
                    break;
                }

                result.Add(streamEvent);
                sequence = streamEvent.Sequence;
            }

            return new EventBatchResult(result, sequence, resync, false);
        }
    }

    public void Reset()
    {
        lock (_sync)
        {
            _events.Clear();
            _overflowed = false;
        }
    }
}
