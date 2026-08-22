using System.Threading.Channels;
using EgressGuard.Protocol;

namespace EgressGuard.Service;

internal sealed class SimulatedDecisionEventHub : IDisposable
{
    private const int SubscriberChannelCapacity = 256;
    private readonly object _sync = new();
    private readonly Dictionary<Guid, Subscriber> _subscribers = [];
    private long _rejectedSubscriberCount;
    private bool _disposed;

    internal int SubscriberCount
    {
        get
        {
            lock (_sync)
                return _subscribers.Count;
        }
    }

    internal long RejectedSubscriberCount
    {
        get
        {
            lock (_sync)
                return _rejectedSubscriberCount;
        }
    }

    internal SimulatedDecisionEventSubscription Subscribe()
    {
        lock (_sync)
        {
            ObjectDisposedException.ThrowIf(_disposed, this);
            if (_subscribers.Count >= SimulatedDecisionProtocolLimits.DecisionSubscriberCapacity)
            {
                _rejectedSubscriberCount = checked(_rejectedSubscriberCount + 1);
                throw new SimulatedDecisionRequestException(
                    SimulatedDecisionReasonCodes.SubscriberCapacityExhausted,
                    "The Simulation decision event subscriber capacity is exhausted.");
            }

            var id = Guid.NewGuid();
            var subscriber = new Subscriber();
            _subscribers.Add(id, subscriber);
            return new SimulatedDecisionEventSubscription(id, subscriber.Channel.Reader, this);
        }
    }

    internal void Publish(SimulatedDecisionEventMessage message)
    {
        ArgumentNullException.ThrowIfNull(message);
        lock (_sync)
        {
            if (_disposed)
                return;

            foreach (var subscriber in _subscribers.Values)
            {
                if (subscriber.NeedsResync)
                    continue;
                if (subscriber.Channel.Writer.TryWrite(message))
                    continue;

                subscriber.NeedsResync = true;
                while (subscriber.Channel.Reader.TryRead(out _))
                {
                }
                subscriber.Channel.Writer.TryWrite(Resync(message.Sequence));
            }
        }
    }

    private static SimulatedDecisionEventMessage Resync(long sequence) => new(
        ProtocolConstants.Version,
        sequence,
        SimulatedDecisionEventKind.ResyncRequired,
        null,
        null,
        null,
        null,
        null,
        null,
        null,
        requiresResync: true);

    private void Unsubscribe(Guid id)
    {
        lock (_sync)
        {
            if (_subscribers.Remove(id, out var subscriber))
                subscriber.Channel.Writer.TryComplete();
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
                return;
            _disposed = true;
            foreach (var subscriber in _subscribers.Values)
                subscriber.Channel.Writer.TryComplete();
            _subscribers.Clear();
        }
    }

    private sealed class Subscriber
    {
        internal Channel<SimulatedDecisionEventMessage> Channel { get; } = System.Threading.Channels.Channel.CreateBounded<SimulatedDecisionEventMessage>(
            new BoundedChannelOptions(SubscriberChannelCapacity)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = false,
                SingleWriter = false
            });

        internal bool NeedsResync { get; set; }
    }

    internal sealed class SimulatedDecisionEventSubscription : IAsyncDisposable
    {
        private readonly Guid _id;
        private SimulatedDecisionEventHub? _owner;

        internal SimulatedDecisionEventSubscription(
            Guid id,
            ChannelReader<SimulatedDecisionEventMessage> reader,
            SimulatedDecisionEventHub owner)
        {
            _id = id;
            Reader = reader;
            _owner = owner;
        }

        internal ChannelReader<SimulatedDecisionEventMessage> Reader { get; }

        public ValueTask DisposeAsync()
        {
            Interlocked.Exchange(ref _owner, null)?.Unsubscribe(_id);
            return ValueTask.CompletedTask;
        }
    }
}
