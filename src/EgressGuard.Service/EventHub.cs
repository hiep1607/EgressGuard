using System.Collections.Concurrent;
using System.Threading.Channels;
using EgressGuard.Core;
using EgressGuard.Protocol;

namespace EgressGuard.Service;

public sealed class EventHub
{
    private readonly ConcurrentDictionary<Guid, Subscriber> _subscribers = new();
    private long _sequence;

    public long CurrentSequence => Interlocked.Read(ref _sequence);

    public EventSubscription Subscribe(long lastSequence)
    {
        var subscriber = new Subscriber();
        var id = Guid.NewGuid();
        _subscribers[id] = subscriber;
        var current = CurrentSequence;
        if (lastSequence != 0 && lastSequence != current)
        {
            subscriber.Channel.Writer.TryWrite(new StreamEventMessage(current, StreamEventKind.ResyncRequired, null, null, null, null, true));
        }

        return new EventSubscription(id, subscriber.Channel.Reader, current, this);
    }

    public void PublishFlow(StreamEventKind kind, NetworkFlow? flow, string flowId)
    {
        if (kind is not (StreamEventKind.FlowAdded or StreamEventKind.FlowUpdated or StreamEventKind.FlowRemoved))
        {
            throw new ArgumentOutOfRangeException(nameof(kind));
        }

        Publish(new StreamEventMessage(NextSequence(), kind, flow, flowId, null, null, false));
    }

    public void PublishAlert(SecurityAlert alert) =>
        Publish(new StreamEventMessage(NextSequence(), StreamEventKind.AlertRaised, null, alert.FlowId, alert, null, false));

    public void PublishStatus(ServiceStatusMessage status) =>
        Publish(new StreamEventMessage(NextSequence(), StreamEventKind.ServiceStatusChanged, null, null, null, status, false));

    private long NextSequence() => Interlocked.Increment(ref _sequence);

    private void Publish(StreamEventMessage message)
    {
        foreach (var subscriber in _subscribers.Values)
        {
            if (Volatile.Read(ref subscriber.NeedsResync) != 0)
            {
                continue;
            }

            if (!subscriber.Channel.Writer.TryWrite(message))
            {
                Interlocked.Exchange(ref subscriber.NeedsResync, 1);
                while (subscriber.Channel.Reader.TryRead(out _))
                {
                }

                subscriber.Channel.Writer.TryWrite(message with
                {
                    Kind = StreamEventKind.ResyncRequired,
                    Flow = null,
                    FlowId = null,
                    Alert = null,
                    Status = null,
                    RequiresResync = true
                });
            }
        }
    }

    private void Unsubscribe(Guid id) => _subscribers.TryRemove(id, out _);

    private sealed class Subscriber
    {
        internal Channel<StreamEventMessage> Channel { get; } = System.Threading.Channels.Channel.CreateBounded<StreamEventMessage>(
            new BoundedChannelOptions(512)
            {
                FullMode = BoundedChannelFullMode.Wait,
                SingleReader = true,
                SingleWriter = false
            });
        internal int NeedsResync;
    }

    public sealed class EventSubscription : IAsyncDisposable
    {
        private readonly Guid _id;
        private readonly EventHub _owner;

        internal EventSubscription(Guid id, ChannelReader<StreamEventMessage> reader, long sequence, EventHub owner)
        {
            _id = id;
            Reader = reader;
            SequenceAtSubscribe = sequence;
            _owner = owner;
        }

        public ChannelReader<StreamEventMessage> Reader { get; }
        public long SequenceAtSubscribe { get; }

        public ValueTask DisposeAsync()
        {
            _owner.Unsubscribe(_id);
            return ValueTask.CompletedTask;
        }
    }
}
