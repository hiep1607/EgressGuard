using System.Collections.ObjectModel;
using System.Net;
using System.Text.Json;
using EgressGuard.Core;

namespace EgressGuard.OutboundGateSimulator;

internal enum SimulatedTransportKind
{
    Tcp,
    Udp,
    Quic
}

internal enum SimulatedFlowShape
{
    NewFlow,
    ExistingMultiplexed
}

internal enum SimulatedFlowOutcome
{
    Pending,
    Granted,
    Blocked,
    FailedOpen,
    ReconnectRequired
}

internal enum SimulationEnvelopeKind
{
    FileReadIntent,
    GateArmRequest,
    GateArmAck,
    FileReadDisposition,
    FileReadCompletionAck,
    NetworkGateChallenge,
    Decision,
    TicketRedemption,
    ExpirySweep,
    Fault
}

internal enum SimulationFaultKind
{
    DelayNext,
    DropNext,
    MinifilterCrash,
    MinifilterRestart,
    WfpCrash,
    WfpRestart,
    ServiceRestart,
    StaleGeneration,
    PartialCoverage,
    DegradedCoverage
}

internal sealed record SimulatedReadMetadata
{
    public Guid OperationId { get; }
    public GateSubject Subject { get; }
    public FileVersionIdentity File { get; }
    public long Sequence { get; }
    public long RequestedByteCount { get; }

    public SimulatedReadMetadata(Guid operationId, GateSubject subject, FileVersionIdentity file, long sequence, long requestedByteCount)
    {
        OutboundGateLimits.GuidValue(operationId, nameof(operationId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(file);
        if (sequence <= 0 || requestedByteCount is < 0 or > OutboundGateLimits.MaximumFileSizeBytes)
            throw new ArgumentOutOfRangeException(nameof(sequence));
        OperationId = operationId;
        Subject = subject;
        File = file;
        Sequence = sequence;
        RequestedByteCount = requestedByteCount;
    }
}

internal sealed record SimulatedFlowMetadata
{
    public Guid OperationId { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public DestinationBinding Destination { get; }
    public long FlowGeneration { get; }
    public SimulatedTransportKind Transport { get; }
    public SimulatedFlowShape Shape { get; }
    public long ObservedByteCount { get; }

    public SimulatedFlowMetadata(Guid operationId, Guid intentId, GateSubject subject, DestinationBinding destination, long flowGeneration, SimulatedTransportKind transport, SimulatedFlowShape shape, long observedByteCount)
    {
        OutboundGateLimits.GuidValue(operationId, nameof(operationId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        if (flowGeneration <= 0 || observedByteCount is < 0 or > OutboundGateLimits.MaximumGrantBytes || !Enum.IsDefined(transport) || !Enum.IsDefined(shape))
            throw new ArgumentOutOfRangeException(nameof(flowGeneration));
        OperationId = operationId;
        IntentId = intentId;
        Subject = subject;
        Destination = destination;
        FlowGeneration = flowGeneration;
        Transport = transport;
        Shape = shape;
        ObservedByteCount = observedByteCount;
    }
}

internal sealed record SimulationFault
{
    public SimulationFaultKind Kind { get; }
    public SimulationEnvelopeKind EnvelopeKind { get; }
    public Guid? OperationId { get; }
    public long DelayMilliseconds { get; }

    public SimulationFault(SimulationFaultKind kind, SimulationEnvelopeKind envelopeKind = SimulationEnvelopeKind.Fault, Guid? operationId = null, long delayMilliseconds = 0)
    {
        if (!Enum.IsDefined(kind) || !Enum.IsDefined(envelopeKind) || delayMilliseconds < 0)
            throw new ArgumentOutOfRangeException(nameof(kind));
        if (operationId == Guid.Empty)
            throw new ArgumentException("OperationId cannot be empty when present.", nameof(operationId));
        Kind = kind;
        EnvelopeKind = envelopeKind;
        OperationId = operationId;
        DelayMilliseconds = delayMilliseconds;
    }
}

internal sealed record SimulationEnvelope
{
    public SimulationEnvelopeKind Kind { get; }
    public Guid OperationId { get; }
    public GateArmRequest? ArmRequest { get; }
    public GateArmAck? ArmAck { get; }
    public FileReadDisposition? ReadDisposition { get; }
    public FileReadCompletionAck? CompletionAck { get; }
    public NetworkGateChallenge? Challenge { get; }
    public int RemainingDispatches { get; }

    private SimulationEnvelope(
        SimulationEnvelopeKind kind,
        Guid operationId,
        GateArmRequest? armRequest = null,
        GateArmAck? armAck = null,
        FileReadDisposition? readDisposition = null,
        FileReadCompletionAck? completionAck = null,
        NetworkGateChallenge? challenge = null,
        int remainingDispatches = 0)
    {
        OutboundGateLimits.GuidValue(operationId, nameof(operationId));
        ArgumentOutOfRangeException.ThrowIfNegative(remainingDispatches);
        Kind = kind;
        OperationId = operationId;
        ArmRequest = armRequest;
        ArmAck = armAck;
        ReadDisposition = readDisposition;
        CompletionAck = completionAck;
        Challenge = challenge;
        RemainingDispatches = remainingDispatches;
    }

    public static SimulationEnvelope ForArmRequest(Guid operationId, GateArmRequest request) =>
        new(SimulationEnvelopeKind.GateArmRequest, operationId, armRequest: request ?? throw new ArgumentNullException(nameof(request)));

    public static SimulationEnvelope ForArmAck(Guid operationId, GateArmAck ack) =>
        new(SimulationEnvelopeKind.GateArmAck, operationId, armAck: ack ?? throw new ArgumentNullException(nameof(ack)));

    public static SimulationEnvelope ForDisposition(Guid operationId, FileReadDisposition disposition) =>
        new(SimulationEnvelopeKind.FileReadDisposition, operationId, readDisposition: disposition ?? throw new ArgumentNullException(nameof(disposition)));

    public static SimulationEnvelope ForCompletion(Guid operationId, FileReadCompletionAck completion) =>
        new(SimulationEnvelopeKind.FileReadCompletionAck, operationId, completionAck: completion ?? throw new ArgumentNullException(nameof(completion)));

    public static SimulationEnvelope ForChallenge(Guid operationId, NetworkGateChallenge challenge) =>
        new(SimulationEnvelopeKind.NetworkGateChallenge, operationId, challenge: challenge ?? throw new ArgumentNullException(nameof(challenge)));

    public static SimulationEnvelope ForPumpChain(Guid operationId, int remainingDispatches) =>
        new(SimulationEnvelopeKind.Fault, operationId, remainingDispatches: remainingDispatches);
}

internal sealed record SimulationStepResult(
    SimulatedFlowOutcome Outcome,
    string ReasonCode,
    GateTransitionResult? CoreResult = null,
    GateArmAck? Ack = null,
    FileReadCompletionAck? Completion = null,
    OneTimeTicket? Ticket = null,
    EphemeralFlowGrant? Grant = null,
    CriticalAlert? Alert = null,
    bool IsDuplicate = false);

internal sealed record MinifilterSnapshot(
    int PendingCount,
    int PendingCapacity,
    int PendingSubjectMaximum,
    int IntentOutboxCount,
    int IntentOutboxCapacity,
    int DispositionInboxCount,
    int DispositionInboxCapacity,
    int CompletionAckOutboxCount,
    int CompletionAckOutboxCapacity,
    bool Available,
    Guid Generation);

internal sealed record WfpSnapshot(
    int HeldFlowCount,
    int HeldFlowCapacity,
    long HeldByteCount,
    long HeldByteCapacity,
    int InstalledGrantCount,
    int InstalledGrantCapacity,
    int GateArmInboxCount,
    int GateArmInboxCapacity,
    int GateAckOutboxCount,
    int GateAckOutboxCapacity,
    int FlowObservationInboxCount,
    int FlowObservationInboxCapacity,
    int ChallengeOutboxCount,
    int ChallengeOutboxCapacity,
    bool Available,
    Guid Generation);

internal sealed record SimulationSnapshot(
    OutboundGateMode Mode,
    ServiceMonotonicTimestamp Now,
    int PendingReadCount,
    int PendingReadCapacity,
    int ActiveChallengeCount,
    int ActiveChallengeCapacity,
    int HeldFlowCount,
    int HeldFlowCapacity,
    long HeldByteCount,
    long HeldByteCapacity,
    int ScheduledCount,
    int ScheduledCapacity,
    int OwnedOperationCount,
    long AcceptedReadCount,
    long ReleasedReadCount,
    long AcceptedFlowCount,
    long ChallengeCreatedCount,
    long ChallengeDeliveredCount,
    long ReleasedFlowCount,
    long FailedOpenOperationCount,
    long OverflowCount,
    long DroppedEnvelopeCount,
    long CriticalAlertCount,
    long MinifilterCrashCount,
    long MinifilterRestartCount,
    long WfpCrashCount,
    long WfpRestartCount,
    long ServiceRestartCount,
    long DiagnosticAlertEvictionCount,
    long TransitionTraceEvictionCount,
    int OutstandingTicketCount,
    int OutstandingTicketCapacity,
    int ReplayTombstoneCount,
    int ReplayTombstoneCapacity,
    int ActiveGrantReservationCount,
    int ActiveGrantReservationCapacity,
    int InstalledGrantCount,
    int InstalledGrantCapacity,
    bool MinifilterAvailable,
    bool WfpAvailable,
    Guid BootInstance,
    Guid WfpGeneration,
    Guid MinifilterGeneration,
    string LastReasonCode,
    int HostOwnershipCount,
    int HostOwnershipCapacity,
    int FaultPlanCount,
    int FaultPlanCapacity,
    int AlertRingCount,
    int AlertRingCapacity,
    int TraceRingCount,
    int TraceRingCapacity,
    int AcceptanceResultCount,
    int AcceptanceResultCapacity,
    int MinifilterIntentOutboxCount,
    int MinifilterIntentOutboxCapacity,
    int MinifilterDispositionInboxCount,
    int MinifilterDispositionInboxCapacity,
    int MinifilterCompletionAckOutboxCount,
    int MinifilterCompletionAckOutboxCapacity,
    int WfpGateArmInboxCount,
    int WfpGateArmInboxCapacity,
    int WfpGateAckOutboxCount,
    int WfpGateAckOutboxCapacity,
    int WfpFlowObservationInboxCount,
    int WfpFlowObservationInboxCapacity,
    int WfpChallengeOutboxCount,
    int WfpChallengeOutboxCapacity,
    int SchedulerOwnerCount,
    int SchedulerOwnerCapacity,
    int CoreActiveContextCount,
    int CoreActiveContextCapacity,
    int CoreAlertCount,
    int CoreAlertCapacity,
    int CoreAlertDedupeCount,
    int CoreAlertDedupeCapacity,
    int ConsumedTicketCount,
    int ConsumedTicketCapacity);

internal interface IDeterministicSimulationScheduler
{
    bool TrySchedule(SimulationEnvelope envelope, long delayMilliseconds);
    int PumpReady();
    int AdvanceBy(long milliseconds);
    void CancelOwned(Guid operationId);
    int Count { get; }
    int OwnerCount { get; }
}

internal interface IFakeMinifilterEndpoint
{
    SimulationStepResult TryPendRead(SimulatedReadMetadata read);
    SimulationStepResult AcceptDisposition(FileReadDisposition disposition);
    void Crash();
    void Restart(Guid generation);
    MinifilterSnapshot Snapshot { get; }
}

internal interface IFakeWfpEndpoint
{
    SimulationStepResult AcceptArmRequest(GateArmRequest request);
    SimulationStepResult ObserveFlow(SimulatedFlowMetadata flow);
    SimulationStepResult InstallGrant(EphemeralFlowGrant grant);
    void Crash();
    void Restart(Guid generation);
    WfpSnapshot Snapshot { get; }
}

internal sealed class ManualSimulationClock : IOutboundGateMonotonicClock, IOutboundGateAuditClock
{
    private ServiceMonotonicTimestamp _now;
    private DateTimeOffset _auditEpoch;

    public ManualSimulationClock(Guid clockInstanceId, DateTimeOffset auditEpoch)
    {
        OutboundGateLimits.GuidValue(clockInstanceId, nameof(clockInstanceId));
        _now = new ServiceMonotonicTimestamp(1, clockInstanceId, 0);
        _auditEpoch = auditEpoch.ToUniversalTime();
    }

    public ServiceMonotonicTimestamp Now() => _now;
    public DateTimeOffset NowUtc() => _auditEpoch.AddMilliseconds(_now.ElapsedMilliseconds);

    public void AdvanceBy(long milliseconds)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(milliseconds);
        _now = new ServiceMonotonicTimestamp(1, _now.ClockInstanceId, checked(_now.ElapsedMilliseconds + milliseconds));
    }

    public void Restart(Guid clockInstanceId)
    {
        OutboundGateLimits.GuidValue(clockInstanceId, nameof(clockInstanceId));
        _now = new ServiceMonotonicTimestamp(1, clockInstanceId, 0);
    }
}

internal sealed class DeterministicNonceProvider : IOutboundGateNonceProvider
{
    private long _counter;

    public Guid NextNonce()
    {
        var value = checked(++_counter);
        var low = (uint)(value & uint.MaxValue);
        var high = (uint)((ulong)value >> 32);
        return new Guid((int)low, (short)(high & short.MaxValue), (short)((high >> 16) & short.MaxValue), 0x21, 0x5b, 0x03, 0, 0, 0, 0, 1);
    }
}

internal enum SimulationGenerationDomain : byte
{
    Boot = 0x10,
    Clock = 0x22,
    Wfp = 0x20,
    Minifilter = 0x21
}

internal sealed class DeterministicGenerationSource
{
    private long _bootSequence;
    private long _clockSequence;
    private long _wfpSequence;
    private long _minifilterSequence;

    public Guid Next(SimulationGenerationDomain domain)
    {
        var sequence = domain switch
        {
            SimulationGenerationDomain.Boot => checked(++_bootSequence),
            SimulationGenerationDomain.Clock => checked(++_clockSequence),
            SimulationGenerationDomain.Wfp => checked(++_wfpSequence),
            SimulationGenerationDomain.Minifilter => checked(++_minifilterSequence),
            _ => throw new ArgumentOutOfRangeException(nameof(domain))
        };
        var high = (int)((ulong)sequence >> 32);
        var low = (int)(sequence & uint.MaxValue);
        return new Guid(
            ((int)domain << 24) | (high & 0x00ff_ffff),
            (short)((ulong)sequence >> 48),
            (short)((ulong)sequence >> 32),
            (byte)domain,
            0x5b,
            0x04,
            0,
            (byte)(low >> 24),
            (byte)(low >> 16),
            (byte)(low >> 8),
            (byte)low);
    }
}

internal sealed class DeterministicSimulationScheduler : IDeterministicSimulationScheduler
{
    internal const int Capacity = 512;
    internal const int OwnerCapacity = 256;
    private readonly ManualSimulationClock _clock;
    private readonly PriorityQueue<SimulationEnvelope, (long Due, long Sequence)> _events = new();
    private readonly Dictionary<Guid, int> _ownerCounts = new();
    private long _sequence;

    public DeterministicSimulationScheduler(ManualSimulationClock clock) => _clock = clock;
    public int Count => _events.Count;
    public int OwnerCount => _ownerCounts.Count;

    public bool TrySchedule(SimulationEnvelope envelope, long delayMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (delayMilliseconds < 0 || _events.Count >= Capacity)
            return false;
        var ownedCount = _ownerCounts.GetValueOrDefault(envelope.OperationId);
        if (ownedCount == 0 && _ownerCounts.Count >= OwnerCapacity)
            return false;
        var due = checked(_clock.Now().ElapsedMilliseconds + delayMilliseconds);
        _events.Enqueue(envelope, (due, checked(++_sequence)));
        _ownerCounts[envelope.OperationId] = checked(ownedCount + 1);
        return true;
    }

    public int PumpReady() => PumpReady(int.MaxValue, static _ => { });

    internal int PumpReady(int maximum, Action<SimulationEnvelope> dispatch)
    {
        var pumped = 0;
        while (pumped < maximum && _events.TryPeek(out _, out var priority) && priority.Due <= _clock.Now().ElapsedMilliseconds)
        {
            var envelope = _events.Dequeue();
            RemoveOwnerReference(envelope.OperationId);
            dispatch(envelope);
            pumped++;
        }
        return pumped;
    }

    public int AdvanceBy(long milliseconds)
    {
        _clock.AdvanceBy(milliseconds);
        return PumpReady();
    }

    public void CancelOwned(Guid operationId)
    {
        if (operationId == Guid.Empty)
            return;
        var retained = new List<(SimulationEnvelope Envelope, (long Due, long Sequence) Priority)>();
        while (_events.TryDequeue(out var envelope, out var priority))
            if (envelope.OperationId != operationId)
                retained.Add((envelope, priority));
        foreach (var item in retained)
            _events.Enqueue(item.Envelope, item.Priority);
        _ownerCounts.Remove(operationId);
    }

    internal void Clear()
    {
        _events.Clear();
        _ownerCounts.Clear();
    }

    private void RemoveOwnerReference(Guid operationId)
    {
        if (!_ownerCounts.TryGetValue(operationId, out var count))
            return;
        if (count == 1)
            _ownerCounts.Remove(operationId);
        else
            _ownerCounts[operationId] = count - 1;
    }
}

internal sealed class FakeMinifilterEndpoint : IFakeMinifilterEndpoint
{
    internal const int GlobalCapacity = 64;
    internal const int SubjectCapacity = 4;
    internal const int IntentOutboxCapacity = 64;
    internal const int DispositionInboxCapacity = 64;
    internal const int CompletionAckOutboxCapacity = 64;
    private readonly Dictionary<Guid, PendingRead> _pending = new();
    private readonly Queue<FileReadIntent> _intentOutbox = new();
    private readonly Queue<FileReadDisposition> _dispositionInbox = new();
    private readonly Queue<FileReadCompletionAck> _completionAckOutbox = new();
    private readonly Dictionary<Guid, FileReadDisposition> _releasedDispositions = new();
    private readonly Queue<Guid> _releasedDispositionOrder = new();
    private Guid _generation;
    private bool _available = true;

    public FakeMinifilterEndpoint(Guid generation) => _generation = generation;
    public MinifilterSnapshot Snapshot => new(
        _pending.Count,
        GlobalCapacity,
        SubjectCapacity,
        _intentOutbox.Count,
        IntentOutboxCapacity,
        _dispositionInbox.Count,
        DispositionInboxCapacity,
        _completionAckOutbox.Count,
        CompletionAckOutboxCapacity,
        _available,
        _generation);

    public SimulationStepResult TryPendRead(SimulatedReadMetadata read)
    {
        ArgumentNullException.ThrowIfNull(read);
        if (!_available)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-minifilter-unavailable");
        if (_pending.ContainsKey(read.OperationId))
            return new(SimulatedFlowOutcome.Pending, "sim-read-duplicate", IsDuplicate: true);
        if (_pending.Count >= GlobalCapacity || CountFor(read.Subject) >= SubjectCapacity)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-pending-read-capacity-exhausted");
        _pending.Add(read.OperationId, new PendingRead(read, null));
        return new(SimulatedFlowOutcome.Pending, "sim-read-pended");
    }

    public SimulationStepResult AcceptDisposition(FileReadDisposition disposition)
    {
        ArgumentNullException.ThrowIfNull(disposition);
        if (_dispositionInbox.Count >= DispositionInboxCapacity)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-minifilter-channel-capacity-exhausted");
        _dispositionInbox.Enqueue(disposition);
        var received = _dispositionInbox.Dequeue();
        var pending = _pending.FirstOrDefault(item => item.Value.ExpectedDisposition is not null && DispositionMatches(item.Value.ExpectedDisposition, received));
        if (pending.Value is null)
        {
            if (_releasedDispositions.TryGetValue(received.IntentId, out var released) && DispositionMatches(released, received))
                return new(SimulatedFlowOutcome.Pending, "sim-read-released", IsDuplicate: true);
            return new(SimulatedFlowOutcome.FailedOpen, "sim-read-disposition-mismatch");
        }
        _pending.Remove(pending.Key);
        RememberReleasedDisposition(received);
        return new(SimulatedFlowOutcome.Pending, received.Disposition == FileReadDispositionKind.ReleaseAfterGateArmed ? "sim-read-released" : "sim-read-failed-open");
    }

    internal bool TryGet(Guid operationId, out SimulatedReadMetadata? read)
    {
        if (_pending.TryGetValue(operationId, out var pending))
        {
            read = pending.Read;
            return true;
        }
        read = null;
        return false;
    }

    internal bool BindDisposition(Guid operationId, FileReadDisposition disposition)
    {
        ArgumentNullException.ThrowIfNull(disposition);
        if (!_pending.TryGetValue(operationId, out var pending))
            return false;
        _pending[operationId] = pending with { ExpectedDisposition = disposition };
        return true;
    }

    internal bool TryEnqueueIntent(FileReadIntent intent) => TryEnqueue(_intentOutbox, intent, IntentOutboxCapacity);
    internal bool TryDequeueIntent(out FileReadIntent? intent) => _intentOutbox.TryDequeue(out intent);
    internal bool TryEnqueueDisposition(FileReadDisposition disposition) => TryEnqueue(_dispositionInbox, disposition, DispositionInboxCapacity);
    internal bool TryEnqueueCompletion(FileReadCompletionAck completion) => TryEnqueue(_completionAckOutbox, completion, CompletionAckOutboxCapacity);
    internal bool TryDequeueCompletion(out FileReadCompletionAck? completion) => _completionAckOutbox.TryDequeue(out completion);
    internal IReadOnlyList<Guid> PendingOperationIds => _pending.Keys.ToArray();
    internal bool ReleaseOperation(Guid operationId) => _pending.Remove(operationId);

    internal static FileReadCompletionAck CreateCompletion(FileReadDisposition disposition, Guid generation, IOutboundGateNonceProvider nonces, long sequence)
    {
        var completionResult = disposition.Disposition == FileReadDispositionKind.Cancel ? FileReadCompletionResult.Canceled : FileReadCompletionResult.Released;
        return new FileReadCompletionAck(1, nonces.NextNonce(), disposition.IntentId, disposition.ProcessIdentity, disposition.File, disposition.Sequence, disposition.Disposition, disposition.GateAckId, completionResult, completionResult == FileReadCompletionResult.Released ? "read-released" : "read-failed-open", sequence, generation);
    }

    public void Crash()
    {
        _available = false;
        ReleaseAll();
    }

    public void Restart(Guid generation)
    {
        OutboundGateLimits.GuidValue(generation, nameof(generation));
        _generation = generation;
        _available = true;
        ReleaseAll();
    }

    internal void ReleaseAll()
    {
        _pending.Clear();
        _intentOutbox.Clear();
        _dispositionInbox.Clear();
        _completionAckOutbox.Clear();
        _releasedDispositions.Clear();
        _releasedDispositionOrder.Clear();
    }

    private int CountFor(GateSubject subject) => _pending.Values.Count(item => item.Read.Subject.Matches(subject));

    private void RememberReleasedDisposition(FileReadDisposition disposition)
    {
        if (_releasedDispositions.ContainsKey(disposition.IntentId))
            return;
        _releasedDispositions.Add(disposition.IntentId, disposition);
        _releasedDispositionOrder.Enqueue(disposition.IntentId);
        while (_releasedDispositions.Count > GlobalCapacity)
            _releasedDispositions.Remove(_releasedDispositionOrder.Dequeue());
    }

    private static bool DispositionMatches(FileReadDisposition left, FileReadDisposition right) =>
        left.Version == right.Version
        && left.IntentId == right.IntentId
        && left.ProcessIdentity == right.ProcessIdentity
        && left.File == right.File
        && left.Disposition == right.Disposition
        && left.GateAckId == right.GateAckId
        && left.ReadWindow == right.ReadWindow
        && left.ReasonCode == right.ReasonCode
        && left.Sequence == right.Sequence;

    private static bool TryEnqueue<T>(Queue<T> queue, T item, int capacity)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (queue.Count >= capacity)
            return false;
        queue.Enqueue(item);
        return true;
    }

    private sealed record PendingRead(SimulatedReadMetadata Read, FileReadDisposition? ExpectedDisposition);
}

internal sealed class FakeWfpEndpoint : IFakeWfpEndpoint
{
    internal const int ArmChannelCapacity = 64;
    internal const int FlowChannelCapacity = 128;
    internal const int GateAckOutboxCapacity = 64;
    internal const int ChallengeOutboxCapacity = 128;
    internal const int HeldFlowCapacity = 128;
    internal const int HeldSubjectCapacity = 4;
    internal const long FlowByteCapacity = 256L * 1024;
    internal const long GlobalByteCapacity = 4L * 1024 * 1024;
    internal const int GrantCapacity = OneTimeGateTicketService.MaximumActiveGrantsGlobal;
    private readonly Dictionary<Guid, HeldFlow> _held = new();
    private readonly Dictionary<Guid, InstalledGrant> _grants = new();
    private readonly Queue<GateArmRequest> _gateArmInbox = new();
    private readonly Queue<GateArmAck> _gateAckOutbox = new();
    private readonly Queue<SimulatedFlowMetadata> _flowObservationInbox = new();
    private readonly Queue<NetworkGateChallenge> _challengeOutbox = new();
    private readonly Func<Guid> _currentGeneration;
    private readonly IOutboundGateNonceProvider _nonces;
    private readonly ManualSimulationClock _clock;
    private bool _available = true;

    public FakeWfpEndpoint(Func<Guid> currentGeneration, IOutboundGateNonceProvider nonces, ManualSimulationClock clock)
    {
        _currentGeneration = currentGeneration;
        _nonces = nonces;
        _clock = clock;
    }

    public WfpSnapshot Snapshot => new(
        _held.Count,
        HeldFlowCapacity,
        _held.Values.Sum(item => item.ByteCount),
        GlobalByteCapacity,
        _grants.Count,
        GrantCapacity,
        _gateArmInbox.Count,
        ArmChannelCapacity,
        _gateAckOutbox.Count,
        GateAckOutboxCapacity,
        _flowObservationInbox.Count,
        FlowChannelCapacity,
        _challengeOutbox.Count,
        ChallengeOutboxCapacity,
        _available,
        _currentGeneration());

    public SimulationStepResult AcceptArmRequest(GateArmRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!_available)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-unavailable");
        if (!TryEnqueue(_gateArmInbox, request, ArmChannelCapacity))
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-channel-capacity-exhausted");
        var accepted = _gateArmInbox.Dequeue();
        var ack = CreateAck(accepted, accepted.RequiredCoverage, null, _currentGeneration());
        if (!TryEnqueue(_gateAckOutbox, ack, GateAckOutboxCapacity))
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-channel-capacity-exhausted");
        _gateAckOutbox.Dequeue();
        return new(SimulatedFlowOutcome.Pending, "sim-full-coverage-armed", Ack: ack);
    }

    internal GateArmAck CreateAck(GateArmRequest request, GateCoverage coverage, string? limitationReason, Guid generation)
    {
        return new GateArmAck(1, _nonces.NextNonce(), request.IntentId, request.Subject, request.RequiredCoverage, coverage, request.PolicyEpoch, generation, request.RequestNonce, _nonces.NextNonce(), _clock.NowUtc(), request.ArmWindow, limitationReason);
    }

    public SimulationStepResult ObserveFlow(SimulatedFlowMetadata flow)
    {
        ArgumentNullException.ThrowIfNull(flow);
        if (!_available)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-unavailable");
        if (!TryEnqueue(_flowObservationInbox, flow, FlowChannelCapacity))
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-channel-capacity-exhausted");
        return TryReserveHeld(_flowObservationInbox.Dequeue());
    }

    internal SimulationStepResult TryReserveHeld(SimulatedFlowMetadata flow)
    {
        if (_held.ContainsKey(flow.OperationId))
            return new(SimulatedFlowOutcome.Pending, "sim-held-flow-duplicate", IsDuplicate: true);
        if (_held.Count >= HeldFlowCapacity || CountFor(flow.Subject) >= HeldSubjectCapacity)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-held-flow-capacity-exhausted");
        if (flow.ObservedByteCount is < 1 or > FlowByteCapacity)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-held-data-flow-capacity-exhausted");
        if (_held.Values.Sum(item => item.ByteCount) > GlobalByteCapacity - flow.ObservedByteCount)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-held-data-global-capacity-exhausted");
        _held.Add(flow.OperationId, new HeldFlow(flow, flow.ObservedByteCount));
        return new(SimulatedFlowOutcome.Pending, "sim-held-flow-reserved");
    }

    public SimulationStepResult InstallGrant(EphemeralFlowGrant grant)
    {
        ArgumentNullException.ThrowIfNull(grant);
        if (!_available)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-unavailable");
        if (_grants.Count >= GrantCapacity)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-grant-map-capacity-exhausted");
        if (_grants.ContainsKey(grant.GrantId))
            return new(SimulatedFlowOutcome.FailedOpen, "sim-grant-map-capacity-exhausted");
        _grants.Add(grant.GrantId, new InstalledGrant(grant, 0));
        return new(SimulatedFlowOutcome.Granted, "sim-grant-installed", Grant: grant);
    }

    internal SimulationStepResult ConsumeGrantBytes(Guid grantId, long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        if (!_grants.TryGetValue(grantId, out var grant))
            return new(SimulatedFlowOutcome.FailedOpen, "sim-grant-not-installed");
        if (bytes > grant.Grant.MaximumBytes - grant.UsedBytes)
        {
            _grants.Remove(grantId);
            return new(SimulatedFlowOutcome.FailedOpen, "sim-grant-byte-capacity-exhausted");
        }
        var usedBytes = checked(grant.UsedBytes + bytes);
        if (usedBytes == grant.Grant.MaximumBytes)
            _grants.Remove(grantId);
        else
            _grants[grantId] = grant with { UsedBytes = usedBytes };
        return new(SimulatedFlowOutcome.Granted, "sim-grant-byte-counted", Grant: grant.Grant);
    }

    internal bool TryEnqueueArmRequest(GateArmRequest request) => TryEnqueue(_gateArmInbox, request, ArmChannelCapacity);
    internal bool TryEnqueueArmAck(GateArmAck ack) => TryEnqueue(_gateAckOutbox, ack, GateAckOutboxCapacity);
    internal bool TryEnqueueFlowObservation(SimulatedFlowMetadata flow) => TryEnqueue(_flowObservationInbox, flow, FlowChannelCapacity);
    internal bool TryEnqueueChallenge(NetworkGateChallenge challenge) => TryEnqueue(_challengeOutbox, challenge, ChallengeOutboxCapacity);
    internal bool TryDequeueChallenge(out NetworkGateChallenge? challenge) => _challengeOutbox.TryDequeue(out challenge);

    internal bool RemoveHeld(Guid operationId) => _held.Remove(operationId);
    internal IReadOnlyList<Guid> HeldOperationIds => _held.Keys.ToArray();
    internal void RemoveGrant(Guid grantId) => _grants.Remove(grantId);
    internal bool HasHeld(Guid operationId) => _held.ContainsKey(operationId);
    internal IReadOnlyList<EphemeralFlowGrant> Grants => _grants.Values.Select(item => item.Grant).ToArray();
    internal void ReleaseAll()
    {
        _held.Clear();
        _grants.Clear();
        _gateArmInbox.Clear();
        _gateAckOutbox.Clear();
        _flowObservationInbox.Clear();
        _challengeOutbox.Clear();
    }
    internal int GrantCount => _grants.Count;

    public void Crash()
    {
        _available = false;
        ReleaseAll();
    }

    public void Restart(Guid generation)
    {
        OutboundGateLimits.GuidValue(generation, nameof(generation));
        _available = true;
        ReleaseAll();
    }

    private int CountFor(GateSubject subject) => _held.Values.Count(item => item.Flow.Subject.Matches(subject));
    private static bool TryEnqueue<T>(Queue<T> queue, T item, int capacity)
    {
        ArgumentNullException.ThrowIfNull(item);
        if (queue.Count >= capacity)
            return false;
        queue.Enqueue(item);
        return true;
    }
    private sealed record HeldFlow(SimulatedFlowMetadata Flow, long ByteCount);
    private sealed record InstalledGrant(EphemeralFlowGrant Grant, long UsedBytes);
}

internal sealed class OutboundGateSimulatorHost : IDisposable
{
    internal const int SchedulerCapacity = DeterministicSimulationScheduler.Capacity;
    internal const int SchedulerOwnerCapacity = DeterministicSimulationScheduler.OwnerCapacity;
    internal const int FaultPlanCapacity = 256;
    internal const int PumpDispatchCapacity = 1_024;
    internal const int HostOwnershipCapacity = 256;
    internal const int AlertRingCapacity = 256;
    internal const int TraceRingCapacity = 1_024;
    internal const int AcceptanceResultCapacity = 64;
    internal const int CoreAlertDedupeCapacity = 256;
    internal const int ConsumedTicketCapacity = OneTimeGateTicketService.MaximumReplayTombstonesGlobal;
    private static readonly GateCoverage FullCoverage = new(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);
    private readonly object _transitionSync = new();
    private readonly DeterministicGenerationSource _generations;
    private readonly ManualSimulationClock _clock;
    private readonly DeterministicNonceProvider _nonces;
    private readonly DeterministicSimulationScheduler _scheduler;
    private readonly FakeMinifilterEndpoint _minifilter;
    private readonly FakeWfpEndpoint _wfp;
    private readonly List<SimulationFault> _faults = new();
    private readonly Dictionary<Guid, FileReadIntent> _intents = new();
    private readonly Dictionary<Guid, Guid> _intentOperations = new();
    private readonly Dictionary<Guid, Guid> _challengeOperations = new();
    private readonly Dictionary<Guid, OneTimeTicket> _tickets = new();
    private readonly Dictionary<Guid, OneTimeTicket> _consumedTickets = new();
    private readonly Queue<Guid> _consumedTicketOrder = new();
    private readonly HashSet<Guid> _acceptedReadOperations = new();
    private readonly HashSet<Guid> _acceptedFlowOperations = new();
    private readonly HashSet<Guid> _failedOpenOperations = new();
    private readonly HashSet<Guid> _coreAlertIds = new();
    private readonly Queue<Guid> _coreAlertIdOrder = new();
    private readonly Queue<CriticalAlert> _alerts = new();
    private readonly Queue<string> _trace = new();
    private readonly OutboundGateStateMachine? _machine;
    private readonly OneTimeGateTicketService? _ticketService;
    private readonly bool _simulation;
    private Guid _bootInstance;
    private Guid _wfpGeneration;
    private Guid _minifilterGeneration;
    private long _acceptedReadCount;
    private long _releasedReadCount;
    private long _acceptedFlowCount;
    private long _challengeCreatedCount;
    private long _challengeDeliveredCount;
    private long _releasedFlowCount;
    private long _failedOpenCount;
    private long _overflowCount;
    private long _droppedEnvelopeCount;
    private long _criticalAlertCount;
    private long _minifilterCrashCount;
    private long _minifilterRestartCount;
    private long _wfpCrashCount;
    private long _wfpRestartCount;
    private long _serviceRestartCount;
    private long _diagnosticAlertEvictionCount;
    private long _transitionTraceEvictionCount;
    private string _lastReasonCode = "sim-disabled";
    private SimulationStepResult? _lastStepResult;
    private bool _disposed;

    public OutboundGateSimulatorHost(bool simulation = false)
        : this(simulation, 0, 0)
    {
    }

    private OutboundGateSimulatorHost(bool simulation, int seededOutstandingTickets, int seededActiveGrants)
    {
        if (seededOutstandingTickets is < 0 or > OneTimeGateTicketService.MaximumOutstandingPerSubject)
            throw new ArgumentOutOfRangeException(nameof(seededOutstandingTickets));
        if (seededActiveGrants is < 0 or > OneTimeGateTicketService.MaximumActiveGrantsGlobal)
            throw new ArgumentOutOfRangeException(nameof(seededActiveGrants));
        _simulation = simulation;
        _generations = new DeterministicGenerationSource();
        _bootInstance = _generations.Next(SimulationGenerationDomain.Boot);
        _wfpGeneration = _generations.Next(SimulationGenerationDomain.Wfp);
        _minifilterGeneration = _generations.Next(SimulationGenerationDomain.Minifilter);
        _clock = new ManualSimulationClock(_generations.Next(SimulationGenerationDomain.Clock), new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _nonces = new DeterministicNonceProvider();
        _scheduler = new DeterministicSimulationScheduler(_clock);
        _minifilter = new FakeMinifilterEndpoint(_minifilterGeneration);
        _wfp = new FakeWfpEndpoint(() => _wfpGeneration, _nonces, _clock);
        if (!simulation)
            return;

        _ticketService = new OneTimeGateTicketService(_clock, _clock, _nonces, new DeterministicTestTicketAuthenticator(_bootInstance), 0);
        for (var index = 0; index < seededOutstandingTickets; index++)
        {
            var binding = new TicketAuthorizationBinding(
                1,
                _nonces.NextNonce(),
                SimulationFixture.Subject,
                SimulationFixture.File,
                SimulationFixture.Destination(),
                index + 1,
                _bootInstance,
                0,
                OutboundGateLimits.MaximumGrantBytes,
                (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);
            if (_ticketService.TryIssue(binding).Kind != TicketServiceResultKind.Success)
                throw new InvalidOperationException("Unable to seed deterministic ticket reservations.");
        }
        for (var index = 0; index < seededActiveGrants; index++)
        {
            var process = new ProcessIdentity(100_000 + index, SimulationFixture.Start);
            var subject = new GateSubject(1, process, $"sha256:grant-capacity-{index}", null, [process]);
            var binding = new TicketAuthorizationBinding(
                1,
                _nonces.NextNonce(),
                subject,
                SimulationFixture.File,
                SimulationFixture.Destination(),
                index + 1,
                _bootInstance,
                0,
                OutboundGateLimits.MaximumGrantBytes,
                (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);
            var issued = _ticketService.TryIssue(binding);
            if (issued.Kind != TicketServiceResultKind.Success || issued.Ticket is null
                || _ticketService.TryRedeem(issued.Ticket, binding).Kind != TicketServiceResultKind.Success)
                throw new InvalidOperationException("Unable to seed deterministic active grant reservations.");
        }
        _machine = new OutboundGateStateMachine(_clock, _nonces, _clock, OutboundGateMode.Simulation, 0, new OutboundGateTrustedRuntimeState(_bootInstance, _wfpGeneration, _minifilterGeneration), _ticketService);
        _lastReasonCode = "sim-ready";
    }

    internal static OutboundGateSimulatorHost CreateTicketCapacityHostForAcceptance() =>
        new(true, OneTimeGateTicketService.MaximumOutstandingPerSubject, 0);

    internal static OutboundGateSimulatorHost CreateGrantCapacityHostForAcceptance() =>
        new(true, 0, OneTimeGateTicketService.MaximumActiveGrantsGlobal);

    public SimulationSnapshot Snapshot
    {
        get
        {
            lock (_transitionSync)
            {
                var coreStorage = _machine?.Storage;
                var ticketSnapshot = _ticketService?.Snapshot;
                var coreRuntime = _machine?.TrustedRuntime;
                return new SimulationSnapshot(
                _simulation ? OutboundGateMode.Simulation : OutboundGateMode.Disabled,
                _clock.Now(),
                _minifilter.Snapshot.PendingCount,
                FakeMinifilterEndpoint.GlobalCapacity,
                coreStorage?.ChallengeMappingCount ?? 0,
                128,
                _wfp.Snapshot.HeldFlowCount,
                FakeWfpEndpoint.HeldFlowCapacity,
                _wfp.Snapshot.HeldByteCount,
                FakeWfpEndpoint.GlobalByteCapacity,
                _scheduler.Count,
                SchedulerCapacity,
                OwnedOperationCount(),
                _acceptedReadCount,
                _releasedReadCount,
                _acceptedFlowCount,
                _challengeCreatedCount,
                _challengeDeliveredCount,
                _releasedFlowCount,
                _failedOpenCount,
                _overflowCount,
                _droppedEnvelopeCount,
                _criticalAlertCount,
                _minifilterCrashCount,
                _minifilterRestartCount,
                _wfpCrashCount,
                _wfpRestartCount,
                _serviceRestartCount,
                _diagnosticAlertEvictionCount,
                _transitionTraceEvictionCount,
                ticketSnapshot?.OutstandingGlobal ?? 0,
                OneTimeGateTicketService.MaximumOutstandingGlobal,
                ticketSnapshot?.ReplayTombstones ?? 0,
                OneTimeGateTicketService.MaximumReplayTombstonesGlobal,
                ticketSnapshot?.ActiveGrantReservations ?? 0,
                OneTimeGateTicketService.MaximumActiveGrantsGlobal,
                _wfp.Snapshot.InstalledGrantCount,
                FakeWfpEndpoint.GrantCapacity,
                _minifilter.Snapshot.Available,
                _wfp.Snapshot.Available,
                coreRuntime?.BootInstance ?? _bootInstance,
                coreRuntime?.WfpGeneration ?? _wfpGeneration,
                coreRuntime?.MinifilterGeneration ?? _minifilterGeneration,
                _lastReasonCode,
                OwnedOperationCount(),
                HostOwnershipCapacity,
                _faults.Count,
                FaultPlanCapacity,
                _alerts.Count,
                AlertRingCapacity,
                _trace.Count,
                TraceRingCapacity,
                0,
                AcceptanceResultCapacity,
                _minifilter.Snapshot.IntentOutboxCount,
                _minifilter.Snapshot.IntentOutboxCapacity,
                _minifilter.Snapshot.DispositionInboxCount,
                _minifilter.Snapshot.DispositionInboxCapacity,
                _minifilter.Snapshot.CompletionAckOutboxCount,
                _minifilter.Snapshot.CompletionAckOutboxCapacity,
                _wfp.Snapshot.GateArmInboxCount,
                _wfp.Snapshot.GateArmInboxCapacity,
                _wfp.Snapshot.GateAckOutboxCount,
                _wfp.Snapshot.GateAckOutboxCapacity,
                _wfp.Snapshot.FlowObservationInboxCount,
                _wfp.Snapshot.FlowObservationInboxCapacity,
                _wfp.Snapshot.ChallengeOutboxCount,
                _wfp.Snapshot.ChallengeOutboxCapacity,
                _scheduler.OwnerCount,
                SchedulerOwnerCapacity,
                coreStorage?.ActiveContextCount ?? 0,
                coreStorage?.ActiveContextCapacity ?? 256,
                coreStorage?.CriticalAlertCount ?? 0,
                coreStorage?.CriticalAlertCapacity ?? 256,
                _coreAlertIds.Count,
                CoreAlertDedupeCapacity,
                _consumedTickets.Count,
                ConsumedTicketCapacity);
            }
        }
    }

    public SimulationStepResult SubmitRead(SimulatedReadMetadata read)
    {
        lock (_transitionSync)
            return SubmitReadCore(read);
    }

    private SimulationStepResult SubmitReadCore(SimulatedReadMetadata read)
    {
        EnsureNotDisposed();
        _lastStepResult = null;
        if (!_simulation)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-disabled"));
        if (OwnedOperationCount() >= HostOwnershipCapacity)
            return Overflow(read.OperationId, "sim-operation-ownership-capacity-exhausted", read.Subject);
        var pending = _minifilter.TryPendRead(read);
        if (pending.Outcome == SimulatedFlowOutcome.FailedOpen)
            return Overflow(read.OperationId, pending.ReasonCode, read.Subject);
        if (pending.IsDuplicate)
            return Remember(pending);
        _acceptedReadOperations.Add(read.OperationId);
        Increment(ref _acceptedReadCount);
        var now = _clock.Now();
        var deadline = new ServiceMonotonicTimestamp(1, now.ClockInstanceId, checked(now.ElapsedMilliseconds + (long)OutboundGateLimits.MaximumGateArmReadDuration.TotalMilliseconds));
        var intent = new FileReadIntent(1, _nonces.NextNonce(), read.Subject, read.File, FileActivityOperation.Read, _clock.NowUtc(), new ServiceMonotonicTimeRange(1, now, deadline), _bootInstance, read.Sequence);
        if (!_minifilter.TryEnqueueIntent(intent) || !_minifilter.TryDequeueIntent(out var emittedIntent) || emittedIntent is null)
            return Overflow(read.OperationId, "sim-minifilter-channel-capacity-exhausted", read.Subject);
        var transition = _machine!.ReceiveIntent(emittedIntent);
        ObserveCore(transition);
        if (transition.ArmRequest is null)
            return FailOperation(read.OperationId, transition.Status.ReasonCode, transition.CriticalAlert);
        _intents.Add(read.OperationId, emittedIntent);
        _intentOperations.Add(emittedIntent.IntentId, read.OperationId);
        var scheduled = Schedule(SimulationEnvelope.ForArmRequest(read.OperationId, transition.ArmRequest));
        if (scheduled is not null)
            return Remember(scheduled);
        PumpReadyCore();
        return _lastStepResult ?? Remember(new(SimulatedFlowOutcome.Pending, "sim-read-arm-scheduled"));
    }

    public SimulationStepResult SubmitFlow(SimulatedFlowMetadata flow)
    {
        lock (_transitionSync)
            return SubmitFlowCore(flow);
    }

    private SimulationStepResult SubmitFlowCore(SimulatedFlowMetadata flow)
    {
        EnsureNotDisposed();
        _lastStepResult = null;
        if (!_simulation)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-disabled"));
        if (!TransportMatchesDestination(flow.Transport, flow.Destination.Protocol))
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-transport-protocol-mismatch"));
        if (flow.Shape == SimulatedFlowShape.NewFlow && flow.Transport == SimulatedTransportKind.Quic)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-new-quic-unsupported"));
        if (flow.Shape == SimulatedFlowShape.ExistingMultiplexed)
        {
            var reason = flow.Transport switch
            {
                SimulatedTransportKind.Tcp => "sim-reconnect-required-existing-tcp",
                SimulatedTransportKind.Udp => "sim-reconnect-required-existing-udp",
                SimulatedTransportKind.Quic => "sim-reconnect-required-existing-quic",
                _ => "sim-reconnect-required-existing-udp"
            };
            return Remember(new(SimulatedFlowOutcome.ReconnectRequired, reason));
        }
        if (!_intentOperations.TryGetValue(flow.IntentId, out var operationId))
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-flow-intent-not-found"));
        if (operationId != flow.OperationId)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-flow-operation-binding-mismatch"));
        var reserved = _wfp.ObserveFlow(flow);
        if (reserved.Outcome == SimulatedFlowOutcome.FailedOpen)
        {
            if (reserved.ReasonCode == "sim-held-flow-capacity-exhausted")
                return RejectChallengeAdmission(flow.OperationId, flow.IntentId, flow.Subject, reserved.ReasonCode);
            return Overflow(flow.OperationId, reserved.ReasonCode, flow.Subject);
        }
        _acceptedFlowOperations.Add(flow.OperationId);
        Increment(ref _acceptedFlowCount);
        var now = _clock.Now();
        var window = new ServiceMonotonicTimeRange(1, now, new ServiceMonotonicTimestamp(1, now.ClockInstanceId, checked(now.ElapsedMilliseconds + (long)OutboundGateLimits.MaximumDecisionHoldDuration.TotalMilliseconds)));
        var challenge = new NetworkGateChallenge(1, _nonces.NextNonce(), flow.IntentId, flow.Subject, flow.Destination, flow.FlowGeneration, false, FullCoverage, _clock.NowUtc(), window, "Simulation");
        Increment(ref _challengeCreatedCount);
        if (!_wfp.TryEnqueueChallenge(challenge) || !_wfp.TryDequeueChallenge(out var observed) || observed is null)
            return Overflow(flow.OperationId, "sim-wfp-channel-capacity-exhausted", flow.Subject);
        var scheduled = Schedule(SimulationEnvelope.ForChallenge(flow.OperationId, observed));
        if (scheduled is not null)
            return Remember(scheduled);
        PumpReadyCore();
        return _lastStepResult ?? Remember(new(SimulatedFlowOutcome.Pending, "sim-challenge-scheduled"));
    }

    public SimulationStepResult SubmitDecision(UserDecision decision)
    {
        lock (_transitionSync)
            return SubmitDecisionCore(decision);
    }

    private SimulationStepResult SubmitDecisionCore(UserDecision decision)
    {
        EnsureNotDisposed();
        if (!_simulation)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-disabled"));
        var transition = _machine!.ReceiveDecision(decision);
        ObserveCore(transition);
        if (!_challengeOperations.TryGetValue(decision.ChallengeId, out var operationId))
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-challenge-not-owned", transition));
        if (transition.Status.State == GateRuntimeState.Blocked)
        {
            ReleaseFlow(operationId);
            CompleteOperation(operationId);
            return Remember(new(SimulatedFlowOutcome.Blocked, transition.Status.ReasonCode, transition));
        }
        if (transition.Ticket is null)
        {
            if (transition.Status.State == GateRuntimeState.FailedOpen)
                FailOperation(operationId, transition.Status.ReasonCode, transition.CriticalAlert);
            return Remember(new(SimulatedFlowOutcome.FailedOpen, transition.Status.ReasonCode, transition));
        }
        _tickets[operationId] = transition.Ticket;
        return Remember(new(SimulatedFlowOutcome.Pending, "sim-ticket-issued", transition, Ticket: transition.Ticket));
    }

    public SimulationStepResult Redeem(OneTimeTicket ticket)
    {
        lock (_transitionSync)
            return RedeemCore(ticket);
    }

    private SimulationStepResult RedeemCore(OneTimeTicket ticket)
    {
        EnsureNotDisposed();
        if (!_simulation)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-disabled"));
        if (!_intentOperations.TryGetValue(ticket.IntentId, out var operationId))
            return Remember(new(SimulatedFlowOutcome.FailedOpen, _consumedTickets.Values.Any(item => item.TicketId == ticket.TicketId) ? "ticket-replay" : "sim-ticket-operation-not-found"));
        SimulationStepResult result;
        try
        {
            var transition = _machine!.RedeemTicket(ticket);
            ObserveCore(transition);
            if (transition.Grant is not null)
            {
                RememberConsumedTicket(ticket);
                var installed = _wfp.InstallGrant(transition.Grant);
                if (installed.Outcome != SimulatedFlowOutcome.Granted)
                {
                    ReleaseFlow(operationId);
                    MarkFailedOpen(operationId);
                    CompleteOperation(operationId);
                    EmitAlert(installed.ReasonCode, operationId, null);
                    result = new(SimulatedFlowOutcome.FailedOpen, installed.ReasonCode, transition, Ticket: ticket, Alert: _alerts.Count == 0 ? null : _alerts.ToArray()[^1]);
                    return Remember(result);
                }
                ReleaseFlow(operationId);
                CompleteOperation(operationId);
                result = new(SimulatedFlowOutcome.Granted, "sim-ticket-redeemed", transition, Ticket: ticket, Grant: transition.Grant);
            }
            else
            {
                FailOperation(operationId, transition.Status.ReasonCode, transition.CriticalAlert);
                result = new(SimulatedFlowOutcome.FailedOpen, transition.Status.ReasonCode, transition, Ticket: ticket);
            }
        }
        catch (InvalidOperationException exception)
        {
            result = new(SimulatedFlowOutcome.FailedOpen, exception.Message == "ticket-replay" || _consumedTickets.Values.Any(item => item.TicketId == ticket.TicketId) ? "ticket-replay" : "sim-ticket-rejected");
        }
        return Remember(result);
    }

    public SimulationStepResult Inject(SimulationFault fault)
    {
        lock (_transitionSync)
            return InjectCore(fault);
    }

    private SimulationStepResult InjectCore(SimulationFault fault)
    {
        EnsureNotDisposed();
        ArgumentNullException.ThrowIfNull(fault);
        if (fault.Kind is SimulationFaultKind.DelayNext or SimulationFaultKind.DropNext or SimulationFaultKind.StaleGeneration or SimulationFaultKind.PartialCoverage or SimulationFaultKind.DegradedCoverage)
        {
            if (_faults.Count >= FaultPlanCapacity)
                return Overflow(Guid.Empty, "sim-fault-plan-capacity-exhausted", null);
            _faults.Add(fault);
            return Remember(new(SimulatedFlowOutcome.Pending, "sim-fault-planned"));
        }
        return fault.Kind switch
        {
            SimulationFaultKind.MinifilterCrash => RestartEndpoint(true, false),
            SimulationFaultKind.MinifilterRestart => RestartEndpoint(true, true),
            SimulationFaultKind.WfpCrash => RestartEndpoint(false, false),
            SimulationFaultKind.WfpRestart => RestartEndpoint(false, true),
            SimulationFaultKind.ServiceRestart => RestartService(),
            _ => Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-fault-unsupported"))
        };
    }

    public int PumpReady()
    {
        lock (_transitionSync)
            return PumpReadyCore();
    }

    private int PumpReadyCore()
    {
        EnsureNotDisposed();
        var pumped = _scheduler.PumpReady(PumpDispatchCapacity, Dispatch);
        if (pumped >= PumpDispatchCapacity && _scheduler.Count > 0)
        {
            Increment(ref _overflowCount);
            InvalidateRuntime(OwnedOperationIds().ToArray());
            EmitAlert("sim-pump-budget-exhausted", null, null);
            _lastReasonCode = "sim-pump-budget-exhausted";
        }
        return pumped;
    }

    public int AdvanceBy(long milliseconds)
    {
        lock (_transitionSync)
            return AdvanceByCore(milliseconds);
    }

    private int AdvanceByCore(long milliseconds)
    {
        EnsureNotDisposed();
        _clock.AdvanceBy(milliseconds);
        Reconcile(_machine?.ProcessExpired() ?? Array.Empty<GateStatus>());
        var pumped = PumpReady();
        foreach (var grant in _wfp.Grants)
            if (grant.GrantWindow.Deadline.ElapsedMilliseconds <= _clock.Now().ElapsedMilliseconds)
            {
                _wfp.RemoveGrant(grant.GrantId);
                if (_intentOperations.TryGetValue(grant.IntentId, out var operationId))
                    CompleteOperation(operationId);
            }
        return pumped;
    }

    internal void ApplyPolicyEpoch(long epoch)
    {
        lock (_transitionSync)
            ApplyPolicyEpochCore(epoch);
    }

    private void ApplyPolicyEpochCore(long epoch)
    {
        if (_machine is null)
            return;
        Reconcile(_machine.ApplyPolicyEpoch(epoch));
        _wfp.ReleaseAll();
    }

    internal bool TryGetTicket(Guid operationId, out OneTimeTicket? ticket)
    {
        lock (_transitionSync)
            return _tickets.TryGetValue(operationId, out ticket);
    }

    internal bool TryGetIntentId(Guid operationId, out Guid intentId)
    {
        lock (_transitionSync)
        {
            if (_intents.TryGetValue(operationId, out var intent))
            {
                intentId = intent.IntentId;
                return true;
            }
            intentId = Guid.Empty;
            return false;
        }
    }

    internal bool TryGetChallengeId(Guid operationId, out Guid challengeId)
    {
        lock (_transitionSync)
        {
            var value = _challengeOperations.FirstOrDefault(pair => pair.Value == operationId);
            challengeId = value.Key;
            return value.Key != Guid.Empty;
        }
    }

    internal IReadOnlyList<CriticalAlert> Alerts
    {
        get
        {
            lock (_transitionSync)
                return new ReadOnlyCollection<CriticalAlert>(_alerts.ToArray());
        }
    }

    internal int FaultPlanCount
    {
        get
        {
            lock (_transitionSync)
                return _faults.Count;
        }
    }

    internal int SchedulerOwnerCount
    {
        get
        {
            lock (_transitionSync)
                return _scheduler.OwnerCount;
        }
    }

    internal IReadOnlyList<OneTimeTicket> ConsumedTickets
    {
        get
        {
            lock (_transitionSync)
                return _consumedTickets.Values.ToArray();
        }
    }

    internal IReadOnlyList<EphemeralFlowGrant> InstalledGrants
    {
        get
        {
            lock (_transitionSync)
                return _wfp.Grants;
        }
    }

    internal SimulationStepResult ConsumeGrantBytes(Guid grantId, long bytes)
    {
        lock (_transitionSync)
        {
            EnsureNotDisposed();
            var result = _wfp.ConsumeGrantBytes(grantId, bytes);
            if (!_wfp.Grants.Any(grant => grant.GrantId == grantId))
            {
                _wfpGeneration = _generations.Next(SimulationGenerationDomain.Wfp);
                _minifilterGeneration = _generations.Next(SimulationGenerationDomain.Minifilter);
                InvalidateRuntime(OwnedOperationIds().ToArray());
                _minifilter.Restart(_minifilterGeneration);
                _wfp.Restart(_wfpGeneration);
            }
            return Remember(result);
        }
    }

    internal SimulationStepResult RunPumpChainForAcceptance(int dispatchCount)
    {
        lock (_transitionSync)
        {
            EnsureNotDisposed();
            ArgumentOutOfRangeException.ThrowIfNegativeOrZero(dispatchCount);
            var operationId = _nonces.NextNonce();
            if (!_scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(operationId, dispatchCount), 0))
                return Overflow(operationId, "sim-scheduler-capacity-exhausted", null);
            PumpReadyCore();
            return Remember(new(
                _lastReasonCode == "sim-pump-budget-exhausted" ? SimulatedFlowOutcome.FailedOpen : SimulatedFlowOutcome.Pending,
                _lastReasonCode));
        }
    }

    internal SimulationStepResult RunSchedulerCapacityForAcceptance(bool ownerCapacity)
    {
        lock (_transitionSync)
        {
            EnsureNotDisposed();
            var eventsPerOwner = ownerCapacity ? 1 : 2;
            for (var owner = 0; owner < SchedulerOwnerCapacity; owner++)
                for (var eventIndex = 0; eventIndex < eventsPerOwner; eventIndex++)
                    if (!_scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(SimulationFixture.Id(80_000 + owner), 1), 1))
                        throw new InvalidOperationException("Scheduler rejected before the locked acceptance boundary.");
            var rejectedOwner = ownerCapacity ? SimulationFixture.Id(81_000) : SimulationFixture.Id(80_000);
            if (_scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(rejectedOwner, 1), 1))
                throw new InvalidOperationException("Scheduler accepted beyond the locked acceptance boundary.");
            return Overflow(Guid.Empty, "sim-scheduler-capacity-exhausted", null);
        }
    }

    internal SimulationStepResult RunEndpointChannelCapacityForAcceptance(bool minifilter)
    {
        lock (_transitionSync)
        {
            EnsureNotDisposed();
            var now = _clock.Now();
            var window = new ServiceMonotonicTimeRange(1, now, new ServiceMonotonicTimestamp(1, now.ClockInstanceId, checked(now.ElapsedMilliseconds + 2_000)));
            if (minifilter)
            {
                var intent = new FileReadIntent(1, _nonces.NextNonce(), SimulationFixture.Subject, SimulationFixture.File, FileActivityOperation.Read, _clock.NowUtc(), window, _bootInstance, 1);
                for (var index = 0; index < FakeMinifilterEndpoint.IntentOutboxCapacity; index++)
                    if (!_minifilter.TryEnqueueIntent(intent))
                        throw new InvalidOperationException("Minifilter channel rejected before the locked acceptance boundary.");
                if (_minifilter.TryEnqueueIntent(intent))
                    throw new InvalidOperationException("Minifilter channel accepted beyond the locked acceptance boundary.");
                return Overflow(Guid.Empty, "sim-minifilter-channel-capacity-exhausted", null);
            }

            var request = new GateArmRequest(1, _nonces.NextNonce(), SimulationFixture.Subject, FullCoverage, 0, _wfpGeneration, _nonces.NextNonce(), _clock.NowUtc(), window);
            for (var index = 0; index < FakeWfpEndpoint.ArmChannelCapacity; index++)
                if (!_wfp.TryEnqueueArmRequest(request))
                    throw new InvalidOperationException("WFP channel rejected before the locked acceptance boundary.");
            if (_wfp.TryEnqueueArmRequest(request))
                throw new InvalidOperationException("WFP channel accepted beyond the locked acceptance boundary.");
            return Overflow(Guid.Empty, "sim-wfp-channel-capacity-exhausted", null);
        }
    }

    private SimulationStepResult? Schedule(SimulationEnvelope envelope)
    {
        var fault = TakeDeliveryFault(envelope.Kind, envelope.OperationId);
        if (fault?.Kind == SimulationFaultKind.DropNext)
        {
            Increment(ref _droppedEnvelopeCount);
            _lastReasonCode = "sim-envelope-dropped";
            return Remember(new(SimulatedFlowOutcome.Pending, "sim-envelope-dropped"));
        }
        var delay = fault?.Kind == SimulationFaultKind.DelayNext ? fault.DelayMilliseconds : 0;
        if (!_scheduler.TrySchedule(envelope, delay))
            return Overflow(envelope.OperationId, "sim-scheduler-capacity-exhausted", null);
        return null;
    }

    private void Dispatch(SimulationEnvelope envelope)
    {
        switch (envelope.Kind)
        {
            case SimulationEnvelopeKind.GateArmRequest:
                DispatchArmRequest(envelope);
                break;
            case SimulationEnvelopeKind.GateArmAck:
                DispatchArmAck(envelope);
                break;
            case SimulationEnvelopeKind.FileReadDisposition:
                DispatchDisposition(envelope);
                break;
            case SimulationEnvelopeKind.FileReadCompletionAck:
                DispatchCompletion(envelope);
                break;
            case SimulationEnvelopeKind.NetworkGateChallenge:
                DispatchChallenge(envelope);
                break;
            case SimulationEnvelopeKind.Fault when envelope.RemainingDispatches > 0:
                if (envelope.RemainingDispatches > 1)
                    _scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(envelope.OperationId, envelope.RemainingDispatches - 1), 0);
                break;
        }
    }

    private void DispatchArmRequest(SimulationEnvelope envelope)
    {
        if (!_intents.ContainsKey(envelope.OperationId) || envelope.ArmRequest is not { } request)
            return;
        var armResult = _wfp.AcceptArmRequest(request);
        var ack = armResult.Ack;
        if (ack is null)
        {
            FailOperation(envelope.OperationId, armResult.ReasonCode, armResult.Alert);
            return;
        }
        var fault = TakeMutationFault(SimulationEnvelopeKind.GateArmAck, envelope.OperationId);
        if (fault is not null)
        {
            var simulatorReason = fault.Kind switch
            {
                SimulationFaultKind.PartialCoverage => "sim-coverage-partial",
                SimulationFaultKind.DegradedCoverage => "sim-coverage-degraded",
                SimulationFaultKind.StaleGeneration => "sim-stale-wfp-generation",
                _ => "sim-full-coverage-armed"
            };
            EmitAlert(simulatorReason, envelope.OperationId, request.Subject);
            ack = _wfp.CreateAck(
                request,
                fault.Kind == SimulationFaultKind.PartialCoverage ? new GateCoverage(1, GateCoverageFlags.NewTcp) : FullCoverage,
                fault.Kind == SimulationFaultKind.DegradedCoverage ? "sim-coverage-degraded" : null,
                fault.Kind == SimulationFaultKind.StaleGeneration ? _generations.Next(SimulationGenerationDomain.Wfp) : _wfpGeneration);
        }
        Schedule(SimulationEnvelope.ForArmAck(envelope.OperationId, ack));
    }

    private void DispatchArmAck(SimulationEnvelope envelope)
    {
        if (!_intents.ContainsKey(envelope.OperationId) || envelope.ArmAck is not { } ack)
            return;
        var armed = _machine!.ReceiveGateArmAck(ack);
        ObserveCore(armed);
        if (armed.Status.State == GateRuntimeState.FailedOpen)
        {
            FailOperation(envelope.OperationId, armed.Status.ReasonCode, armed.CriticalAlert);
            return;
        }
        var disposition = _machine.ReleaseAfterGateArmed(ack.IntentId).Disposition;
        if (disposition is null || !_minifilter.BindDisposition(envelope.OperationId, disposition))
        {
            FailOperation(envelope.OperationId, "sim-disposition-missing", null);
            return;
        }
        Schedule(SimulationEnvelope.ForDisposition(envelope.OperationId, disposition));
    }

    private void DispatchDisposition(SimulationEnvelope envelope)
    {
        if (!_intents.ContainsKey(envelope.OperationId) || envelope.ReadDisposition is not { } disposition)
            return;
        var endpointResult = _minifilter.AcceptDisposition(disposition);
        if (endpointResult.Outcome == SimulatedFlowOutcome.FailedOpen)
        {
            FailOperation(envelope.OperationId, endpointResult.ReasonCode, endpointResult.Alert);
            return;
        }
        if (!endpointResult.IsDuplicate)
            Increment(ref _releasedReadCount);
        var generation = _minifilter.Snapshot.Generation;
        if (TakeMutationFault(SimulationEnvelopeKind.FileReadCompletionAck, envelope.OperationId)?.Kind == SimulationFaultKind.StaleGeneration)
        {
            EmitAlert("sim-stale-minifilter-generation", envelope.OperationId, null);
            generation = _generations.Next(SimulationGenerationDomain.Minifilter);
        }
        var completion = FakeMinifilterEndpoint.CreateCompletion(disposition, generation, _nonces, disposition.Sequence);
        if (!_minifilter.TryEnqueueCompletion(completion) || !_minifilter.TryDequeueCompletion(out var emitted) || emitted is null)
        {
            Overflow(envelope.OperationId, "sim-minifilter-channel-capacity-exhausted", null);
            return;
        }
        Schedule(SimulationEnvelope.ForCompletion(envelope.OperationId, emitted));
    }

    private void DispatchCompletion(SimulationEnvelope envelope)
    {
        if (!_intents.ContainsKey(envelope.OperationId) || envelope.CompletionAck is not { } completion)
            return;
        var completed = _machine!.AcceptCompletion(completion);
        ObserveCore(completed);
        if (completed.Status.State == GateRuntimeState.FailedOpen)
        {
            FailOperation(envelope.OperationId, completed.Status.ReasonCode, completed.CriticalAlert);
            return;
        }
        Remember(new(SimulatedFlowOutcome.Pending, "sim-read-completion-accepted", completed, Completion: completion));
    }

    private void DispatchChallenge(SimulationEnvelope envelope)
    {
        if (!_intents.ContainsKey(envelope.OperationId) || envelope.Challenge is not { } challenge)
            return;
        Increment(ref _challengeDeliveredCount);
        var transition = _machine!.ReceiveChallenge(challenge);
        ObserveCore(transition);
        if (transition.Challenge is null || transition.Status.State == GateRuntimeState.FailedOpen)
        {
            ReleaseFlow(envelope.OperationId);
            MarkFailedOpen(envelope.OperationId);
            CompleteOperation(envelope.OperationId);
            Remember(new(SimulatedFlowOutcome.FailedOpen, transition.Status.ReasonCode, transition));
            return;
        }
        _challengeOperations[challenge.ChallengeId] = envelope.OperationId;
        Remember(new(SimulatedFlowOutcome.Pending, "sim-challenge-created", transition));
    }

    private SimulationFault? TakeDeliveryFault(SimulationEnvelopeKind kind, Guid operationId) =>
        TakeFault(kind, operationId, SimulationFaultKind.DelayNext, SimulationFaultKind.DropNext);

    private SimulationFault? TakeMutationFault(SimulationEnvelopeKind kind, Guid operationId) =>
        TakeFault(kind, operationId, SimulationFaultKind.StaleGeneration, SimulationFaultKind.PartialCoverage, SimulationFaultKind.DegradedCoverage);

    private SimulationFault? TakeFault(SimulationEnvelopeKind kind, Guid operationId, params SimulationFaultKind[] allowedKinds)
    {
        var index = _faults.FindIndex(item => allowedKinds.Contains(item.Kind) && item.EnvelopeKind == kind && (item.OperationId is null || item.OperationId == operationId));
        if (index < 0)
            return null;
        var fault = _faults[index];
        _faults.RemoveAt(index);
        return fault;
    }

    private SimulationStepResult RestartEndpoint(bool minifilter, bool restart)
    {
        var liveOperations = OwnedOperationIds().ToArray();
        if (minifilter)
        {
            foreach (var operationId in _minifilter.PendingOperationIds.ToArray())
                ReleaseRead(operationId);
            if (restart) Increment(ref _minifilterRestartCount); else Increment(ref _minifilterCrashCount);
            _minifilterGeneration = _generations.Next(SimulationGenerationDomain.Minifilter);
            if (restart) _minifilter.Restart(_minifilterGeneration); else _minifilter.Crash();
        }
        else
        {
            foreach (var operationId in _wfp.HeldOperationIds.ToArray())
                ReleaseFlow(operationId);
            if (restart) Increment(ref _wfpRestartCount); else Increment(ref _wfpCrashCount);
            _wfpGeneration = _generations.Next(SimulationGenerationDomain.Wfp);
            if (restart) _wfp.Restart(_wfpGeneration); else _wfp.Crash();
        }
        InvalidateRuntime(liveOperations);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, minifilter ? (restart ? "sim-minifilter-restarted" : "sim-minifilter-crashed") : (restart ? "sim-wfp-restarted" : "sim-wfp-crashed")));
    }

    private SimulationStepResult RestartService()
    {
        var liveOperations = OwnedOperationIds().ToArray();
        Increment(ref _serviceRestartCount);
        _faults.Clear();
        _bootInstance = _generations.Next(SimulationGenerationDomain.Boot);
        _wfpGeneration = _generations.Next(SimulationGenerationDomain.Wfp);
        _minifilterGeneration = _generations.Next(SimulationGenerationDomain.Minifilter);
        InvalidateRuntime(liveOperations);
        _clock.Restart(_generations.Next(SimulationGenerationDomain.Clock));
        _minifilter.Restart(_minifilterGeneration);
        _wfp.Restart(_wfpGeneration);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-service-restarted"));
    }

    private void InvalidateRuntime(IReadOnlyList<Guid> liveOperations)
    {
        _scheduler.Clear();
        if (_machine is not null)
            Reconcile(_machine.HandleServiceRestart(new OutboundGateTrustedRuntimeState(_bootInstance, _wfpGeneration, _minifilterGeneration)));
        foreach (var operationId in liveOperations)
            MarkFailedOpen(operationId);
        foreach (var operationId in _minifilter.PendingOperationIds)
            ReleaseRead(operationId);
        foreach (var operationId in _wfp.HeldOperationIds)
            ReleaseFlow(operationId);
        _minifilter.ReleaseAll();
        _wfp.ReleaseAll();
        _intents.Clear();
        _intentOperations.Clear();
        _challengeOperations.Clear();
        _tickets.Clear();
        _acceptedReadOperations.Clear();
        _acceptedFlowOperations.Clear();
        _failedOpenOperations.Clear();
        EmitAlert("sim-runtime-invalidated", null, null);
        foreach (var operationId in liveOperations)
            CompleteOperation(operationId);
    }

    private void Reconcile(IReadOnlyList<GateStatus> statuses)
    {
        if (_machine is not null)
            foreach (var alert in _machine.CriticalAlerts)
                ObserveCoreAlert(alert);
        foreach (var status in statuses)
        {
            var operationId = status.AffectedScope.IntentId is Guid intentId && _intentOperations.TryGetValue(intentId, out var found) ? found : (Guid?)null;
            if (operationId is Guid live)
            {
                if (status.State == GateRuntimeState.FailedOpen || status.State == GateRuntimeState.Blocked)
                    MarkFailedOpen(live);
                ReleaseRead(live);
                ReleaseFlow(live);
                CompleteOperation(live);
            }
            _lastReasonCode = status.ReasonCode;
        }
    }

    private SimulationStepResult FailOperation(Guid operationId, string reason, CriticalAlert? coreAlert)
    {
        MarkFailedOpen(operationId);
        ReleaseRead(operationId);
        ReleaseFlow(operationId);
        CompleteOperation(operationId);
        if (coreAlert is not null)
            ObserveCoreAlert(coreAlert);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, reason, Alert: coreAlert));
    }

    private SimulationStepResult Overflow(Guid operationId, string reason, GateSubject? subject)
    {
        Increment(ref _overflowCount);
        var admittedToCore = operationId != Guid.Empty && _intents.ContainsKey(operationId);
        if (admittedToCore)
        {
            var liveOperations = OwnedOperationIds().ToArray();
            _wfpGeneration = _generations.Next(SimulationGenerationDomain.Wfp);
            _minifilterGeneration = _generations.Next(SimulationGenerationDomain.Minifilter);
            InvalidateRuntime(liveOperations);
            _minifilter.Restart(_minifilterGeneration);
            _wfp.Restart(_wfpGeneration);
        }
        else if (operationId != Guid.Empty)
        {
            MarkFailedOpen(operationId);
            ReleaseRead(operationId);
            ReleaseFlow(operationId);
            CompleteOperation(operationId);
        }
        EmitAlert(reason, operationId == Guid.Empty ? null : operationId, subject);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, reason, Alert: _alerts.LastOrDefault()));
    }

    private SimulationStepResult RejectChallengeAdmission(Guid operationId, Guid intentId, GateSubject subject, string simulatorReason)
    {
        Increment(ref _overflowCount);
        var failure = new ChallengeAdmissionFailure(
            1,
            _nonces.NextNonce(),
            intentId,
            subject,
            _wfpGeneration,
            ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted,
            _clock.Now());
        GateTransitionResult transition;
        try
        {
            transition = _machine!.ReceiveChallengeAdmissionFailure(failure);
        }
        catch (InvalidOperationException)
        {
            return FailChallengeAdmissionInvariant(operationId, subject);
        }
        ObserveCore(transition);
        if (transition.Status.State != GateRuntimeState.FailedOpen
            || transition.Status.ReasonCode != "challenge-admission-held-flow-capacity-exhausted"
            || transition.Status.AffectedScope.IntentId != intentId
            || transition.Challenge is not null
            || transition.Ticket is not null
            || transition.Grant is not null
            || transition.CriticalAlert is null)
            return FailChallengeAdmissionInvariant(operationId, subject);

        MarkFailedOpen(operationId);
        CompleteOperation(operationId);
        EmitAlert(simulatorReason, operationId, subject);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, simulatorReason, transition, Alert: transition.CriticalAlert));
    }

    private SimulationStepResult FailChallengeAdmissionInvariant(Guid operationId, GateSubject subject)
    {
        var liveOperations = OwnedOperationIds().ToArray();
        _wfpGeneration = _generations.Next(SimulationGenerationDomain.Wfp);
        _minifilterGeneration = _generations.Next(SimulationGenerationDomain.Minifilter);
        InvalidateRuntime(liveOperations);
        _minifilter.Restart(_minifilterGeneration);
        _wfp.Restart(_wfpGeneration);
        EmitAlert("sim-challenge-admission-transition-invalid", operationId, subject);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-challenge-admission-transition-invalid", Alert: _alerts.LastOrDefault()));
    }

    private void ObserveCore(GateTransitionResult result)
    {
        _lastReasonCode = result.Status.ReasonCode;
        if (result.CriticalAlert is not null)
            ObserveCoreAlert(result.CriticalAlert);
    }

    private void ObserveCoreAlert(CriticalAlert alert)
    {
        if (!_coreAlertIds.Add(alert.AlertId))
            return;
        _coreAlertIdOrder.Enqueue(alert.AlertId);
        while (_coreAlertIds.Count > CoreAlertDedupeCapacity)
            _coreAlertIds.Remove(_coreAlertIdOrder.Dequeue());
        AddAlert(alert);
    }

    private void EmitAlert(string reason, Guid? operationId, GateSubject? subject)
    {
        var scope = operationId is Guid id && _intents.TryGetValue(id, out var intent)
            ? new GateAffectedScope(1, GateAffectedScopeKind.Intent, intent.IntentId, intent.Subject)
            : subject is not null
                ? new GateAffectedScope(1, GateAffectedScopeKind.Subject, null, subject)
                : new GateAffectedScope(1, GateAffectedScopeKind.OutboundGateSubsystem, null, null);
        AddAlert(new CriticalAlert(1, _nonces.NextNonce(), reason, scope, _clock.NowUtc(), _clock.Now(), _droppedEnvelopeCount, _overflowCount, true));
    }

    private void AddAlert(CriticalAlert alert)
    {
        Increment(ref _criticalAlertCount);
        _alerts.Enqueue(alert);
        while (_alerts.Count > AlertRingCapacity)
        {
            _alerts.Dequeue();
            Increment(ref _diagnosticAlertEvictionCount);
        }
    }

    private SimulationStepResult Remember(SimulationStepResult result)
    {
        _lastReasonCode = result.ReasonCode;
        _lastStepResult = result;
        if (_trace.Count >= TraceRingCapacity)
        {
            _trace.Dequeue();
            Increment(ref _transitionTraceEvictionCount);
        }
        _trace.Enqueue(result.ReasonCode);
        return result;
    }

    private void RememberConsumedTicket(OneTimeTicket ticket)
    {
        _consumedTickets[ticket.TicketId] = ticket;
        _consumedTicketOrder.Enqueue(ticket.TicketId);
        while (_consumedTicketOrder.Count > ConsumedTicketCapacity)
            _consumedTickets.Remove(_consumedTicketOrder.Dequeue());
    }

    private void MarkFailedOpen(Guid operationId)
    {
        if (operationId != Guid.Empty && (_acceptedReadOperations.Contains(operationId) || _acceptedFlowOperations.Contains(operationId)) && _failedOpenOperations.Add(operationId))
            Increment(ref _failedOpenCount);
    }

    private void ReleaseRead(Guid operationId)
    {
        if (_minifilter.ReleaseOperation(operationId))
            Increment(ref _releasedReadCount);
    }

    private void ReleaseFlow(Guid operationId)
    {
        if (_wfp.RemoveHeld(operationId))
            Increment(ref _releasedFlowCount);
    }

    private IEnumerable<Guid> OwnedOperationIds() => _minifilter.PendingOperationIds.Concat(_wfp.HeldOperationIds).Concat(_intents.Keys).Distinct();
    private int OwnedOperationCount() => OwnedOperationIds().Count();
    private static void Increment(ref long counter) => counter = checked(counter + 1);
    private static bool TransportMatchesDestination(SimulatedTransportKind transport, TransportProtocol protocol) => transport switch
    {
        SimulatedTransportKind.Tcp => protocol == TransportProtocol.Tcp,
        SimulatedTransportKind.Udp or SimulatedTransportKind.Quic => protocol == TransportProtocol.Udp,
        _ => false
    };
    private void CompleteOperation(Guid operationId)
    {
        _scheduler.CancelOwned(operationId);
        if (_intents.Remove(operationId, out var intent))
            _intentOperations.Remove(intent.IntentId);
        foreach (var challenge in _challengeOperations.Where(pair => pair.Value == operationId).Select(pair => pair.Key).ToArray())
            _challengeOperations.Remove(challenge);
        _tickets.Remove(operationId);
        _acceptedReadOperations.Remove(operationId);
        _acceptedFlowOperations.Remove(operationId);
        _failedOpenOperations.Remove(operationId);
    }
    private void EnsureNotDisposed() => ObjectDisposedException.ThrowIf(_disposed, typeof(OutboundGateSimulatorHost));

    public void Dispose()
    {
        lock (_transitionSync)
        {
            if (_disposed)
                return;
            _disposed = true;
            if (_simulation)
                InvalidateRuntime(OwnedOperationIds().ToArray());
            _faults.Clear();
            _machine?.Dispose();
        }
    }
}

internal sealed record ScenarioReport(string Name, bool Passed, string Reason, SimulationSnapshot Snapshot);
internal sealed record SuiteReport(int Passed, int Total, IReadOnlyList<ScenarioReport> Scenarios, SimulationSnapshot FinalSnapshot);

internal static class SimulationFixture
{
    internal static readonly DateTimeOffset Start = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);
    internal static readonly ProcessIdentity Process = new(42, Start);
    internal static readonly GateSubject Subject = new(1, Process, "sha256:simulation-app", null, [Process]);
    internal static readonly FileVersionIdentity File = new(1, "volume-1", "file-42", Start, 1024, Start.AddMinutes(1), Start.AddMinutes(2), 42, "version-token-1");

    internal static Guid Id(int value, byte domain = 0x31) =>
        new(value, domain, 0x5b04, domain, 0x5b, 0x04, 0, 0, 0, (byte)(value >> 8), (byte)value);

    internal static SimulatedReadMetadata Read(Guid operationId, GateSubject? subject = null, long sequence = 1) => new(operationId, subject ?? Subject, File, sequence, 1024);

    internal static DestinationBinding Destination(TransportProtocol protocol = TransportProtocol.Tcp) => new(1, IPAddress.Loopback, IpVersion.IPv4, protocol == TransportProtocol.Tcp ? 5050 : 5051, protocol, NetworkTrafficDirection.Outbound, 12, 34, "localhost", DomainEvidenceProvenance.DnsObservation, Start);

    internal static SimulatedFlowMetadata Flow(Guid operationId, Guid intentId, GateSubject? subject = null, TransportProtocol protocol = TransportProtocol.Tcp, SimulatedFlowShape shape = SimulatedFlowShape.NewFlow, SimulatedTransportKind? transport = null, long bytes = 1024) => new(operationId, intentId, subject ?? Subject, Destination(protocol), 1, transport ?? (protocol == TransportProtocol.Tcp ? SimulatedTransportKind.Tcp : SimulatedTransportKind.Udp), shape, bytes);

    internal static UserDecision Decision(Guid challengeId, UserDecisionKind decision = UserDecisionKind.AllowOnce, int sequence = 1) => new(1, Id(900_000 + sequence, 0x44), challengeId, decision, null, Start, "simulation-test");
}

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };
    private static readonly string[] LockedScenarioNames =
    [
        "disabled-default-zero-state", "happy-new-tcp", "happy-new-udp", "release-requires-full-ack", "completion-requires-exact-binding", "existing-tcp-reconnect-required", "existing-udp-reconnect-required", "existing-quic-reconnect-required", "delay-before-deadline-succeeds", "delay-at-deadline-fails-open", "drop-times-out-deterministically", "minifilter-crash-restart-cleans", "wfp-crash-restart-cleans", "service-restart-cleans", "stale-wfp-generation-rejected", "stale-minifilter-generation-rejected", "pending-read-subject-cap", "pending-read-global-cap", "challenge-subject-cap", "challenge-global-cap", "endpoint-channel-boundaries", "held-flow-entry-boundaries", "held-data-flow-cap", "held-data-global-cap", "scheduler-cap", "fault-plan-cap", "pump-dispatch-budget", "ticket-replay-through-endpoint", "ticket-capacity-through-endpoint", "grant-expiry-and-byte-count", "policy-change-cleans-endpoints", "privacy-metadata-only", "no-wall-clock-or-event-workers", "all-faults-finish-zero-owned-state"
    ];

    public static int Main(string[] args)
    {
        try
        {
            if (args.Length == 0)
            {
                using var disabled = new OutboundGateSimulatorHost();
                Console.WriteLine(JsonSerializer.Serialize(disabled.Snapshot, JsonOptions));
                return 0;
            }
            if (args.Length == 2 && args[0] == "--acceptance-suite" && args[1] == "--json")
            {
                var suite = RunAcceptanceSuite();
                Console.WriteLine(JsonSerializer.Serialize(suite, JsonOptions));
                return suite.Passed == suite.Total ? 0 : 1;
            }
            if (args.Length == 3 && args[0] == "--scenario" && args[2] == "--json")
            {
                var report = RunNamedScenario(args[1]);
                Console.WriteLine(JsonSerializer.Serialize(report, JsonOptions));
                return report.Passed ? 0 : 1;
            }
            Console.Error.WriteLine("Usage: EgressGuard.OutboundGateSimulator [--acceptance-suite --json|--scenario <name> --json]");
            return 2;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or TestFailureException)
        {
            Console.Error.WriteLine($"Simulation failed: {exception.Message}");
            return 1;
        }
    }

    internal static SuiteReport RunAcceptanceSuite()
    {
        Ensure(LockedScenarioNames.Length <= OutboundGateSimulatorHost.AcceptanceResultCapacity, "acceptance result cap was exceeded");
        var reports = LockedScenarioNames.Select(RunNamedScenario).ToArray();
        var finalSnapshot = reports.Length == 0
            ? new OutboundGateSimulatorHost().Snapshot
            : reports[^1].Snapshot with { AcceptanceResultCount = reports.Length };
        return new SuiteReport(reports.Count(report => report.Passed), reports.Length, reports, finalSnapshot);
    }

    internal static ScenarioReport RunNamedScenario(string name)
    {
        using var host = name == "ticket-capacity-through-endpoint"
            ? OutboundGateSimulatorHost.CreateTicketCapacityHostForAcceptance()
            : new OutboundGateSimulatorHost(name != "disabled-default-zero-state");
        try
        {
            RunScenario(name, host);
            var snapshot = host.Snapshot;
            return new ScenarioReport(name, true, "passed", snapshot);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or TestFailureException)
        {
            return new ScenarioReport(name, false, exception.Message, host.Snapshot);
        }
    }

    private static void RunScenario(string name, OutboundGateSimulatorHost host)
    {
        switch (name)
        {
            case "disabled-default-zero-state":
                Ensure(host.Snapshot.Mode == OutboundGateMode.Disabled, "default mode was not Disabled");
                Ensure(host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(1))).ReasonCode == "sim-disabled", "Disabled created authority");
                EnsureZeroOwnedState(host, authorityMustBeZero: true);
                break;
            case "happy-new-tcp":
            case "happy-new-udp":
                EnsureHappyPath(host, name.EndsWith("udp", StringComparison.Ordinal) ? TransportProtocol.Udp : TransportProtocol.Tcp);
                break;
            case "release-requires-full-ack":
                EnsureCoverageFault(host, SimulationFaultKind.PartialCoverage, "sim-coverage-partial");
                using (var degraded = new OutboundGateSimulatorHost(true))
                    EnsureCoverageFault(degraded, SimulationFaultKind.DegradedCoverage, "sim-coverage-degraded");
                break;
            case "completion-requires-exact-binding":
                EnsureDispositionAndCompletionBinding(host);
                break;
            case "existing-tcp-reconnect-required":
                EnsureTransportRules(host, SimulatedTransportKind.Tcp, TransportProtocol.Tcp, "sim-reconnect-required-existing-tcp");
                break;
            case "existing-udp-reconnect-required":
                EnsureTransportRules(host, SimulatedTransportKind.Udp, TransportProtocol.Udp, "sim-reconnect-required-existing-udp");
                break;
            case "existing-quic-reconnect-required":
                EnsureTransportRules(host, SimulatedTransportKind.Quic, TransportProtocol.Udp, "sim-reconnect-required-existing-quic");
                break;
            case "delay-before-deadline-succeeds":
                EnsureDelayCoverage(host, timeout: false);
                break;
            case "delay-at-deadline-fails-open":
                EnsureDelayCoverage(host, timeout: true);
                break;
            case "drop-times-out-deterministically":
                EnsureDropCoverage(host);
                break;
            case "minifilter-crash-restart-cleans":
                EnsureEndpointRestart(host, minifilter: true);
                break;
            case "wfp-crash-restart-cleans":
                EnsureEndpointRestart(host, minifilter: false);
                break;
            case "service-restart-cleans":
                EnsureServiceRestart(host);
                break;
            case "stale-wfp-generation-rejected":
                EnsureStaleGeneration(host, SimulationEnvelopeKind.GateArmAck, "sim-stale-wfp-generation");
                break;
            case "stale-minifilter-generation-rejected":
                EnsureStaleGeneration(host, SimulationEnvelopeKind.FileReadCompletionAck, "sim-stale-minifilter-generation");
                break;
            case "pending-read-subject-cap":
                EnsurePendingCap(host, 4, SimulationFixture.Subject);
                break;
            case "pending-read-global-cap":
                EnsurePendingGlobalCap(host);
                break;
            case "challenge-subject-cap":
                EnsureChallengeCap(host, 4, false);
                break;
            case "challenge-global-cap":
                EnsureChallengeCap(host, 128, true);
                break;
            case "endpoint-channel-boundaries":
                EnsureEndpointChannelBoundaries(host);
                break;
            case "held-flow-entry-boundaries":
                EnsureHeldFlowBoundaries();
                break;
            case "held-data-flow-cap":
                EnsureHeldByteCap();
                break;
            case "held-data-global-cap":
                EnsureGlobalByteCap();
                break;
            case "scheduler-cap":
                EnsureSchedulerBoundaries(host);
                break;
            case "fault-plan-cap":
                EnsureFaultPlanCap(host);
                break;
            case "pump-dispatch-budget":
                EnsurePumpBudget(host);
                break;
            case "ticket-replay-through-endpoint":
                EnsureReplay(host);
                break;
            case "ticket-capacity-through-endpoint":
                EnsureTicketCapacityThroughEndpoint(host);
                break;
            case "grant-expiry-and-byte-count":
                EnsureGrantExpiryAndByteCount(host);
                break;
            case "policy-change-cleans-endpoints":
                EnsurePolicyCleanup(host);
                break;
            case "privacy-metadata-only":
                EnsurePrivacy();
                break;
            case "no-wall-clock-or-event-workers":
                EnsureNoWorkersAndConcurrentEntry(host);
                break;
            case "all-faults-finish-zero-owned-state":
                EnsureAllFaultClasses(host);
                break;
            default:
                throw new TestFailureException($"Unknown scenario {name}.");
        }
    }

    private static (Guid OperationId, SimulationStepResult Flow, SimulationStepResult Decision) PrepareTicket(
        OutboundGateSimulatorHost host,
        TransportProtocol protocol,
        int sequence = 1,
        GateSubject? subject = null)
    {
        var operationId = SimulationFixture.Id(10_000 + sequence);
        var selectedSubject = subject ?? SimulationFixture.Subject;
        var read = host.SubmitRead(SimulationFixture.Read(operationId, selectedSubject, sequence));
        Ensure(read.ReasonCode == "sim-read-completion-accepted", "read did not complete after the matching Ack");
        Ensure(host.TryGetIntentId(operationId, out var intentId), "intent was not retained for the flow");
        var flow = host.SubmitFlow(SimulationFixture.Flow(operationId, intentId, subject: selectedSubject, protocol: protocol));
        Ensure(flow.ReasonCode == "sim-challenge-created", "new flow was not challenged");
        Ensure(flow.CoreResult?.Challenge is { } challenge
            && challenge.IntentId == intentId
            && challenge.Subject.Matches(selectedSubject)
            && challenge.Destination == SimulationFixture.Destination(protocol)
            && challenge.FlowGeneration == 1,
            "challenge did not preserve exact flow binding");
        Ensure(host.TryGetChallengeId(operationId, out var challengeId), "challenge was not retained");
        var decision = host.SubmitDecision(SimulationFixture.Decision(challengeId, sequence: sequence));
        Ensure(decision.Ticket is not null, "AllowOnce did not create a ticket");
        return (operationId, flow, decision);
    }

    private static SimulationStepResult RunHappy(OutboundGateSimulatorHost host, TransportProtocol protocol, int sequence = 1)
    {
        var prepared = PrepareTicket(host, protocol, sequence);
        var redeemed = host.Redeem(prepared.Decision.Ticket!);
        Ensure(redeemed.Grant is not null && host.Snapshot.HeldFlowCount == 0, "grant did not release the held flow");
        return redeemed;
    }

    private static void EnsureHappyPath(OutboundGateSimulatorHost host, TransportProtocol protocol)
    {
        var result = RunHappy(host, protocol);
        Ensure(result.Outcome == SimulatedFlowOutcome.Granted, "happy path did not grant");
        var snapshot = host.Snapshot;
        Ensure(snapshot.AcceptedReadCount == 1 && snapshot.ReleasedReadCount == 1, "happy read counters were not exact");
        Ensure(snapshot.AcceptedFlowCount == 1 && snapshot.ReleasedFlowCount == 1, "happy flow counters were not exact");
        Ensure(snapshot.InstalledGrantCount == 1 && snapshot.ActiveGrantReservationCount == 1, "grant authority was not installed exactly once");
    }

    private static void EnsureCoverageFault(OutboundGateSimulatorHost host, SimulationFaultKind kind, string simulatorReason)
    {
        Ensure(host.Inject(new SimulationFault(kind, SimulationEnvelopeKind.GateArmAck)).ReasonCode == "sim-fault-planned", "coverage fault was not planned");
        var result = host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(kind == SimulationFaultKind.PartialCoverage ? 20_001 : 20_002)));
        Ensure(result.Outcome == SimulatedFlowOutcome.FailedOpen && result.ReasonCode == "gate-ack-invalid-or-expired", "coverage fault did not fail open through Core");
        Ensure(host.Alerts.Any(alert => alert.ReasonCode == simulatorReason), "coverage fault omitted simulator-specific evidence");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureStaleGeneration(OutboundGateSimulatorHost host, SimulationEnvelopeKind kind, string simulatorReason)
    {
        var oldGeneration = kind == SimulationEnvelopeKind.GateArmAck ? host.Snapshot.WfpGeneration : host.Snapshot.MinifilterGeneration;
        host.Inject(new SimulationFault(SimulationFaultKind.StaleGeneration, kind));
        var result = host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(kind == SimulationEnvelopeKind.GateArmAck ? 21_001 : 21_002)));
        var expectedCoreReason = kind == SimulationEnvelopeKind.GateArmAck ? "gate-ack-invalid-or-expired" : "completion-binding-or-generation-invalid";
        Ensure(result.Outcome == SimulatedFlowOutcome.FailedOpen && result.ReasonCode == expectedCoreReason, "stale generation did not fail open with the stable Core reason");
        Ensure(host.Alerts.Any(alert => alert.ReasonCode == simulatorReason), "stale generation omitted simulator-specific evidence");
        var current = kind == SimulationEnvelopeKind.GateArmAck ? host.Snapshot.WfpGeneration : host.Snapshot.MinifilterGeneration;
        Ensure(current == oldGeneration, "rejected stale contract changed the trusted current generation");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureTransportRules(OutboundGateSimulatorHost host, SimulatedTransportKind transport, TransportProtocol protocol, string reason)
    {
        var operationId = SimulationFixture.Id(22_000 + (int)transport);
        var result = host.SubmitFlow(SimulationFixture.Flow(operationId, SimulationFixture.Id(22_100 + (int)transport), protocol: protocol, shape: SimulatedFlowShape.ExistingMultiplexed, transport: transport));
        Ensure(result.Outcome == SimulatedFlowOutcome.ReconnectRequired && result.ReasonCode == reason, "existing flow returned the wrong reconnect result");
        var mismatchProtocol = protocol == TransportProtocol.Tcp ? TransportProtocol.Udp : TransportProtocol.Tcp;
        var mismatch = host.SubmitFlow(SimulationFixture.Flow(SimulationFixture.Id(22_200 + (int)transport), SimulationFixture.Id(22_300 + (int)transport), protocol: mismatchProtocol, shape: SimulatedFlowShape.ExistingMultiplexed, transport: transport));
        Ensure(mismatch.Outcome == SimulatedFlowOutcome.FailedOpen && mismatch.ReasonCode == "sim-transport-protocol-mismatch", "existing transport mismatch used a reconnect reason");
        if (transport == SimulatedTransportKind.Quic)
        {
            var newQuic = host.SubmitFlow(SimulationFixture.Flow(SimulationFixture.Id(22_400), SimulationFixture.Id(22_401), protocol: TransportProtocol.Udp, transport: SimulatedTransportKind.Quic));
            Ensure(newQuic.Outcome == SimulatedFlowOutcome.FailedOpen && newQuic.ReasonCode == "sim-new-quic-unsupported", "new QUIC was not rejected clearly");
        }
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureDelayCoverage(OutboundGateSimulatorHost host, bool timeout, long afterDeadlineMilliseconds = 0)
    {
        var readStages = new[]
        {
            SimulationEnvelopeKind.GateArmRequest,
            SimulationEnvelopeKind.GateArmAck,
            SimulationEnvelopeKind.FileReadDisposition,
            SimulationEnvelopeKind.FileReadCompletionAck
        };
        for (var index = 0; index < readStages.Length; index++)
        {
            using var owned = index == 0 ? null : new OutboundGateSimulatorHost(true);
            var selected = owned ?? host;
            EnsureReadDelay(selected, readStages[index], timeout, 23_000 + index, afterDeadlineMilliseconds);
        }
        using var challengeHost = new OutboundGateSimulatorHost(true);
        EnsureChallengeDelay(challengeHost, timeout, afterDeadlineMilliseconds);
    }

    private static void EnsureReadDelay(OutboundGateSimulatorHost host, SimulationEnvelopeKind kind, bool timeout, int identifier, long afterDeadlineMilliseconds)
    {
        var delay = timeout ? checked(2_000L + afterDeadlineMilliseconds) : 500L;
        host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, kind, delayMilliseconds: delay));
        host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(identifier)));
        Ensure(host.Snapshot.ScheduledCount == 1 && host.Snapshot.CoreActiveContextCount == 1, $"{kind} delay did not retain one scheduled Core operation");
        if (timeout)
        {
            host.AdvanceBy(2_000);
            Ensure(host.Snapshot.FailedOpenOperationCount == 1 && host.Snapshot.CriticalAlertCount > 0, $"{kind} deadline omitted fail-open counters or Critical Alert");
            EnsureZeroOwnedState(host, authorityMustBeZero: true);
        }
        else
        {
            host.AdvanceBy(499);
            Ensure(host.Snapshot.ScheduledCount == 1, $"{kind} dispatched before its manual due time");
            host.AdvanceBy(1);
            Ensure(host.Snapshot.ScheduledCount == 0 && host.Snapshot.CoreActiveContextCount == 1, $"{kind} did not dispatch at manual due time");
        }
    }

    private static void EnsureChallengeDelay(OutboundGateSimulatorHost host, bool timeout, long afterDeadlineMilliseconds)
    {
        var operationId = SimulationFixture.Id(timeout ? 23_101 : 23_100);
        host.SubmitRead(SimulationFixture.Read(operationId));
        Ensure(host.TryGetIntentId(operationId, out var intentId), "challenge-delay intent missing");
        host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.NetworkGateChallenge, delayMilliseconds: timeout ? checked(15_000 + afterDeadlineMilliseconds) : 500));
        host.SubmitFlow(SimulationFixture.Flow(operationId, intentId));
        Ensure(host.Snapshot.ScheduledCount == 1 && host.Snapshot.HeldFlowCount == 1, "challenge delay did not retain its held owner");
        if (timeout)
        {
            host.AdvanceBy(15_000);
            Ensure(host.Snapshot.FailedOpenOperationCount == 1 && host.Snapshot.CriticalAlertCount > 0, "challenge deadline omitted fail-open counters or Critical Alert");
            EnsureZeroOwnedState(host, authorityMustBeZero: true);
        }
        else
        {
            host.AdvanceBy(499);
            Ensure(host.Snapshot.ActiveChallengeCount == 0, "challenge dispatched early");
            host.AdvanceBy(1);
            Ensure(host.Snapshot.ActiveChallengeCount == 1 && host.Snapshot.ScheduledCount == 0, "challenge did not dispatch at due time");
        }
    }

    private static void EnsureDropCoverage(OutboundGateSimulatorHost host)
    {
        var stages = new[]
        {
            SimulationEnvelopeKind.GateArmRequest,
            SimulationEnvelopeKind.GateArmAck,
            SimulationEnvelopeKind.FileReadDisposition,
            SimulationEnvelopeKind.FileReadCompletionAck
        };
        for (var index = 0; index < stages.Length; index++)
        {
            using var owned = index == 0 ? null : new OutboundGateSimulatorHost(true);
            var selected = owned ?? host;
            selected.Inject(new SimulationFault(SimulationFaultKind.DropNext, stages[index]));
            selected.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(24_000 + index)));
            Ensure(selected.Snapshot.DroppedEnvelopeCount == 1, $"{stages[index]} was not dropped exactly once");
            selected.AdvanceBy(2_000);
            Ensure(selected.Snapshot.FailedOpenOperationCount == 1 && selected.Snapshot.CriticalAlertCount > 0, $"{stages[index]} drop omitted fail-open counters or Critical Alert");
            EnsureZeroOwnedState(selected, authorityMustBeZero: true);
        }
        using var challengeHost = new OutboundGateSimulatorHost(true);
        var operationId = SimulationFixture.Id(24_100);
        challengeHost.SubmitRead(SimulationFixture.Read(operationId));
        Ensure(challengeHost.TryGetIntentId(operationId, out var intentId), "drop challenge intent missing");
        challengeHost.Inject(new SimulationFault(SimulationFaultKind.DropNext, SimulationEnvelopeKind.NetworkGateChallenge));
        challengeHost.SubmitFlow(SimulationFixture.Flow(operationId, intentId));
        Ensure(challengeHost.Snapshot.DroppedEnvelopeCount == 1, "challenge was not dropped exactly once");
        challengeHost.AdvanceBy(15_000);
        Ensure(challengeHost.Snapshot.FailedOpenOperationCount == 1 && challengeHost.Snapshot.CriticalAlertCount > 0, "challenge drop omitted fail-open counters or Critical Alert");
        EnsureZeroOwnedState(challengeHost, authorityMustBeZero: true);
    }

    private static void EnsureDispositionAndCompletionBinding(OutboundGateSimulatorHost host)
    {
        var operationId = SimulationFixture.Id(25_000);
        var intentId = SimulationFixture.Id(25_001);
        var ackId = SimulationFixture.Id(25_002);
        var generation = SimulationFixture.Id(25_003);
        var otherProcess = new ProcessIdentity(43, SimulationFixture.Start);
        var otherFile = new FileVersionIdentity(1, "volume-1", "file-43", SimulationFixture.Start, 1024, SimulationFixture.Start.AddMinutes(1), SimulationFixture.Start.AddMinutes(2), 43, "version-token-2");
        var clock = new ManualSimulationClock(SimulationFixture.Id(25_004), SimulationFixture.Start);
        var window = Window(clock, 2_000);
        var endpoint = new FakeMinifilterEndpoint(generation);
        Ensure(endpoint.TryPendRead(SimulationFixture.Read(operationId)).ReasonCode == "sim-read-pended", "binding fixture was not pended");
        var expected = Disposition(intentId, SimulationFixture.Process, SimulationFixture.File, FileReadDispositionKind.ReleaseAfterGateArmed, ackId, window, "gate-armed", 7);
        Ensure(endpoint.BindDisposition(operationId, expected), "expected disposition was not bound");

        var mismatches = new[]
        {
            Disposition(SimulationFixture.Id(25_010), SimulationFixture.Process, SimulationFixture.File, FileReadDispositionKind.ReleaseAfterGateArmed, ackId, window, "gate-armed", 7),
            Disposition(intentId, otherProcess, SimulationFixture.File, FileReadDispositionKind.ReleaseAfterGateArmed, ackId, window, "gate-armed", 7),
            Disposition(intentId, SimulationFixture.Process, otherFile, FileReadDispositionKind.ReleaseAfterGateArmed, ackId, window, "gate-armed", 7),
            Disposition(intentId, SimulationFixture.Process, SimulationFixture.File, FileReadDispositionKind.ReleaseAfterGateArmed, SimulationFixture.Id(25_011), window, "gate-armed", 7),
            Disposition(intentId, SimulationFixture.Process, SimulationFixture.File, FileReadDispositionKind.FailOpenRelease, null, window, "gate-armed", 7),
            Disposition(intentId, SimulationFixture.Process, SimulationFixture.File, FileReadDispositionKind.ReleaseAfterGateArmed, ackId, window, "gate-armed", 8)
        };
        foreach (var mismatch in mismatches)
        {
            var rejected = endpoint.AcceptDisposition(mismatch);
            Ensure(rejected.Outcome == SimulatedFlowOutcome.FailedOpen && rejected.ReasonCode == "sim-read-disposition-mismatch", "mismatched disposition was accepted");
            Ensure(endpoint.Snapshot.PendingCount == 1, "mismatched disposition released the read");
        }
        var released = endpoint.AcceptDisposition(expected);
        Ensure(released.ReasonCode == "sim-read-released" && !released.IsDuplicate && endpoint.Snapshot.PendingCount == 0, "matching disposition did not release exactly once");
        var duplicate = endpoint.AcceptDisposition(expected);
        Ensure(duplicate.ReasonCode == "sim-read-released" && duplicate.IsDuplicate && endpoint.Snapshot.PendingCount == 0, "duplicate disposition was not idempotent");

        var nonces = new DeterministicNonceProvider();
        var completion = FakeMinifilterEndpoint.CreateCompletion(expected, generation, nonces, expected.Sequence);
        Ensure(completion.IsBoundTo(expected, generation), "matching completion did not bind");
        var completionMismatches = new[]
        {
            Completion(expected, generation, intentId: SimulationFixture.Id(25_020)),
            Completion(expected, generation, process: otherProcess),
            Completion(expected, generation, file: otherFile),
            Completion(expected, generation, dispositionSequence: 8),
            Completion(expected, generation, disposition: FileReadDispositionKind.FailOpenRelease, omitGateAck: true, result: FileReadCompletionResult.FailedOpen),
            Completion(expected, generation, gateAckId: SimulationFixture.Id(25_021)),
            Completion(expected, SimulationFixture.Id(25_022))
        };
        Ensure(completionMismatches.All(item => !item.IsBoundTo(expected, generation)), "mismatched completion passed exact binding");

        var normal = host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(25_100)));
        Ensure(normal.ReasonCode == "sim-read-completion-accepted", "normal completion was not accepted");
        Ensure(host.Snapshot.AcceptedReadCount == 1 && host.Snapshot.ReleasedReadCount == 1, "normal completion released more than once");
    }

    private static void EnsureEndpointRestart(OutboundGateSimulatorHost host, bool minifilter)
    {
        var operationId = SimulationFixture.Id(minifilter ? 26_001 : 26_002);
        if (minifilter)
        {
            host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 5_000));
            host.SubmitRead(SimulationFixture.Read(operationId));
        }
        else
        {
            host.SubmitRead(SimulationFixture.Read(operationId));
            Ensure(host.TryGetIntentId(operationId, out var intentId), "WFP crash fixture intent missing");
            host.SubmitFlow(SimulationFixture.Flow(operationId, intentId));
            Ensure(host.Snapshot.HeldFlowCount == 1, "WFP crash fixture did not hold a flow");
        }

        var seen = new HashSet<Guid> { minifilter ? host.Snapshot.MinifilterGeneration : host.Snapshot.WfpGeneration };
        var crash = host.Inject(new SimulationFault(minifilter ? SimulationFaultKind.MinifilterCrash : SimulationFaultKind.WfpCrash));
        Ensure(crash.Outcome == SimulatedFlowOutcome.FailedOpen, "endpoint crash did not fail open");
        var afterCrash = minifilter ? host.Snapshot.MinifilterGeneration : host.Snapshot.WfpGeneration;
        Ensure(seen.Add(afterCrash), "endpoint crash reused a generation");
        for (var index = 0; index < 8; index++)
        {
            host.Inject(new SimulationFault(minifilter ? SimulationFaultKind.MinifilterRestart : SimulationFaultKind.WfpRestart));
            var current = minifilter ? host.Snapshot.MinifilterGeneration : host.Snapshot.WfpGeneration;
            Ensure(seen.Add(current), "endpoint restart reused a prior generation");
        }
        var snapshot = host.Snapshot;
        Ensure((minifilter ? snapshot.MinifilterCrashCount : snapshot.WfpCrashCount) == 1, "endpoint crash counter was not exact");
        Ensure((minifilter ? snapshot.MinifilterRestartCount : snapshot.WfpRestartCount) == 8, "endpoint restart counter was not exact");
        Ensure(snapshot.CriticalAlertCount > 0, "endpoint restart omitted Critical Alert");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureServiceRestart(OutboundGateSimulatorHost host)
    {
        RunHappy(host, TransportProtocol.Tcp);
        Ensure(host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 1_000)).ReasonCode == "sim-fault-planned", "restart fixture delivery fault was not planned");
        Ensure(host.Inject(new SimulationFault(SimulationFaultKind.PartialCoverage, SimulationEnvelopeKind.GateArmAck)).ReasonCode == "sim-fault-planned", "restart fixture mutation fault was not planned");
        Ensure(host.Snapshot.FaultPlanCount == 2, "restart fixture did not retain both planned faults");
        var seen = new HashSet<Guid>();
        for (var index = 0; index < 8; index++)
        {
            var before = host.Snapshot;
            Ensure(seen.Add(before.BootInstance) && seen.Add(before.Now.ClockInstanceId) && seen.Add(before.WfpGeneration) && seen.Add(before.MinifilterGeneration), "generation domains collided or reused before restart");
            host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
            if (index == 0)
            {
                Ensure(host.Snapshot.FaultPlanCount == 0, "service restart retained an old fault plan");
                var newGenerationWork = host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(26_100), sequence: 2));
                Ensure(newGenerationWork.ReasonCode == "sim-read-completion-accepted", "pre-restart fault affected new-generation work");
                Ensure(host.Snapshot.FaultPlanCount == 0, "new-generation work revived an old fault plan");
            }
        }
        var final = host.Snapshot;
        Ensure(seen.Add(final.BootInstance) && seen.Add(final.Now.ClockInstanceId) && seen.Add(final.WfpGeneration) && seen.Add(final.MinifilterGeneration), "service restart reused an old generation");
        Ensure(final.ServiceRestartCount == 8 && final.CriticalAlertCount >= 8 && final.FaultPlanCount == 0, "service restart counters or fault cleanup were not exact");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsurePendingCap(OutboundGateSimulatorHost host, int capacity, GateSubject subject)
    {
        for (var index = 0; index < capacity; index++)
        {
            host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 10_000));
            host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(27_000 + index), subject, index + 1));
        }
        Ensure(host.Snapshot.PendingReadCount == capacity && host.Snapshot.CoreActiveContextCount == capacity, "pending subject cap was not reached exactly");
        var overflow = host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(27_100), subject, capacity + 1));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-pending-read-capacity-exhausted" && host.Snapshot.PendingReadCount == capacity, "pre-admission subject overflow changed live state");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsurePendingGlobalCap(OutboundGateSimulatorHost host)
    {
        for (var index = 0; index < 64; index++)
        {
            var process = new ProcessIdentity(10_000 + index, SimulationFixture.Start);
            var subject = new GateSubject(1, process, $"sha256:pending-{index}", null, [process]);
            host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 10_000));
            host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(28_000 + index), subject, index + 1));
        }
        Ensure(host.Snapshot.PendingReadCount == 64 && host.Snapshot.CoreActiveContextCount == 64, "pending global cap was not reached exactly");
        var overflowProcess = new ProcessIdentity(20_000, SimulationFixture.Start);
        var overflowSubject = new GateSubject(1, overflowProcess, "sha256:pending-overflow", null, [overflowProcess]);
        var overflow = host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(28_100), overflowSubject, 65));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-pending-read-capacity-exhausted" && host.Snapshot.PendingReadCount == 64, "pre-admission global overflow changed live state");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureChallengeCap(OutboundGateSimulatorHost host, int capacity, bool global)
    {
        for (var index = 0; index < capacity; index++)
        {
            var subject = global ? NewSubject(index + 1000) : SimulationFixture.Subject;
            var operationId = SimulationFixture.Id(29_000 + index);
            host.SubmitRead(SimulationFixture.Read(operationId, subject, index + 1));
            Ensure(host.TryGetIntentId(operationId, out var intentId), "challenge setup intent missing");
            host.SubmitFlow(SimulationFixture.Flow(operationId, intentId, subject: subject));
        }
        var beforeOverflow = host.Snapshot;
        Ensure(beforeOverflow.ActiveChallengeCount == capacity
            && beforeOverflow.HeldFlowCount == capacity
            && beforeOverflow.CoreActiveContextCount == capacity
            && beforeOverflow.ChallengeCreatedCount == capacity
            && beforeOverflow.ChallengeDeliveredCount == capacity,
            "challenge cap was not reached exactly");
        var subjectForOverflow = global ? NewSubject(20_000) : SimulationFixture.Subject;
        var operation = SimulationFixture.Id(29_500);
        host.SubmitRead(SimulationFixture.Read(operation, subjectForOverflow, capacity + 1));
        Ensure(host.TryGetIntentId(operation, out var overflowIntent), "challenge overflow setup intent missing");
        var overflow = host.SubmitFlow(SimulationFixture.Flow(operation, overflowIntent, subject: subjectForOverflow));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-held-flow-capacity-exhausted", "challenge overflow returned the wrong stable reason");
        Ensure(overflow.CoreResult?.Status.ReasonCode == "challenge-admission-held-flow-capacity-exhausted"
            && overflow.CoreResult.Status.State == GateRuntimeState.FailedOpen
            && overflow.CoreResult.Challenge is null
            && overflow.CoreResult.Ticket is null
            && overflow.CoreResult.Grant is null,
            "challenge overflow did not use the targeted pre-challenge Core failure");
        var atCapacity = host.Snapshot;
        Ensure(atCapacity.ActiveChallengeCount == capacity
            && atCapacity.HeldFlowCount == capacity
            && atCapacity.CoreActiveContextCount == capacity
            && atCapacity.AcceptedReadCount == capacity + 1
            && atCapacity.ReleasedReadCount == capacity + 1
            && atCapacity.AcceptedFlowCount == capacity
            && atCapacity.ReleasedFlowCount == 0
            && atCapacity.ChallengeCreatedCount == beforeOverflow.ChallengeCreatedCount
            && atCapacity.ChallengeDeliveredCount == beforeOverflow.ChallengeDeliveredCount
            && atCapacity.OverflowCount == 1
            && atCapacity.FailedOpenOperationCount == 1
            && atCapacity.CoreAlertCount == 1
            && atCapacity.CriticalAlertCount == 2
            && atCapacity.WfpGeneration == beforeOverflow.WfpGeneration
            && atCapacity.MinifilterGeneration == beforeOverflow.MinifilterGeneration
            && atCapacity.ServiceRestartCount == 0,
            "challenge cap+1 did not preserve all prior live entries and exact counters");
        Ensure(!host.TryGetIntentId(operation, out _), "rejected challenge-cap operation retained host authority");
        Ensure(!host.TryGetChallengeId(operation, out _), "WFP-rejected operation created a challenge identity");
        Ensure(!host.TryGetTicket(operation, out _)
            && atCapacity.OutstandingTicketCount == 0
            && atCapacity.ActiveGrantReservationCount == 0
            && atCapacity.InstalledGrantCount == 0,
            "WFP-rejected operation created ticket or grant authority");
        var replay = host.SubmitFlow(SimulationFixture.Flow(operation, overflowIntent, subject: subjectForOverflow));
        Ensure(replay.Outcome == SimulatedFlowOutcome.FailedOpen && replay.ReasonCode == "sim-flow-intent-not-found", "rejected challenge-cap operation could be submitted again");
        Ensure(host.Snapshot.ActiveChallengeCount == capacity
            && host.Snapshot.HeldFlowCount == capacity
            && host.Snapshot.ChallengeCreatedCount == capacity
            && host.Snapshot.ChallengeDeliveredCount == capacity
            && host.Snapshot.OverflowCount == 1,
            "rejected operation retry changed prior live state");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        Ensure(host.Snapshot.AcceptedReadCount == host.Snapshot.ReleasedReadCount && host.Snapshot.AcceptedFlowCount == host.Snapshot.ReleasedFlowCount, "challenge cleanup counters did not balance");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureEndpointChannelBoundaries(OutboundGateSimulatorHost host)
    {
        var clock = new ManualSimulationClock(SimulationFixture.Id(30_000), SimulationFixture.Start);
        var nonces = new DeterministicNonceProvider();
        var generation = SimulationFixture.Id(30_001);
        var request = ArmRequest(clock, SimulationFixture.Id(30_002), generation);
        var wfpForAck = new FakeWfpEndpoint(() => generation, nonces, clock);
        var ack = wfpForAck.CreateAck(request, request.RequiredCoverage, null, generation);
        var disposition = Disposition(request.IntentId, SimulationFixture.Process, SimulationFixture.File, FileReadDispositionKind.ReleaseAfterGateArmed, ack.AckId, request.ArmWindow, "gate-armed", 1);
        var completion = FakeMinifilterEndpoint.CreateCompletion(disposition, generation, nonces, 1);
        var challenge = Challenge(clock, request.IntentId, SimulationFixture.Id(30_003));
        var flow = SimulationFixture.Flow(SimulationFixture.Id(30_004), request.IntentId);
        var intent = new FileReadIntent(1, request.IntentId, SimulationFixture.Subject, SimulationFixture.File, FileActivityOperation.Read, SimulationFixture.Start, request.ArmWindow, SimulationFixture.Id(30_005), 1);

        var minifilterIntent = new FakeMinifilterEndpoint(generation);
        Fill(FakeMinifilterEndpoint.IntentOutboxCapacity, () => minifilterIntent.TryEnqueueIntent(intent), "minifilter intent outbox");
        Ensure(!minifilterIntent.TryEnqueueIntent(intent) && minifilterIntent.Snapshot.IntentOutboxCount == FakeMinifilterEndpoint.IntentOutboxCapacity, "minifilter intent outbox exceeded cap");
        var minifilterDisposition = new FakeMinifilterEndpoint(generation);
        Fill(FakeMinifilterEndpoint.DispositionInboxCapacity, () => minifilterDisposition.TryEnqueueDisposition(disposition), "minifilter disposition inbox");
        Ensure(minifilterDisposition.AcceptDisposition(disposition).ReasonCode == "sim-minifilter-channel-capacity-exhausted", "minifilter disposition inbox did not reject at cap");
        var minifilterCompletion = new FakeMinifilterEndpoint(generation);
        Fill(FakeMinifilterEndpoint.CompletionAckOutboxCapacity, () => minifilterCompletion.TryEnqueueCompletion(completion), "minifilter completion outbox");
        Ensure(!minifilterCompletion.TryEnqueueCompletion(completion), "minifilter completion outbox exceeded cap");

        var wfpArm = new FakeWfpEndpoint(() => generation, nonces, clock);
        Fill(FakeWfpEndpoint.ArmChannelCapacity, () => wfpArm.TryEnqueueArmRequest(request), "WFP arm inbox");
        Ensure(wfpArm.AcceptArmRequest(request).ReasonCode == "sim-wfp-channel-capacity-exhausted", "WFP arm inbox did not reject at cap");
        var wfpAck = new FakeWfpEndpoint(() => generation, nonces, clock);
        Fill(FakeWfpEndpoint.GateAckOutboxCapacity, () => wfpAck.TryEnqueueArmAck(ack), "WFP Ack outbox");
        Ensure(!wfpAck.TryEnqueueArmAck(ack), "WFP Ack outbox exceeded cap");
        var wfpFlow = new FakeWfpEndpoint(() => generation, nonces, clock);
        Fill(FakeWfpEndpoint.FlowChannelCapacity, () => wfpFlow.TryEnqueueFlowObservation(flow), "WFP flow inbox");
        Ensure(!wfpFlow.TryEnqueueFlowObservation(flow), "WFP flow inbox exceeded cap");
        var wfpChallenge = new FakeWfpEndpoint(() => generation, nonces, clock);
        Fill(FakeWfpEndpoint.ChallengeOutboxCapacity, () => wfpChallenge.TryEnqueueChallenge(challenge), "WFP challenge outbox");
        Ensure(!wfpChallenge.TryEnqueueChallenge(challenge), "WFP challenge outbox exceeded cap");

        Ensure(minifilterIntent.Snapshot.IntentOutboxCount == 64
            && minifilterDisposition.Snapshot.DispositionInboxCount == 64
            && minifilterCompletion.Snapshot.CompletionAckOutboxCount == 64
            && wfpArm.Snapshot.GateArmInboxCount == 64
            && wfpAck.Snapshot.GateAckOutboxCount == 64
            && wfpFlow.Snapshot.FlowObservationInboxCount == 128
            && wfpChallenge.Snapshot.ChallengeOutboxCount == 128,
            "endpoint snapshots did not expose exact channel boundaries");
        minifilterIntent.ReleaseAll();
        minifilterDisposition.ReleaseAll();
        minifilterCompletion.ReleaseAll();
        wfpForAck.ReleaseAll();
        wfpArm.ReleaseAll();
        wfpAck.ReleaseAll();
        wfpFlow.ReleaseAll();
        wfpChallenge.ReleaseAll();
        Ensure(minifilterIntent.Snapshot.IntentOutboxCount == 0
            && minifilterDisposition.Snapshot.DispositionInboxCount == 0
            && minifilterCompletion.Snapshot.CompletionAckOutboxCount == 0
            && wfpArm.Snapshot.GateArmInboxCount == 0
            && wfpAck.Snapshot.GateAckOutboxCount == 0
            && wfpFlow.Snapshot.FlowObservationInboxCount == 0
            && wfpChallenge.Snapshot.ChallengeOutboxCount == 0,
            "direct endpoint channel cleanup retained state");

        var minifilterOverflow = host.RunEndpointChannelCapacityForAcceptance(minifilter: true);
        Ensure(minifilterOverflow.Outcome == SimulatedFlowOutcome.FailedOpen && minifilterOverflow.ReasonCode == "sim-minifilter-channel-capacity-exhausted", "host minifilter channel overflow returned the wrong reason");
        Ensure(host.Snapshot.MinifilterIntentOutboxCount == 64 && host.Snapshot.OverflowCount == 1 && host.Snapshot.CriticalAlertCount > 0, "host minifilter channel overflow evicted entries or omitted evidence");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(host, authorityMustBeZero: true);

        using var wfpHost = new OutboundGateSimulatorHost(true);
        var wfpOverflow = wfpHost.RunEndpointChannelCapacityForAcceptance(minifilter: false);
        Ensure(wfpOverflow.Outcome == SimulatedFlowOutcome.FailedOpen && wfpOverflow.ReasonCode == "sim-wfp-channel-capacity-exhausted", "host WFP channel overflow returned the wrong reason");
        Ensure(wfpHost.Snapshot.WfpGateArmInboxCount == 64 && wfpHost.Snapshot.OverflowCount == 1 && wfpHost.Snapshot.CriticalAlertCount > 0, "host WFP channel overflow evicted entries or omitted evidence");
        wfpHost.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(wfpHost, authorityMustBeZero: true);
    }

    private static void EnsureHeldFlowBoundaries()
    {
        var subjectEndpoint = WfpFixture(out _);
        for (var index = 0; index < FakeWfpEndpoint.HeldSubjectCapacity; index++)
            Ensure(subjectEndpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(31_000 + index), SimulationFixture.Id(31_100 + index))).ReasonCode == "sim-held-flow-reserved", "held subject entry rejected before cap");
        var subjectOverflow = subjectEndpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(31_010), SimulationFixture.Id(31_110)));
        Ensure(subjectOverflow.ReasonCode == "sim-held-flow-capacity-exhausted" && subjectEndpoint.Snapshot.HeldFlowCount == FakeWfpEndpoint.HeldSubjectCapacity, "held subject map exceeded cap");

        var globalEndpoint = WfpFixture(out _);
        for (var index = 0; index < FakeWfpEndpoint.HeldFlowCapacity; index++)
        {
            var subject = NewSubject(31_500 + index);
            Ensure(globalEndpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(32_000 + index), SimulationFixture.Id(32_500 + index), subject: subject)).ReasonCode == "sim-held-flow-reserved", "held global entry rejected before cap");
        }
        var overflowSubject = NewSubject(32_999);
        var globalOverflow = globalEndpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(32_999), SimulationFixture.Id(33_000), subject: overflowSubject));
        Ensure(globalOverflow.ReasonCode == "sim-held-flow-capacity-exhausted" && globalEndpoint.Snapshot.HeldFlowCount == FakeWfpEndpoint.HeldFlowCapacity, "held global map exceeded cap");
        globalEndpoint.ReleaseAll();
        subjectEndpoint.ReleaseAll();
        Ensure(globalEndpoint.Snapshot.HeldFlowCount == 0 && subjectEndpoint.Snapshot.HeldFlowCount == 0, "held map cleanup was incomplete");
    }

    private static void EnsureHeldByteCap()
    {
        var endpoint = WfpFixture(out _);
        var overflow = endpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(33_100), SimulationFixture.Id(33_101), bytes: FakeWfpEndpoint.FlowByteCapacity + 1));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-held-data-flow-capacity-exhausted" && endpoint.Snapshot.HeldByteCount == 0, "per-flow byte cap was exceeded");
        var exact = endpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(33_102), SimulationFixture.Id(33_103), bytes: FakeWfpEndpoint.FlowByteCapacity));
        Ensure(exact.ReasonCode == "sim-held-flow-reserved" && endpoint.Snapshot.HeldByteCount == FakeWfpEndpoint.FlowByteCapacity, "exact per-flow byte cap was not accepted");
        endpoint.ReleaseAll();
        Ensure(endpoint.Snapshot.HeldFlowCount == 0 && endpoint.Snapshot.HeldByteCount == 0, "per-flow byte fixture did not clean held state");
    }

    private static void EnsureGlobalByteCap()
    {
        var endpoint = WfpFixture(out _);
        for (var index = 0; index < 16; index++)
        {
            var subject = NewSubject(34_000 + index);
            var result = endpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(34_100 + index), SimulationFixture.Id(34_200 + index), subject: subject, bytes: FakeWfpEndpoint.FlowByteCapacity));
            Ensure(result.ReasonCode == "sim-held-flow-reserved", "global bytes rejected before exact cap");
        }
        Ensure(endpoint.Snapshot.HeldByteCount == FakeWfpEndpoint.GlobalByteCapacity, "global bytes did not reach exact cap");
        var overflowSubject = NewSubject(34_999);
        var overflow = endpoint.ObserveFlow(SimulationFixture.Flow(SimulationFixture.Id(34_999), SimulationFixture.Id(35_000), subject: overflowSubject, bytes: 1));
        Ensure(overflow.ReasonCode == "sim-held-data-global-capacity-exhausted" && endpoint.Snapshot.HeldByteCount == FakeWfpEndpoint.GlobalByteCapacity, "global byte cap was exceeded");
        endpoint.ReleaseAll();
        Ensure(endpoint.Snapshot.HeldFlowCount == 0 && endpoint.Snapshot.HeldByteCount == 0, "global byte fixture did not clean held state");
    }

    private static void EnsureSchedulerBoundaries(OutboundGateSimulatorHost host)
    {
        var clock = new ManualSimulationClock(SimulationFixture.Id(35_100), SimulationFixture.Start);
        var scheduler = new DeterministicSimulationScheduler(clock);
        for (var owner = 0; owner < DeterministicSimulationScheduler.OwnerCapacity; owner++)
            for (var eventIndex = 0; eventIndex < 2; eventIndex++)
                Ensure(scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(SimulationFixture.Id(35_200 + owner), 1), 1), "scheduler rejected before 512 events");
        Ensure(scheduler.Count == DeterministicSimulationScheduler.Capacity && scheduler.OwnerCount == DeterministicSimulationScheduler.OwnerCapacity, "scheduler did not expose exact event/owner caps");
        Ensure(!scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(SimulationFixture.Id(35_200), 1), 1), "scheduler accepted event 513");
        scheduler.Clear();
        for (var owner = 0; owner < DeterministicSimulationScheduler.OwnerCapacity; owner++)
            Ensure(scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(SimulationFixture.Id(36_000 + owner), 1), 1), "scheduler owner rejected before cap");
        Ensure(!scheduler.TrySchedule(SimulationEnvelope.ForPumpChain(SimulationFixture.Id(36_999), 1), 1) && scheduler.Count == 256, "scheduler accepted owner 257");
        scheduler.Clear();
        Ensure(scheduler.Count == 0 && scheduler.OwnerCount == 0, "scheduler cleanup retained ownership");

        var eventOverflow = host.RunSchedulerCapacityForAcceptance(ownerCapacity: false);
        Ensure(eventOverflow.Outcome == SimulatedFlowOutcome.FailedOpen && eventOverflow.ReasonCode == "sim-scheduler-capacity-exhausted", "host scheduler event 513 did not fail open");
        var atEventCapacity = host.Snapshot;
        Ensure(atEventCapacity.ScheduledCount == OutboundGateSimulatorHost.SchedulerCapacity
            && atEventCapacity.SchedulerOwnerCount == OutboundGateSimulatorHost.SchedulerOwnerCapacity
            && atEventCapacity.OverflowCount == 1
            && atEventCapacity.CriticalAlertCount > 0,
            "host scheduler event 513 evicted live events or omitted evidence");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        Ensure(host.Snapshot.OverflowCount == 1, "scheduler cleanup changed the event-overflow counter");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);

        using var ownerHost = new OutboundGateSimulatorHost(true);
        var ownerOverflow = ownerHost.RunSchedulerCapacityForAcceptance(ownerCapacity: true);
        Ensure(ownerOverflow.Outcome == SimulatedFlowOutcome.FailedOpen && ownerOverflow.ReasonCode == "sim-scheduler-capacity-exhausted", "host scheduler owner 257 did not fail open");
        var atOwnerCapacity = ownerHost.Snapshot;
        Ensure(atOwnerCapacity.ScheduledCount == OutboundGateSimulatorHost.SchedulerOwnerCapacity
            && atOwnerCapacity.SchedulerOwnerCount == OutboundGateSimulatorHost.SchedulerOwnerCapacity
            && atOwnerCapacity.OverflowCount == 1
            && atOwnerCapacity.CriticalAlertCount > 0,
            "host scheduler owner 257 evicted live owners or omitted evidence");
        ownerHost.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(ownerHost, authorityMustBeZero: true);
    }

    private static void EnsureFaultPlanCap(OutboundGateSimulatorHost host)
    {
        for (var index = 0; index < OutboundGateSimulatorHost.FaultPlanCapacity; index++)
            Ensure(host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest)).ReasonCode == "sim-fault-planned", "fault plan rejected before cap");
        Ensure(host.Snapshot.FaultPlanCount == OutboundGateSimulatorHost.FaultPlanCapacity, "fault plan did not retain entries 1 through 256");
        var overflow = host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-fault-plan-capacity-exhausted", "fault plan entry 257 did not fail open");
        var atCapacity = host.Snapshot;
        Ensure(atCapacity.FaultPlanCount == OutboundGateSimulatorHost.FaultPlanCapacity && atCapacity.OverflowCount == 1 && atCapacity.CriticalAlertCount > 0, "fault plan cap exceeded 256 or omitted exact overflow evidence");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        Ensure(host.Snapshot.FaultPlanCount == 0 && host.Snapshot.OverflowCount == 1, "service restart did not clear the full fault plan while preserving counters");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsurePumpBudget(OutboundGateSimulatorHost host)
    {
        var result = host.RunPumpChainForAcceptance(OutboundGateSimulatorHost.PumpDispatchCapacity + 1);
        Ensure(result.Outcome == SimulatedFlowOutcome.FailedOpen && result.ReasonCode == "sim-pump-budget-exhausted", "pump event 1025 did not fail open");
        var snapshot = host.Snapshot;
        Ensure(snapshot.OverflowCount == 1 && snapshot.ScheduledCount == 0 && snapshot.SchedulerOwnerCount == 0 && snapshot.CriticalAlertCount > 0, "pump overflow did not clean scheduler state exactly");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureTicketCapacityThroughEndpoint(OutboundGateSimulatorHost host)
    {
        var operationId = SimulationFixture.Id(37_000);
        Ensure(host.SubmitRead(SimulationFixture.Read(operationId)).ReasonCode == "sim-read-completion-accepted", "ticket cap fixture read failed");
        Ensure(host.TryGetIntentId(operationId, out var intentId), "ticket cap fixture intent missing");
        Ensure(host.SubmitFlow(SimulationFixture.Flow(operationId, intentId)).ReasonCode == "sim-challenge-created", "ticket cap fixture challenge missing");
        Ensure(host.TryGetChallengeId(operationId, out var challengeId), "ticket cap fixture challenge identity missing");
        var denied = host.SubmitDecision(SimulationFixture.Decision(challengeId, sequence: 37));
        Ensure(denied.Outcome == SimulatedFlowOutcome.FailedOpen && denied.ReasonCode == "ticket-subject-capacity-exhausted", "ticket capacity did not propagate through the endpoint path");
        Ensure(host.Snapshot.OutstandingTicketCount == OneTimeGateTicketService.MaximumOutstandingPerSubject && host.Snapshot.HeldFlowCount == 0, "ticket capacity failure leaked held state");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(host, authorityMustBeZero: true);

        using var grantHost = OutboundGateSimulatorHost.CreateGrantCapacityHostForAcceptance();
        var grantOperationId = SimulationFixture.Id(37_100);
        Ensure(grantHost.SubmitRead(SimulationFixture.Read(grantOperationId)).ReasonCode == "sim-read-completion-accepted", "grant cap fixture read failed");
        Ensure(grantHost.TryGetIntentId(grantOperationId, out var grantIntentId), "grant cap fixture intent missing");
        Ensure(grantHost.SubmitFlow(SimulationFixture.Flow(grantOperationId, grantIntentId)).ReasonCode == "sim-challenge-created", "grant cap fixture challenge missing");
        Ensure(grantHost.TryGetChallengeId(grantOperationId, out var grantChallengeId), "grant cap fixture challenge identity missing");
        var grantDenied = grantHost.SubmitDecision(SimulationFixture.Decision(grantChallengeId, sequence: 38));
        Ensure(grantDenied.Outcome == SimulatedFlowOutcome.FailedOpen && grantDenied.ReasonCode == "ticket-active-grant-capacity-exhausted", "active-grant capacity did not propagate through the endpoint path");
        Ensure(grantHost.Snapshot.ActiveGrantReservationCount == OneTimeGateTicketService.MaximumActiveGrantsGlobal
            && grantHost.Snapshot.HeldFlowCount == 0
            && grantHost.Snapshot.CriticalAlertCount > 0,
            "active-grant capacity failure leaked held state or omitted evidence");
        grantHost.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(grantHost, authorityMustBeZero: true);
    }

    private static void EnsureGrantExpiryAndByteCount(OutboundGateSimulatorHost host)
    {
        var exact = RunHappy(host, TransportProtocol.Tcp);
        var exactGrant = exact.Grant ?? throw new TestFailureException("grant fixture did not return authority");
        Ensure(exactGrant.MaximumBytes == OutboundGateLimits.MaximumGrantBytes, "grant byte limit was not the frozen 512 MiB");
        var counted = host.ConsumeGrantBytes(exactGrant.GrantId, OutboundGateLimits.MaximumGrantBytes);
        Ensure(counted.Outcome == SimulatedFlowOutcome.Granted && host.Snapshot.InstalledGrantCount == 0 && host.Snapshot.ActiveGrantReservationCount == 0, "exact grant byte limit did not revoke authority");
        EnsureZeroOwnedState(host, authorityMustBeZero: true);

        using var overflowHost = new OutboundGateSimulatorHost(true);
        var overflowGrant = RunHappy(overflowHost, TransportProtocol.Tcp).Grant!;
        Ensure(overflowHost.ConsumeGrantBytes(overflowGrant.GrantId, overflowGrant.MaximumBytes - 1).Outcome == SimulatedFlowOutcome.Granted, "grant byte accounting rejected below cap");
        var overflow = overflowHost.ConsumeGrantBytes(overflowGrant.GrantId, 2);
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-grant-byte-capacity-exhausted", "grant byte cap +1 did not fail open");
        EnsureZeroOwnedState(overflowHost, authorityMustBeZero: true);

        using var expiryHost = new OutboundGateSimulatorHost(true);
        RunHappy(expiryHost, TransportProtocol.Tcp);
        expiryHost.AdvanceBy((long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);
        EnsureZeroOwnedState(expiryHost, authorityMustBeZero: true);
    }

    private static void EnsurePolicyCleanup(OutboundGateSimulatorHost host)
    {
        RunHappy(host, TransportProtocol.Tcp);
        Ensure(host.Snapshot.ActiveGrantReservationCount == 1 && host.Snapshot.InstalledGrantCount == 1, "policy fixture authority missing");
        host.ApplyPolicyEpoch(1);
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureReplay(OutboundGateSimulatorHost host)
    {
        Ensure(RunHappy(host, TransportProtocol.Tcp).Outcome == SimulatedFlowOutcome.Granted, "replay setup failed");
        Ensure(host.Snapshot.InstalledGrantCount == 1, "grant was not installed");
        var replay = host.Redeem(host.ConsumedTickets.Single());
        Ensure(replay.Outcome == SimulatedFlowOutcome.FailedOpen && replay.ReasonCode == "ticket-replay", "exact replay was not rejected");
    }

    private static GateSubject NewSubject(int pid)
    {
        var process = new ProcessIdentity(pid, SimulationFixture.Start);
        return new GateSubject(1, process, $"sha256:subject-{pid}", null, [process]);
    }

    private static void EnsurePrivacy()
    {
        var assembly = typeof(Program).Assembly;
        var visited = new HashSet<Type>();
        foreach (var type in assembly.GetTypes().Where(type =>
            type.Namespace == typeof(Program).Namespace
            && !type.IsDefined(typeof(System.Runtime.CompilerServices.CompilerGeneratedAttribute), inherit: false)
            && !type.Name.StartsWith('<')))
            EnsureMetadataOnly(type, visited);
        Ensure(!typeof(ScenarioReport).GetProperties().Any(property => property.PropertyType == typeof(SimulationStepResult)), "scenario output exposed a transition result");
        Ensure(!typeof(SuiteReport).GetProperties().Any(property => property.PropertyType == typeof(SimulationStepResult)), "suite output exposed a transition result");
    }

    private static void EnsureNoWorkersAndConcurrentEntry(OutboundGateSimulatorHost host)
    {
        var workerTypes = new[] { typeof(Thread), typeof(Task), typeof(Timer) };
        var fields = typeof(OutboundGateSimulatorHost).GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic);
        Ensure(fields.All(field => workerTypes.All(worker => !worker.IsAssignableFrom(field.FieldType))), "host retained a per-event worker");
        using var barrier = new Barrier(9);
        var tasks = Enumerable.Range(0, 8).Select(index => Task.Run(() =>
        {
            barrier.SignalAndWait();
            var subject = NewSubject(50_000 + index);
            return host.SubmitRead(SimulationFixture.Read(SimulationFixture.Id(50_100 + index), subject, index + 1));
        })).ToArray();
        barrier.SignalAndWait();
        Task.WaitAll(tasks);
        Ensure(tasks.All(task => task.Result.ReasonCode == "sim-read-completion-accepted"), "serialized concurrent entry lost a transition");
        Ensure(host.Snapshot.AcceptedReadCount == 8 && host.Snapshot.ReleasedReadCount == 8 && host.Snapshot.CoreActiveContextCount == 8, "concurrent entry counters were not exact");
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureRepeatedPostAdmissionOverflowAndAlertBound(OutboundGateSimulatorHost host)
    {
        const int repetitions = OutboundGateSimulatorHost.CoreAlertDedupeCapacity + 44;
        for (var index = 0; index < repetitions; index++)
        {
            var operationId = SimulationFixture.Id(60_000 + index);
            Ensure(host.SubmitRead(SimulationFixture.Read(operationId, sequence: index + 1)).ReasonCode == "sim-read-completion-accepted", "overflow fixture read failed");
            Ensure(host.TryGetIntentId(operationId, out var intentId), "overflow fixture intent missing");
            var overflow = host.SubmitFlow(SimulationFixture.Flow(operationId, intentId, bytes: FakeWfpEndpoint.FlowByteCapacity + 1));
            Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && overflow.ReasonCode == "sim-held-data-flow-capacity-exhausted", "post-admission overflow returned the wrong stable reason");
            EnsureZeroOwnedState(host, authorityMustBeZero: true);
        }
        var snapshot = host.Snapshot;
        Ensure(snapshot.OverflowCount == repetitions && snapshot.FailedOpenOperationCount == repetitions, "repeated overflow counters were not exact");
        Ensure(snapshot.CoreAlertDedupeCount == OutboundGateSimulatorHost.CoreAlertDedupeCapacity && snapshot.CoreAlertDedupeCount <= snapshot.CoreAlertDedupeCapacity, "Core alert dedupe map was not bounded at cap");
        Ensure(snapshot.AlertRingCount == OutboundGateSimulatorHost.AlertRingCapacity && snapshot.DiagnosticAlertEvictionCount > 0, "diagnostic alert ring was not bounded");
    }

    private static void EnsureAllFaultClasses(OutboundGateSimulatorHost host)
    {
        static void Run(Action<OutboundGateSimulatorHost> assertion)
        {
            using var fixture = new OutboundGateSimulatorHost(true);
            assertion(fixture);
            EnsureZeroOwnedState(fixture, authorityMustBeZero: true);
        }

        Run(fixture => EnsureDelayCoverage(fixture, timeout: true));
        Run(fixture => EnsureDelayCoverage(fixture, timeout: true, afterDeadlineMilliseconds: 1));
        Run(EnsureDropCoverage);
        Run(fixture => EnsureEndpointRestart(fixture, minifilter: true));
        Run(fixture => EnsureEndpointRestart(fixture, minifilter: false));
        Run(EnsureServiceRestart);
        Run(fixture => EnsureStaleGeneration(fixture, SimulationEnvelopeKind.GateArmAck, "sim-stale-wfp-generation"));
        Run(fixture => EnsureStaleGeneration(fixture, SimulationEnvelopeKind.FileReadCompletionAck, "sim-stale-minifilter-generation"));
        Run(fixture => EnsureCoverageFault(fixture, SimulationFaultKind.PartialCoverage, "sim-coverage-partial"));
        Run(fixture => EnsureCoverageFault(fixture, SimulationFaultKind.DegradedCoverage, "sim-coverage-degraded"));
        Run(fixture => EnsurePendingCap(fixture, FakeMinifilterEndpoint.SubjectCapacity, SimulationFixture.Subject));
        Run(EnsurePendingGlobalCap);
        Run(fixture => EnsureChallengeCap(fixture, FakeWfpEndpoint.HeldSubjectCapacity, global: false));
        Run(fixture => EnsureChallengeCap(fixture, FakeWfpEndpoint.HeldFlowCapacity, global: true));
        Run(EnsureEndpointChannelBoundaries);
        EnsureHeldFlowBoundaries();
        EnsureHeldByteCap();
        EnsureGlobalByteCap();
        Run(EnsureSchedulerBoundaries);
        Run(EnsureFaultPlanCap);
        Run(EnsurePumpBudget);
        using (var ticketHost = OutboundGateSimulatorHost.CreateTicketCapacityHostForAcceptance())
            EnsureTicketCapacityThroughEndpoint(ticketHost);
        Run(EnsureGrantExpiryAndByteCount);
        EnsureRepeatedPostAdmissionOverflowAndAlertBound(host);
        EnsureZeroOwnedState(host, authorityMustBeZero: true);
    }

    private static void EnsureZeroOwnedState(OutboundGateSimulatorHost host, bool authorityMustBeZero)
    {
        var snapshot = host.Snapshot;
        Ensure(snapshot.PendingReadCount == 0
            && snapshot.ActiveChallengeCount == 0
            && snapshot.HeldFlowCount == 0
            && snapshot.HeldByteCount == 0
            && snapshot.ScheduledCount == 0
            && snapshot.SchedulerOwnerCount == 0
            && snapshot.OwnedOperationCount == 0
            && snapshot.HostOwnershipCount == 0
            && snapshot.MinifilterIntentOutboxCount == 0
            && snapshot.MinifilterDispositionInboxCount == 0
            && snapshot.MinifilterCompletionAckOutboxCount == 0
            && snapshot.WfpGateArmInboxCount == 0
            && snapshot.WfpGateAckOutboxCount == 0
            && snapshot.WfpFlowObservationInboxCount == 0
            && snapshot.WfpChallengeOutboxCount == 0,
            "simulator retained owned pending/held/channel/scheduler state");
        Ensure(snapshot.AcceptedReadCount == snapshot.ReleasedReadCount && snapshot.AcceptedFlowCount == snapshot.ReleasedFlowCount, "accepted/released counters diverged");
        if (authorityMustBeZero)
            Ensure(snapshot.CoreActiveContextCount == 0 && snapshot.OutstandingTicketCount == 0 && snapshot.ActiveGrantReservationCount == 0 && snapshot.InstalledGrantCount == 0, "simulator retained authority state");
    }

    private static void EnsureMetadataOnly(Type type, HashSet<Type> visited)
    {
        if (!visited.Add(type))
            return;
        var flags = System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic;
        foreach (var member in type.GetFields(flags).Cast<System.Reflection.MemberInfo>().Concat(type.GetProperties(flags)))
        {
            if (member.Name == "_transitionSync")
                continue;
            var memberType = member switch
            {
                System.Reflection.FieldInfo field => field.FieldType,
                System.Reflection.PropertyInfo property => property.PropertyType,
                _ => throw new InvalidOperationException("Unsupported reflected member.")
            };
            EnsureSafeMetadataType(memberType, member.Name, visited);
            var forbiddenNames = new[]
            {
                "Pay" + "load", "Con" + "tent", "Raw" + "Path", "File" + "Path",
                "Pack" + "et", "Buf" + "fer", "Ticket" + "Secret"
            };
            Ensure(forbiddenNames.All(name => !member.Name.Contains(name, StringComparison.OrdinalIgnoreCase)), "simulator declared a forbidden data-bearing field");
        }
    }

    private static void EnsureSafeMetadataType(Type type, string memberName, HashSet<Type> visited)
    {
        Ensure(!(type.IsArray && type.GetElementType() == typeof(byte)), $"{memberName} retained a byte array");
        Ensure(type != typeof(Memory<byte>) && type != typeof(ReadOnlyMemory<byte>) && type != typeof(ArraySegment<byte>), $"{memberName} retained byte memory");
        Ensure(!typeof(Stream).IsAssignableFrom(type), $"{memberName} retained a stream");
        Ensure(type != typeof(object), $"{memberName} retained arbitrary object data");
        if (type.IsGenericType)
            foreach (var argument in type.GetGenericArguments())
            {
                Ensure(argument != typeof(byte), $"{memberName} retained a byte collection");
                if (argument.Namespace == typeof(Program).Namespace)
                    EnsureMetadataOnly(argument, visited);
            }
        if (type.Namespace == typeof(Program).Namespace)
            EnsureMetadataOnly(type, visited);
    }

    private static ServiceMonotonicTimeRange Window(ManualSimulationClock clock, long milliseconds)
    {
        var now = clock.Now();
        return new ServiceMonotonicTimeRange(1, now, new ServiceMonotonicTimestamp(1, now.ClockInstanceId, checked(now.ElapsedMilliseconds + milliseconds)));
    }

    private static GateArmRequest ArmRequest(ManualSimulationClock clock, Guid intentId, Guid generation)
    {
        var coverage = new GateCoverage(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);
        return new GateArmRequest(1, intentId, SimulationFixture.Subject, coverage, 0, generation, SimulationFixture.Id(70_001), clock.NowUtc(), Window(clock, 2_000));
    }

    private static NetworkGateChallenge Challenge(ManualSimulationClock clock, Guid intentId, Guid challengeId)
    {
        var coverage = new GateCoverage(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);
        return new NetworkGateChallenge(1, challengeId, intentId, SimulationFixture.Subject, SimulationFixture.Destination(), 1, false, coverage, clock.NowUtc(), Window(clock, 15_000), "Simulation");
    }

    private static FileReadDisposition Disposition(Guid intentId, ProcessIdentity process, FileVersionIdentity file, FileReadDispositionKind kind, Guid? ackId, ServiceMonotonicTimeRange window, string reason, long sequence) =>
        new(1, intentId, process, file, kind, ackId, window, reason, sequence);

    private static FileReadCompletionAck Completion(
        FileReadDisposition expected,
        Guid generation,
        Guid? intentId = null,
        ProcessIdentity? process = null,
        FileVersionIdentity? file = null,
        long? dispositionSequence = null,
        FileReadDispositionKind? disposition = null,
        Guid? gateAckId = null,
        bool omitGateAck = false,
        FileReadCompletionResult result = FileReadCompletionResult.Released) =>
        new(
            1,
            SimulationFixture.Id(70_100),
            intentId ?? expected.IntentId,
            process ?? expected.ProcessIdentity,
            file ?? expected.File,
            dispositionSequence ?? expected.Sequence,
            disposition ?? expected.Disposition,
            omitGateAck ? null : gateAckId ?? expected.GateAckId,
            result,
            result == FileReadCompletionResult.Released ? "read-released" : "read-failed-open",
            1,
            generation);

    private static FakeWfpEndpoint WfpFixture(out ManualSimulationClock clock)
    {
        var generation = SimulationFixture.Id(70_200);
        clock = new ManualSimulationClock(SimulationFixture.Id(70_201), SimulationFixture.Start);
        return new FakeWfpEndpoint(() => generation, new DeterministicNonceProvider(), clock);
    }

    private static void Fill(int count, Func<bool> add, string name)
    {
        for (var index = 0; index < count; index++)
            Ensure(add(), $"{name} rejected before cap");
    }

    private static void Ensure(bool condition, string message)
    {
        if (!condition)
            throw new TestFailureException(message);
    }

    private sealed class TestFailureException : Exception
    {
        public TestFailureException(string message) : base(message) { }
    }
}
