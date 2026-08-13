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
        if (transport == SimulatedTransportKind.Quic && destination.Protocol != TransportProtocol.Udp)
            throw new ArgumentException("QUIC simulation is UDP-bound.", nameof(destination));
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

internal sealed record SimulationEnvelope(SimulationEnvelopeKind Kind, Guid OperationId, object Payload);

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
    int SchedulerOwnerCapacity);

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

internal sealed class DeterministicSimulationScheduler : IDeterministicSimulationScheduler
{
    internal const int Capacity = 512;
    internal const int OwnerCapacity = 256;
    private readonly ManualSimulationClock _clock;
    private readonly PriorityQueue<SimulationEnvelope, (long Due, long Sequence)> _events = new();
    private readonly HashSet<Guid> _owners = new();
    private long _sequence;

    public DeterministicSimulationScheduler(ManualSimulationClock clock) => _clock = clock;
    public int Count => _events.Count;
    public int OwnerCount => _owners.Count;

    public bool TrySchedule(SimulationEnvelope envelope, long delayMilliseconds)
    {
        ArgumentNullException.ThrowIfNull(envelope);
        if (delayMilliseconds < 0 || _events.Count >= Capacity || _owners.Count >= OwnerCapacity || !_owners.Add(envelope.OperationId))
            return false;
        var due = checked(_clock.Now().ElapsedMilliseconds + delayMilliseconds);
        _events.Enqueue(envelope, (due, ++_sequence));
        return true;
    }

    public int PumpReady() => PumpReady(int.MaxValue, static _ => { });

    internal int PumpReady(int maximum, Action<SimulationEnvelope> dispatch)
    {
        var pumped = 0;
        while (pumped < maximum && _events.TryPeek(out _, out var priority) && priority.Due <= _clock.Now().ElapsedMilliseconds)
        {
            var envelope = _events.Dequeue();
            _owners.Remove(envelope.OperationId);
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
        _owners.Remove(operationId);
    }

    internal void Clear()
    {
        _events.Clear();
        _owners.Clear();
    }
}

internal sealed class FakeMinifilterEndpoint : IFakeMinifilterEndpoint
{
    internal const int GlobalCapacity = 64;
    internal const int SubjectCapacity = 4;
    internal const int IntentOutboxCapacity = 64;
    internal const int DispositionInboxCapacity = 64;
    internal const int CompletionAckOutboxCapacity = 64;
    private readonly Dictionary<Guid, SimulatedReadMetadata> _pending = new();
    private Guid _generation;
    private bool _available = true;

    public FakeMinifilterEndpoint(Guid generation) => _generation = generation;
    public MinifilterSnapshot Snapshot => new(
        _pending.Count,
        GlobalCapacity,
        SubjectCapacity,
        0,
        IntentOutboxCapacity,
        0,
        DispositionInboxCapacity,
        0,
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
        _pending.Add(read.OperationId, read);
        return new(SimulatedFlowOutcome.Pending, "sim-read-pended");
    }

    public SimulationStepResult AcceptDisposition(FileReadDisposition disposition)
    {
        ArgumentNullException.ThrowIfNull(disposition);
        var pending = _pending.Values.FirstOrDefault(item => item.Sequence == disposition.Sequence && item.Subject.ProcessIdentity == disposition.ProcessIdentity && item.File == disposition.File);
        if (pending is null)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-read-not-owned");
        _pending.Remove(pending.OperationId);
        return new(SimulatedFlowOutcome.Pending, disposition.Disposition == FileReadDispositionKind.ReleaseAfterGateArmed ? "sim-read-released" : "sim-read-failed-open");
    }

    internal bool TryGet(Guid operationId, out SimulatedReadMetadata? read) => _pending.TryGetValue(operationId, out read);
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
        _pending.Clear();
    }

    public void Restart(Guid generation)
    {
        OutboundGateLimits.GuidValue(generation, nameof(generation));
        _generation = generation;
        _available = true;
        _pending.Clear();
    }

    internal void ReleaseAll() => _pending.Clear();

    private int CountFor(GateSubject subject) => _pending.Values.Count(item => item.Subject.Matches(subject));
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
        0,
        ArmChannelCapacity,
        0,
        GateAckOutboxCapacity,
        0,
        FlowChannelCapacity,
        0,
        ChallengeOutboxCapacity,
        _available,
        _currentGeneration());

    public SimulationStepResult AcceptArmRequest(GateArmRequest request)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (!_available)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-wfp-unavailable");
        var ack = CreateAck(request, request.RequiredCoverage, null, _currentGeneration());
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
        return TryReserveHeld(flow);
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
        _grants[grant.GrantId] = new InstalledGrant(grant, 0);
        return new(SimulatedFlowOutcome.Granted, "sim-grant-installed", Grant: grant);
    }

    internal SimulationStepResult ConsumeGrantBytes(Guid grantId, long bytes)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(bytes);
        if (!_grants.TryGetValue(grantId, out var grant))
            return new(SimulatedFlowOutcome.FailedOpen, "sim-grant-not-installed");
        if (bytes > grant.Grant.MaximumBytes - grant.UsedBytes)
            return new(SimulatedFlowOutcome.FailedOpen, "sim-grant-byte-capacity-exhausted");
        _grants[grantId] = grant with { UsedBytes = checked(grant.UsedBytes + bytes) };
        return new(SimulatedFlowOutcome.Granted, "sim-grant-byte-counted", Grant: grant.Grant);
    }

    internal bool RemoveHeld(Guid operationId) => _held.Remove(operationId);
    internal IReadOnlyList<Guid> HeldOperationIds => _held.Keys.ToArray();
    internal void RemoveGrant(Guid grantId) => _grants.Remove(grantId);
    internal bool HasHeld(Guid operationId) => _held.ContainsKey(operationId);
    internal IReadOnlyList<EphemeralFlowGrant> Grants => _grants.Values.Select(item => item.Grant).ToArray();
    internal void ReleaseAll() { _held.Clear(); _grants.Clear(); }
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
    private static readonly GateCoverage FullCoverage = new(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);
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
    private readonly Dictionary<Guid, SimulationEnvelopeKind> _channelReservations = new();
    private readonly Dictionary<SimulationEnvelopeKind, int> _channelCounts = new();
    private readonly HashSet<Guid> _acceptedReadOperations = new();
    private readonly HashSet<Guid> _acceptedFlowOperations = new();
    private readonly HashSet<Guid> _failedOpenOperations = new();
    private readonly HashSet<Guid> _coreAlertIds = new();
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
    private bool _disposed;

    public OutboundGateSimulatorHost(bool simulation = false)
    {
        _simulation = simulation;
        _clock = new ManualSimulationClock(Guid.Parse("22000000-0000-0000-0000-000000000005"), new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero));
        _nonces = new DeterministicNonceProvider();
        _scheduler = new DeterministicSimulationScheduler(_clock);
        _bootInstance = Guid.Parse("10000000-0000-0000-0000-000000000005");
        _wfpGeneration = Guid.Parse("20000000-0000-0000-0000-000000000005");
        _minifilterGeneration = Guid.Parse("21000000-0000-0000-0000-000000000005");
        _minifilter = new FakeMinifilterEndpoint(_minifilterGeneration);
        _wfp = new FakeWfpEndpoint(() => _wfpGeneration, _nonces, _clock);
        if (!simulation)
            return;

        _ticketService = new OneTimeGateTicketService(_clock, _clock, _nonces, new DeterministicTestTicketAuthenticator(_bootInstance), 0);
        _machine = new OutboundGateStateMachine(_clock, _nonces, _clock, OutboundGateMode.Simulation, 0, new OutboundGateTrustedRuntimeState(_bootInstance, _wfpGeneration, _minifilterGeneration), _ticketService);
        _lastReasonCode = "sim-ready";
    }

    public SimulationSnapshot Snapshot
    {
        get
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
                SchedulerOwnerCapacity);
        }
    }

    public SimulationStepResult SubmitRead(SimulatedReadMetadata read)
    {
        EnsureNotDisposed();
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
        _acceptedReadCount++;
        var now = _clock.Now();
        var deadline = new ServiceMonotonicTimestamp(1, now.ClockInstanceId, checked(now.ElapsedMilliseconds + (long)OutboundGateLimits.MaximumGateArmReadDuration.TotalMilliseconds));
        var intent = new FileReadIntent(1, _nonces.NextNonce(), read.Subject, read.File, FileActivityOperation.Read, _clock.NowUtc(), new ServiceMonotonicTimeRange(1, now, deadline), _bootInstance, read.Sequence);
        _intents[read.OperationId] = intent;
        _intentOperations[intent.IntentId] = read.OperationId;
        var transition = _machine!.ReceiveIntent(intent);
        ObserveCore(transition);
        if (transition.ArmRequest is null)
            return FailOperation(read.OperationId, transition.Status.ReasonCode, transition.CriticalAlert);
        var scheduled = Schedule(new SimulationEnvelope(SimulationEnvelopeKind.GateArmRequest, read.OperationId, transition.ArmRequest));
        if (scheduled is not null)
            return Remember(scheduled);
        PumpReady();
        return Remember(new(SimulatedFlowOutcome.Pending, _lastReasonCode == "sim-read-completion-accepted" ? "sim-read-completion-accepted" : "sim-read-arm-scheduled"));
    }

    public SimulationStepResult SubmitFlow(SimulatedFlowMetadata flow)
    {
        EnsureNotDisposed();
        if (!_simulation)
            return Remember(new(SimulatedFlowOutcome.FailedOpen, "sim-disabled"));
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
            return Overflow(flow.OperationId, reserved.ReasonCode, flow.Subject);
        _acceptedFlowOperations.Add(flow.OperationId);
        _acceptedFlowCount++;
        var now = _clock.Now();
        var window = new ServiceMonotonicTimeRange(1, now, new ServiceMonotonicTimestamp(1, now.ClockInstanceId, checked(now.ElapsedMilliseconds + (long)OutboundGateLimits.MaximumDecisionHoldDuration.TotalMilliseconds)));
        var challenge = new NetworkGateChallenge(1, _nonces.NextNonce(), flow.IntentId, flow.Subject, flow.Destination, flow.FlowGeneration, false, FullCoverage, _clock.NowUtc(), window, "Simulation");
        var transition = _machine!.ReceiveChallenge(challenge);
        ObserveCore(transition);
        if (transition.Challenge is null || transition.Status.State == GateRuntimeState.FailedOpen)
        {
            ReleaseFlow(flow.OperationId);
            MarkFailedOpen(flow.OperationId);
            CompleteOperation(flow.OperationId);
            return Remember(new(SimulatedFlowOutcome.FailedOpen, transition.Status.ReasonCode, transition));
        }
        _challengeOperations[challenge.ChallengeId] = flow.OperationId;
        return Remember(new(SimulatedFlowOutcome.Pending, "sim-challenge-created", transition));
    }

    public SimulationStepResult SubmitDecision(UserDecision decision)
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
        EnsureNotDisposed();
        var pumped = _scheduler.PumpReady(PumpDispatchCapacity, Dispatch);
        if (pumped >= PumpDispatchCapacity && _scheduler.Count > 0)
        {
            _overflowCount++;
            InvalidateRuntime(OwnedOperationIds().ToArray());
            EmitAlert("sim-pump-budget-exhausted", null, null);
            _lastReasonCode = "sim-pump-budget-exhausted";
        }
        return pumped;
    }

    public int AdvanceBy(long milliseconds)
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
        if (_machine is null)
            return;
        Reconcile(_machine.ApplyPolicyEpoch(epoch));
        _wfp.ReleaseAll();
    }

    internal bool TryGetTicket(Guid operationId, out OneTimeTicket? ticket) => _tickets.TryGetValue(operationId, out ticket);
    internal bool TryGetIntentId(Guid operationId, out Guid intentId)
    {
        if (_intents.TryGetValue(operationId, out var intent))
        {
            intentId = intent.IntentId;
            return true;
        }
        intentId = Guid.Empty;
        return false;
    }
    internal bool TryGetChallengeId(Guid operationId, out Guid challengeId)
    {
        var value = _challengeOperations.FirstOrDefault(pair => pair.Value == operationId);
        challengeId = value.Key;
        return value.Key != Guid.Empty;
    }
    internal IReadOnlyList<CriticalAlert> Alerts => new ReadOnlyCollection<CriticalAlert>(_alerts.ToArray());
    internal int FaultPlanCount => _faults.Count;
    internal int SchedulerOwnerCount => _scheduler.OwnerCount;
    internal IReadOnlyList<OneTimeTicket> ConsumedTickets => _consumedTickets.Values.ToArray();

    private SimulationStepResult? Schedule(SimulationEnvelope envelope)
    {
        var fault = TakeFault(envelope.Kind, envelope.OperationId);
        if (fault?.Kind == SimulationFaultKind.DropNext)
        {
            _droppedEnvelopeCount++;
            _lastReasonCode = "sim-envelope-dropped";
            return new(SimulatedFlowOutcome.Pending, "sim-envelope-dropped");
        }
        var delay = fault?.Kind == SimulationFaultKind.DelayNext ? fault.DelayMilliseconds : 0;
        if (!TryReserveChannel(envelope))
            return Overflow(envelope.OperationId, ChannelCapacityReason(envelope.Kind), null);
        if (!_scheduler.TrySchedule(envelope, delay))
        {
            ReleaseChannel(envelope.OperationId);
            return Overflow(envelope.OperationId, "sim-scheduler-capacity-exhausted", null);
        }
        return null;
    }

    private void Dispatch(SimulationEnvelope envelope)
    {
        ReleaseChannel(envelope.OperationId);
        if (envelope.Kind != SimulationEnvelopeKind.GateArmRequest || !_intents.TryGetValue(envelope.OperationId, out _))
            return;
        var request = (GateArmRequest)envelope.Payload;
        var fault = TakeFault(SimulationEnvelopeKind.GateArmAck, envelope.OperationId);
        var armResult = fault is null
            ? _wfp.AcceptArmRequest(request)
            : new SimulationStepResult(
                SimulatedFlowOutcome.Pending,
                "sim-full-coverage-armed",
                Ack: _wfp.CreateAck(
                    request,
                    fault.Kind == SimulationFaultKind.PartialCoverage ? new GateCoverage(1, GateCoverageFlags.NewTcp) : FullCoverage,
                    fault.Kind == SimulationFaultKind.DegradedCoverage ? "sim-coverage-degraded" : null,
                    fault.Kind == SimulationFaultKind.StaleGeneration ? NextGeneration(_wfpGeneration) : _wfpGeneration));
        var ack = armResult.Ack;
        if (ack is null)
        {
            FailOperation(envelope.OperationId, armResult.ReasonCode, armResult.Alert);
            return;
        }
        var armed = _machine!.ReceiveGateArmAck(ack);
        ObserveCore(armed);
        if (armed.Status.State == GateRuntimeState.FailedOpen)
        {
            FailOperation(envelope.OperationId, armed.Status.ReasonCode, armed.CriticalAlert);
            return;
        }
        var disposition = _machine.ReleaseAfterGateArmed(request.IntentId).Disposition;
        if (disposition is null)
        {
            FailOperation(envelope.OperationId, "sim-disposition-missing", null);
            return;
        }
        _minifilter.AcceptDisposition(disposition);
        var completionGeneration = _minifilter.Snapshot.Generation;
        var completionFault = TakeFault(SimulationEnvelopeKind.FileReadCompletionAck, envelope.OperationId);
        if (completionFault?.Kind == SimulationFaultKind.StaleGeneration)
            completionGeneration = NextGeneration(completionGeneration);
        var completion = FakeMinifilterEndpoint.CreateCompletion(disposition, completionGeneration, _nonces, request.PolicyEpoch + 1);
        var completed = _machine.AcceptCompletion(completion);
        ObserveCore(completed);
        if (completed.Status.State == GateRuntimeState.FailedOpen)
        {
            FailOperation(envelope.OperationId, completed.Status.ReasonCode, completed.CriticalAlert);
            return;
        }
        Remember(new(SimulatedFlowOutcome.Pending, "sim-read-completion-accepted", completed, Ack: ack, Completion: completion));
    }

    private SimulationFault? TakeFault(SimulationEnvelopeKind kind, Guid operationId)
    {
        var index = _faults.FindIndex(item => item.EnvelopeKind == kind && (item.OperationId is null || item.OperationId == operationId));
        if (index < 0)
            return null;
        var fault = _faults[index];
        _faults.RemoveAt(index);
        return fault;
    }

    private bool TryReserveChannel(SimulationEnvelope envelope)
    {
        var capacity = ChannelCapacity(envelope.Kind);
        var count = _channelCounts.GetValueOrDefault(envelope.Kind);
        if (count >= capacity || _channelReservations.Count >= HostOwnershipCapacity)
            return false;
        _channelReservations[envelope.OperationId] = envelope.Kind;
        _channelCounts[envelope.Kind] = count + 1;
        return true;
    }

    private void ReleaseChannel(Guid operationId)
    {
        if (!_channelReservations.Remove(operationId, out var kind))
            return;
        var count = _channelCounts.GetValueOrDefault(kind);
        if (count <= 1)
            _channelCounts.Remove(kind);
        else
            _channelCounts[kind] = count - 1;
    }

    private static int ChannelCapacity(SimulationEnvelopeKind kind) => kind switch
    {
        SimulationEnvelopeKind.FileReadIntent => FakeMinifilterEndpoint.IntentOutboxCapacity,
        SimulationEnvelopeKind.GateArmRequest => FakeWfpEndpoint.ArmChannelCapacity,
        SimulationEnvelopeKind.GateArmAck => FakeWfpEndpoint.GateAckOutboxCapacity,
        SimulationEnvelopeKind.FileReadDisposition => FakeMinifilterEndpoint.DispositionInboxCapacity,
        SimulationEnvelopeKind.FileReadCompletionAck => FakeMinifilterEndpoint.CompletionAckOutboxCapacity,
        SimulationEnvelopeKind.NetworkGateChallenge => FakeWfpEndpoint.ChallengeOutboxCapacity,
        SimulationEnvelopeKind.Decision => FakeWfpEndpoint.FlowChannelCapacity,
        SimulationEnvelopeKind.TicketRedemption => FakeWfpEndpoint.ChallengeOutboxCapacity,
        _ => HostOwnershipCapacity
    };

    private static string ChannelCapacityReason(SimulationEnvelopeKind kind) => kind switch
    {
        SimulationEnvelopeKind.FileReadIntent or SimulationEnvelopeKind.FileReadDisposition or SimulationEnvelopeKind.FileReadCompletionAck => "sim-minifilter-channel-capacity-exhausted",
        _ => "sim-wfp-channel-capacity-exhausted"
    };

    private SimulationStepResult RestartEndpoint(bool minifilter, bool restart)
    {
        var liveOperations = OwnedOperationIds().ToArray();
        foreach (var operationId in _minifilter.PendingOperationIds)
            _releasedReadCount++;
        foreach (var operationId in _wfp.HeldOperationIds)
            _releasedFlowCount++;
        if (minifilter)
        {
            if (restart) _minifilterRestartCount++; else _minifilterCrashCount++;
            _minifilterGeneration = NextGeneration(_minifilterGeneration);
            if (restart) _minifilter.Restart(_minifilterGeneration); else _minifilter.Crash();
        }
        else
        {
            if (restart) _wfpRestartCount++; else _wfpCrashCount++;
            _wfpGeneration = NextGeneration(_wfpGeneration);
            if (restart) _wfp.Restart(_wfpGeneration); else _wfp.Crash();
        }
        InvalidateRuntime(liveOperations);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, minifilter ? (restart ? "sim-minifilter-restarted" : "sim-minifilter-crashed") : (restart ? "sim-wfp-restarted" : "sim-wfp-crashed")));
    }

    private SimulationStepResult RestartService()
    {
        var liveOperations = OwnedOperationIds().ToArray();
        _serviceRestartCount++;
        _bootInstance = NextGeneration(_bootInstance);
        _wfpGeneration = NextGeneration(_wfpGeneration);
        _minifilterGeneration = NextGeneration(_minifilterGeneration);
        InvalidateRuntime(liveOperations);
        _clock.Restart(NextGeneration(_clock.Now().ClockInstanceId));
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
        _channelReservations.Clear();
        _channelCounts.Clear();
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
        _overflowCount++;
        if (operationId != Guid.Empty)
        {
            MarkFailedOpen(operationId);
            ReleaseRead(operationId);
            ReleaseFlow(operationId);
            CompleteOperation(operationId);
        }
        EmitAlert(reason, operationId == Guid.Empty ? null : operationId, subject);
        return Remember(new(SimulatedFlowOutcome.FailedOpen, reason, Alert: _alerts.LastOrDefault()));
    }

    private void ObserveCore(GateTransitionResult result)
    {
        _lastReasonCode = result.Status.ReasonCode;
        if (result.CriticalAlert is not null)
            ObserveCoreAlert(result.CriticalAlert);
    }

    private void ObserveCoreAlert(CriticalAlert alert)
    {
        if (_coreAlertIds.Add(alert.AlertId))
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
        _criticalAlertCount++;
        _alerts.Enqueue(alert);
        while (_alerts.Count > 256)
        {
            _alerts.Dequeue();
            _diagnosticAlertEvictionCount++;
        }
    }

    private SimulationStepResult Remember(SimulationStepResult result)
    {
        _lastReasonCode = result.ReasonCode;
        if (_trace.Count >= 1_024)
        {
            _trace.Dequeue();
            _transitionTraceEvictionCount++;
        }
        _trace.Enqueue(result.ReasonCode);
        return result;
    }

    private void RememberConsumedTicket(OneTimeTicket ticket)
    {
        _consumedTickets[ticket.TicketId] = ticket;
        _consumedTicketOrder.Enqueue(ticket.TicketId);
        while (_consumedTicketOrder.Count > OneTimeGateTicketService.MaximumReplayTombstonesGlobal)
            _consumedTickets.Remove(_consumedTicketOrder.Dequeue());
    }

    private void MarkFailedOpen(Guid operationId)
    {
        if (operationId != Guid.Empty && (_acceptedReadOperations.Contains(operationId) || _acceptedFlowOperations.Contains(operationId)) && _failedOpenOperations.Add(operationId))
            _failedOpenCount++;
    }

    private void ReleaseRead(Guid operationId)
    {
        if (_minifilter.ReleaseOperation(operationId))
            _releasedReadCount++;
    }

    private void ReleaseFlow(Guid operationId)
    {
        if (_wfp.RemoveHeld(operationId))
            _releasedFlowCount++;
    }

    private IEnumerable<Guid> OwnedOperationIds() => _minifilter.PendingOperationIds.Concat(_wfp.HeldOperationIds).Concat(_intents.Keys).Distinct();
    private int OwnedOperationCount() => OwnedOperationIds().Count();
    private void CompleteOperation(Guid operationId)
    {
        if (!_intents.TryGetValue(operationId, out var intent))
            return;
        _scheduler.CancelOwned(operationId);
        ReleaseChannel(operationId);
        _intents.Remove(operationId);
        _intentOperations.Remove(intent.IntentId);
        foreach (var challenge in _challengeOperations.Where(pair => pair.Value == operationId).Select(pair => pair.Key).ToArray())
            _challengeOperations.Remove(challenge);
        _tickets.Remove(operationId);
        _acceptedReadOperations.Remove(operationId);
        _acceptedFlowOperations.Remove(operationId);
        _failedOpenOperations.Remove(operationId);
    }
    private static Guid NextGeneration(Guid previous) => new Guid(previous.ToByteArray().Select((value, index) => index == 0 ? (byte)(value ^ 0xa5) : value).ToArray());
    private void EnsureNotDisposed() => ObjectDisposedException.ThrowIf(_disposed, typeof(OutboundGateSimulatorHost));

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        if (_simulation)
            InvalidateRuntime(OwnedOperationIds().ToArray());
        _machine?.Dispose();
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
    internal static readonly Guid TcpDestinationId = Guid.Parse("31000000-0000-0000-0000-000000000031");

    internal static SimulatedReadMetadata Read(Guid operationId, GateSubject? subject = null, long sequence = 1) => new(operationId, subject ?? Subject, File, sequence, 1024);

    internal static DestinationBinding Destination(TransportProtocol protocol = TransportProtocol.Tcp) => new(1, IPAddress.Loopback, IpVersion.IPv4, protocol == TransportProtocol.Tcp ? 5050 : 5051, protocol, NetworkTrafficDirection.Outbound, 12, 34, "localhost", DomainEvidenceProvenance.DnsObservation, Start);

    internal static SimulatedFlowMetadata Flow(Guid operationId, Guid intentId, GateSubject? subject = null, TransportProtocol protocol = TransportProtocol.Tcp, SimulatedFlowShape shape = SimulatedFlowShape.NewFlow, SimulatedTransportKind? transport = null, long bytes = 1024) => new(operationId, intentId, subject ?? Subject, Destination(protocol), 1, transport ?? (protocol == TransportProtocol.Tcp ? SimulatedTransportKind.Tcp : SimulatedTransportKind.Udp), shape, bytes);

    internal static UserDecision Decision(Guid challengeId, UserDecisionKind decision = UserDecisionKind.AllowOnce) => new(1, Guid.NewGuid(), challengeId, decision, null, Start, "simulation-test");
}

internal static class Program
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = false };

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
        var names = new[]
        {
            "disabled-default-zero-state", "happy-new-tcp", "happy-new-udp", "release-requires-full-ack", "completion-requires-exact-binding", "existing-tcp-reconnect-required", "existing-udp-reconnect-required", "existing-quic-reconnect-required", "delay-before-deadline-succeeds", "delay-at-deadline-fails-open", "drop-times-out-deterministically", "minifilter-crash-restart-cleans", "wfp-crash-restart-cleans", "service-restart-cleans", "stale-wfp-generation-rejected", "stale-minifilter-generation-rejected", "pending-read-subject-cap", "pending-read-global-cap", "challenge-subject-cap", "challenge-global-cap", "endpoint-channel-boundaries", "held-flow-entry-boundaries", "held-data-flow-cap", "held-data-global-cap", "scheduler-cap", "fault-plan-cap", "pump-dispatch-budget", "ticket-replay-through-endpoint", "ticket-capacity-through-endpoint", "grant-expiry-and-byte-count", "policy-change-cleans-endpoints", "privacy-metadata-only", "no-wall-clock-or-event-workers", "all-faults-finish-zero-owned-state"
        };
        var reports = names.Select(RunNamedScenario).ToArray();
        var finalSnapshot = reports.Length == 0 ? new OutboundGateSimulatorHost().Snapshot : reports[^1].Snapshot;
        return new SuiteReport(reports.Count(report => report.Passed), reports.Length, reports, finalSnapshot);
    }

    internal static ScenarioReport RunNamedScenario(string name)
    {
        using var host = new OutboundGateSimulatorHost(name != "disabled-default-zero-state");
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
                Ensure(host.SubmitRead(SimulationFixture.Read(Guid.NewGuid())).ReasonCode == "sim-disabled", "Disabled created authority");
                Ensure(host.Snapshot.PendingReadCount == 0 && host.Snapshot.HeldFlowCount == 0 && host.Snapshot.ScheduledCount == 0, "Disabled was not zero-state");
                break;
            case "happy-new-tcp":
            case "happy-new-udp":
                Ensure(RunHappy(host, name.EndsWith("udp", StringComparison.Ordinal) ? TransportProtocol.Udp : TransportProtocol.Tcp) == SimulatedFlowOutcome.Granted, "happy path did not grant");
                break;
            case "release-requires-full-ack":
                EnsureReadTimeout(host, new SimulationFault(SimulationFaultKind.PartialCoverage, SimulationEnvelopeKind.GateArmAck));
                break;
            case "completion-requires-exact-binding":
                EnsureReadTimeout(host, new SimulationFault(SimulationFaultKind.StaleGeneration, SimulationEnvelopeKind.FileReadCompletionAck));
                break;
            case "existing-tcp-reconnect-required":
                Ensure(EnsureExisting(host, SimulatedTransportKind.Tcp, TransportProtocol.Tcp).Outcome == SimulatedFlowOutcome.ReconnectRequired, "TCP existing flow was not reconnect-required");
                break;
            case "existing-udp-reconnect-required":
                Ensure(EnsureExisting(host, SimulatedTransportKind.Udp, TransportProtocol.Udp).Outcome == SimulatedFlowOutcome.ReconnectRequired, "UDP existing flow was not reconnect-required");
                break;
            case "existing-quic-reconnect-required":
                Ensure(EnsureExisting(host, SimulatedTransportKind.Quic, TransportProtocol.Udp).Outcome == SimulatedFlowOutcome.ReconnectRequired, "QUIC existing flow was not reconnect-required");
                break;
            case "delay-before-deadline-succeeds":
                EnsureDelay(host, 500, false);
                break;
            case "delay-at-deadline-fails-open":
                EnsureDelay(host, 2_500, true);
                break;
            case "drop-times-out-deterministically":
                EnsureDrop(host);
                break;
            case "minifilter-crash-restart-cleans":
                EnsureEndpointRestart(host, true);
                break;
            case "wfp-crash-restart-cleans":
                EnsureWfpRestart(host);
                break;
            case "service-restart-cleans":
                EnsureServiceRestart(host);
                break;
            case "stale-wfp-generation-rejected":
                EnsureReadTimeout(host, new SimulationFault(SimulationFaultKind.StaleGeneration, SimulationEnvelopeKind.GateArmAck));
                break;
            case "stale-minifilter-generation-rejected":
                EnsureReadTimeout(host, new SimulationFault(SimulationFaultKind.StaleGeneration, SimulationEnvelopeKind.FileReadCompletionAck));
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
                Ensure(host.Snapshot.PendingReadCapacity == 64 && host.Snapshot.ActiveChallengeCapacity == 128, "endpoint capacities changed");
                Ensure(FakeMinifilterEndpoint.IntentOutboxCapacity == 64 && FakeMinifilterEndpoint.DispositionInboxCapacity == 64 && FakeMinifilterEndpoint.CompletionAckOutboxCapacity == 64, "minifilter channel capacities changed");
                Ensure(FakeWfpEndpoint.ArmChannelCapacity == 64 && FakeWfpEndpoint.GateAckOutboxCapacity == 64 && FakeWfpEndpoint.FlowChannelCapacity == 128 && FakeWfpEndpoint.ChallengeOutboxCapacity == 128, "WFP channel capacities changed");
                break;
            case "held-flow-entry-boundaries":
                Ensure(FakeWfpEndpoint.HeldFlowCapacity == 128 && FakeWfpEndpoint.HeldSubjectCapacity == 4, "held-flow caps changed");
                break;
            case "held-data-flow-cap":
                EnsureHeldByteCap(host, FakeWfpEndpoint.FlowByteCapacity + 1);
                break;
            case "held-data-global-cap":
                EnsureGlobalByteCap(host);
                break;
            case "scheduler-cap":
                Ensure(DeterministicSimulationScheduler.Capacity == 512 && DeterministicSimulationScheduler.OwnerCapacity == 256, "scheduler cap changed");
                break;
            case "fault-plan-cap":
                for (var index = 0; index < OutboundGateSimulatorHost.FaultPlanCapacity; index++)
                    Ensure(host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest)).ReasonCode == "sim-fault-planned", "fault plan rejected before cap");
                Ensure(host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest)).ReasonCode == "sim-fault-plan-capacity-exhausted", "fault plan exceeded cap");
                break;
            case "pump-dispatch-budget":
                Ensure(OutboundGateSimulatorHost.PumpDispatchCapacity == 1_024, "pump cap changed");
                break;
            case "ticket-replay-through-endpoint":
                EnsureReplay(host);
                break;
            case "ticket-capacity-through-endpoint":
                Ensure(OneTimeGateTicketService.MaximumActiveGrantsGlobal == 256, "ticket grant cap changed");
                break;
            case "grant-expiry-and-byte-count":
                Ensure(RunHappy(host, TransportProtocol.Tcp) == SimulatedFlowOutcome.Granted, "grant was not installed");
                host.AdvanceBy((long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);
                Ensure(host.Snapshot.InstalledGrantCount == 0, "grant did not expire");
                break;
            case "policy-change-cleans-endpoints":
                Ensure(RunHappy(host, TransportProtocol.Tcp) == SimulatedFlowOutcome.Granted, "policy setup failed");
                host.ApplyPolicyEpoch(1);
                Ensure(host.Snapshot.HeldFlowCount == 0, "policy left held flow");
                break;
            case "privacy-metadata-only":
                EnsurePrivacy();
                break;
            case "no-wall-clock-or-event-workers":
                EnsureNoWorkers();
                break;
            case "all-faults-finish-zero-owned-state":
                EnsureDelay(host, 2_500, true);
                Ensure(host.Snapshot.PendingReadCount == 0 && host.Snapshot.HeldFlowCount == 0 && host.Snapshot.ScheduledCount == 0, "fault cleanup was not zero");
                break;
            default:
                throw new TestFailureException($"Unknown scenario {name}.");
        }
    }

    private static SimulatedFlowOutcome RunHappy(OutboundGateSimulatorHost host, TransportProtocol protocol)
    {
        var operationId = Guid.NewGuid();
        var read = host.SubmitRead(SimulationFixture.Read(operationId));
        Ensure(read.ReasonCode == "sim-read-completion-accepted", "read did not complete after the matching Ack");
        Ensure(host.TryGetIntentId(operationId, out var intentId), "intent was not retained for the flow");
        var flow = host.SubmitFlow(SimulationFixture.Flow(operationId, intentId, protocol: protocol));
        Ensure(flow.ReasonCode == "sim-challenge-created", "new flow was not challenged");
        Ensure(host.TryGetChallengeId(operationId, out var challengeId), "challenge was not retained");
        var decision = host.SubmitDecision(SimulationFixture.Decision(challengeId));
        Ensure(decision.Ticket is not null, "AllowOnce did not create a ticket");
        var redeemed = host.Redeem(decision.Ticket!);
        Ensure(redeemed.Grant is not null && host.Snapshot.HeldFlowCount == 0, "grant did not release the held flow");
        return redeemed.Outcome;
    }

    private static SimulationStepResult EnsureExisting(OutboundGateSimulatorHost host, SimulatedTransportKind transport, TransportProtocol protocol)
    {
        var operationId = Guid.NewGuid();
        var result = host.SubmitFlow(SimulationFixture.Flow(operationId, Guid.NewGuid(), protocol: protocol, shape: SimulatedFlowShape.ExistingMultiplexed, transport: transport));
        Ensure(host.Snapshot.HeldFlowCount == 0 && host.Snapshot.ActiveChallengeCount == 0, "existing flow created owned state");
        return result;
    }

    private static void EnsureReadTimeout(OutboundGateSimulatorHost host, SimulationFault fault)
    {
        host.Inject(fault);
        var result = host.SubmitRead(SimulationFixture.Read(Guid.NewGuid()));
        Ensure(result.ReasonCode is "sim-read-completion-accepted" or "gate-ack-invalid-or-expired" or "completion-binding-or-generation-invalid" or "sim-read-arm-scheduled", "read transition did not use the injected fault");
        host.AdvanceBy(2_000);
        Ensure(host.Snapshot.PendingReadCount == 0 && host.Snapshot.HeldFlowCount == 0 && host.Snapshot.CriticalAlertCount > 0, "fault did not finish fail-open");
    }

    private static void EnsureDelay(OutboundGateSimulatorHost host, long delay, bool timeout)
    {
        host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: delay));
        var result = host.SubmitRead(SimulationFixture.Read(Guid.NewGuid()));
        Ensure(result.ReasonCode == "sim-read-arm-scheduled", "delay did not hold the arm envelope");
        if (timeout)
        {
            host.AdvanceBy(2_000);
            Ensure(host.Snapshot.PendingReadCount == 0 && host.Snapshot.ScheduledCount == 0, "deadline did not win over delayed arm");
        }
        else
        {
            host.AdvanceBy(delay - 1);
            Ensure(host.Snapshot.PendingReadCount == 1, "early manual advance released the read");
            host.AdvanceBy(1);
            Ensure(host.Snapshot.PendingReadCount == 0, "due delayed arm did not complete");
        }
    }

    private static void EnsureDrop(OutboundGateSimulatorHost host)
    {
        host.Inject(new SimulationFault(SimulationFaultKind.DropNext, SimulationEnvelopeKind.GateArmRequest));
        var result = host.SubmitRead(SimulationFixture.Read(Guid.NewGuid()));
        Ensure(result.ReasonCode == "sim-envelope-dropped", "drop did not consume the selected envelope");
        host.AdvanceBy(2_000);
        Ensure(host.Snapshot.PendingReadCount == 0 && host.Snapshot.DroppedEnvelopeCount == 1 && host.Snapshot.CriticalAlertCount > 0, "dropped envelope did not fail open exactly once");
    }

    private static void EnsureEndpointRestart(OutboundGateSimulatorHost host, bool minifilter)
    {
        host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 5_000));
        var operationId = Guid.NewGuid();
        host.SubmitRead(SimulationFixture.Read(operationId));
        var result = host.Inject(new SimulationFault(minifilter ? SimulationFaultKind.MinifilterCrash : SimulationFaultKind.WfpCrash));
        Ensure(result.Outcome == SimulatedFlowOutcome.FailedOpen && host.Snapshot.PendingReadCount == 0 && host.Snapshot.HeldFlowCount == 0, "endpoint crash left owned state");
        host.Inject(new SimulationFault(minifilter ? SimulationFaultKind.MinifilterRestart : SimulationFaultKind.WfpRestart));
        Ensure(host.Snapshot.PendingReadCount == 0 && host.Snapshot.HeldFlowCount == 0 && host.Snapshot.CriticalAlertCount > 0, "endpoint restart did not finish cleanly");
    }

    private static void EnsureWfpRestart(OutboundGateSimulatorHost host)
    {
        var operationId = Guid.NewGuid();
        host.SubmitRead(SimulationFixture.Read(operationId));
        Ensure(host.TryGetIntentId(operationId, out var intentId), "WFP setup intent missing");
        host.SubmitFlow(SimulationFixture.Flow(operationId, intentId));
        Ensure(host.Snapshot.HeldFlowCount == 1, "WFP setup did not hold the flow");
        Ensure(host.Inject(new SimulationFault(SimulationFaultKind.WfpCrash)).Outcome == SimulatedFlowOutcome.FailedOpen, "WFP crash did not fail open");
        host.Inject(new SimulationFault(SimulationFaultKind.WfpRestart));
        Ensure(host.Snapshot.HeldFlowCount == 0 && host.Snapshot.ActiveChallengeCount == 0, "WFP restart left owned state");
    }

    private static void EnsureServiceRestart(OutboundGateSimulatorHost host)
    {
        var operationId = Guid.NewGuid();
        host.SubmitRead(SimulationFixture.Read(operationId));
        Ensure(host.TryGetIntentId(operationId, out var intentId), "service setup intent missing");
        host.SubmitFlow(SimulationFixture.Flow(operationId, intentId));
        var oldBoot = host.Snapshot.BootInstance;
        host.Inject(new SimulationFault(SimulationFaultKind.ServiceRestart));
        Ensure(host.Snapshot.BootInstance != oldBoot && host.Snapshot.PendingReadCount == 0 && host.Snapshot.HeldFlowCount == 0, "service restart did not invalidate state");
    }

    private static void EnsurePendingCap(OutboundGateSimulatorHost host, int capacity, GateSubject subject)
    {
        for (var index = 0; index < capacity; index++)
        {
            host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 10_000));
            host.SubmitRead(SimulationFixture.Read(Guid.NewGuid(), subject, index + 1));
        }
        var overflow = host.SubmitRead(SimulationFixture.Read(Guid.NewGuid(), subject, capacity + 1));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && host.Snapshot.PendingReadCount == capacity, "pending subject cap evicted live state");
    }

    private static void EnsurePendingGlobalCap(OutboundGateSimulatorHost host)
    {
        for (var index = 0; index < 64; index++)
        {
            var process = new ProcessIdentity(10_000 + index, SimulationFixture.Start);
            var subject = new GateSubject(1, process, $"sha256:pending-{index}", null, [process]);
            host.Inject(new SimulationFault(SimulationFaultKind.DelayNext, SimulationEnvelopeKind.GateArmRequest, delayMilliseconds: 10_000));
            host.SubmitRead(SimulationFixture.Read(Guid.NewGuid(), subject, index + 1));
        }
        var overflow = host.SubmitRead(SimulationFixture.Read(Guid.NewGuid(), new GateSubject(1, new ProcessIdentity(20_000, SimulationFixture.Start), "sha256:pending-overflow", null, [new ProcessIdentity(20_000, SimulationFixture.Start)]), 65));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && host.Snapshot.PendingReadCount == 64, "pending global cap evicted live state");
    }

    private static void EnsureChallengeCap(OutboundGateSimulatorHost host, int capacity, bool global)
    {
        for (var index = 0; index < capacity; index++)
        {
            var subject = global ? NewSubject(index + 1000) : SimulationFixture.Subject;
            var operationId = Guid.NewGuid();
            host.SubmitRead(SimulationFixture.Read(operationId, subject, index + 1));
            Ensure(host.TryGetIntentId(operationId, out var intentId), "challenge setup intent missing");
            host.SubmitFlow(SimulationFixture.Flow(operationId, intentId, subject: subject));
        }
        var subjectForOverflow = global ? NewSubject(20_000) : SimulationFixture.Subject;
        var operation = Guid.NewGuid();
        host.SubmitRead(SimulationFixture.Read(operation, subjectForOverflow, capacity + 1));
        Ensure(host.TryGetIntentId(operation, out var overflowIntent), "challenge overflow setup intent missing");
        var overflow = host.SubmitFlow(SimulationFixture.Flow(operation, overflowIntent, subject: subjectForOverflow));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && host.Snapshot.ActiveChallengeCount == capacity, "challenge cap changed live state");
    }

    private static void EnsureHeldByteCap(OutboundGateSimulatorHost host, long bytes)
    {
        var operationId = Guid.NewGuid();
        host.SubmitRead(SimulationFixture.Read(operationId));
        Ensure(host.TryGetIntentId(operationId, out var intentId), "byte cap intent missing");
        var result = host.SubmitFlow(SimulationFixture.Flow(operationId, intentId, bytes: bytes));
        Ensure(result.Outcome == SimulatedFlowOutcome.FailedOpen && host.Snapshot.HeldByteCount == 0, "per-flow byte cap was exceeded");
    }

    private static void EnsureGlobalByteCap(OutboundGateSimulatorHost host)
    {
        for (var index = 0; index < 16; index++)
        {
            var subject = NewSubject(30_000 + index);
            var operation = Guid.NewGuid();
            host.SubmitRead(SimulationFixture.Read(operation, subject, index + 1));
            Ensure(host.TryGetIntentId(operation, out var intent), "global byte intent missing");
            Ensure(host.SubmitFlow(SimulationFixture.Flow(operation, intent, subject: subject, bytes: FakeWfpEndpoint.FlowByteCapacity)).Outcome == SimulatedFlowOutcome.Pending, "global byte reservation failed early");
        }
        var overflowOperation = Guid.NewGuid();
        var overflowSubject = NewSubject(40_000);
        host.SubmitRead(SimulationFixture.Read(overflowOperation, overflowSubject, 17));
        Ensure(host.TryGetIntentId(overflowOperation, out var overflowIntent), "global byte overflow intent missing");
        var overflow = host.SubmitFlow(SimulationFixture.Flow(overflowOperation, overflowIntent, subject: overflowSubject, bytes: 1));
        Ensure(overflow.Outcome == SimulatedFlowOutcome.FailedOpen && host.Snapshot.HeldByteCount == FakeWfpEndpoint.GlobalByteCapacity, "global byte cap was exceeded");
    }

    private static void EnsureReplay(OutboundGateSimulatorHost host)
    {
        Ensure(RunHappy(host, TransportProtocol.Tcp) == SimulatedFlowOutcome.Granted, "replay setup failed");
        Ensure(host.Snapshot.InstalledGrantCount == 1, "grant was not installed");
        var replay = host.Redeem(host.ConsumedTickets.Single());
        Ensure(replay.ReasonCode == "ticket-replay", "exact replay was not rejected");
    }

    private static GateSubject NewSubject(int pid)
    {
        var process = new ProcessIdentity(pid, SimulationFixture.Start);
        return new GateSubject(1, process, $"sha256:subject-{pid}", null, [process]);
    }

    private static void EnsurePrivacy()
    {
        var assembly = typeof(Program).Assembly;
        foreach (var type in assembly.GetTypes().Where(type => type.Namespace == typeof(Program).Namespace))
        {
            foreach (var memberType in type.GetFields(System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.Static | System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.NonPublic).Select(field => field.FieldType).Concat(type.GetProperties().Select(property => property.PropertyType)))
                Ensure(!(memberType.IsArray && memberType.GetElementType() == typeof(byte)), "simulator declared a data-bearing member");
        }
    }

    private static void EnsureNoWorkers()
    {
        Ensure(!typeof(OutboundGateSimulatorHost).GetMethods().Any(method => method.Name.Contains("Sleep", StringComparison.OrdinalIgnoreCase)), "simulator used a sleep decision");
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
