namespace EgressGuard.Core;

public interface IOutboundGateMonotonicClock
{
    ServiceMonotonicTimestamp Now();
}

public interface IOutboundGateNonceProvider
{
    Guid NextNonce();
}

public sealed record GateStateMachineCounters(long FailedOpenCount, long OverflowCount, long ActiveIntentCount, long ActiveChallengeCount);

public sealed record GateTransitionResult
{
    public int Version { get; init; }
    public GateStatus Status { get; init; }
    public GateArmRequest? ArmRequest { get; init; }
    public FileReadDisposition? Disposition { get; init; }
    public NetworkGateChallenge? Challenge { get; init; }
    public OneTimeTicket? Ticket { get; init; }
    public EphemeralFlowGrant? Grant { get; init; }
    public CriticalAlert? CriticalAlert { get; init; }
    public bool IsDuplicate { get; init; }

    internal GateTransitionResult(GateStatus status, GateArmRequest? armRequest = null, FileReadDisposition? disposition = null, NetworkGateChallenge? challenge = null, OneTimeTicket? ticket = null, EphemeralFlowGrant? grant = null, CriticalAlert? criticalAlert = null, bool isDuplicate = false)
    {
        Version = OutboundGateLimits.CurrentVersion;
        Status = status;
        ArmRequest = armRequest;
        Disposition = disposition;
        Challenge = challenge;
        Ticket = ticket;
        Grant = grant;
        CriticalAlert = criticalAlert;
        IsDuplicate = isDuplicate;
    }
}

public sealed class OutboundGateStateMachine
{
    private const int MaximumPendingPerSubject = 4;
    private const int MaximumPendingGlobal = 64;
    private const int MaximumChallengesPerSubject = 4;
    private const int MaximumChallengesGlobal = 128;

    private readonly IOutboundGateMonotonicClock _clock;
    private readonly IOutboundGateNonceProvider _nonces;
    private readonly OutboundGateMode _mode;
    private readonly Dictionary<Guid, Context> _contexts = new();
    private readonly Dictionary<Guid, Guid> _challengeToIntent = new();
    private readonly List<CriticalAlert> _criticalAlerts = new();
    private long _failedOpenCount;
    private long _overflowCount;
    private long _sequence;
    private long _policyEpoch;

    public OutboundGateStateMachine(IOutboundGateMonotonicClock clock, IOutboundGateNonceProvider nonces, OutboundGateMode mode = OutboundGateMode.Disabled, long initialPolicyEpoch = 0)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _nonces = nonces ?? throw new ArgumentNullException(nameof(nonces));
        if (!Enum.IsDefined(mode))
            throw new ArgumentOutOfRangeException(nameof(mode));
        ArgumentOutOfRangeException.ThrowIfNegative(initialPolicyEpoch);
        _mode = mode;
        _policyEpoch = initialPolicyEpoch;
    }

    public OutboundGateMode Mode => _mode;
    public long PolicyEpoch => _policyEpoch;
    public GateStateMachineCounters Counters => new(_failedOpenCount, _overflowCount, _contexts.Values.Count(context => !context.IsTerminal), ActiveChallengeCount());
    public IReadOnlyList<CriticalAlert> CriticalAlerts => _criticalAlerts.ToArray();

    public GateTransitionResult ReceiveIntent(FileReadIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (_mode == OutboundGateMode.Disabled)
            return Unsupported(intent.Subject, intent.IntentId, "outbound-gate-disabled");

        if (_contexts.TryGetValue(intent.IntentId, out var existing))
        {
            if (!existing.Intent.Equals(intent))
                throw new InvalidOperationException("Duplicate intent ID has a different payload.");
            return existing.Result with { IsDuplicate = true };
        }

        var now = RequireClock(_clock.Now());
        if (!now.ClockInstanceId.Equals(intent.ReadWindow.StartedAt.ClockInstanceId) || !intent.ReadWindow.Contains(now))
            return FailOpenWithoutContext(intent.Subject, intent.IntentId, "intent-clock-or-deadline-invalid", now);

        if (PendingCountFor(intent.Subject) >= MaximumPendingPerSubject || PendingCount() >= MaximumPendingGlobal)
            return FailOpenWithoutContext(intent.Subject, intent.IntentId, "pending-intent-capacity-exhausted", now, overflow: true);

        var armWindow = NewWindow(now, OutboundGateLimits.MaximumGateArmReadDuration);
        var request = new GateArmRequest(
            OutboundGateLimits.CurrentVersion,
            intent.IntentId,
            intent.Subject,
            RequiredCoverageFor(intent),
            _policyEpoch,
            _nonces.NextNonce(),
            _nonces.NextNonce(),
            intent.ObservedAtUtc,
            armWindow);
        var status = Status(intent.Subject, intent.IntentId, GateRuntimeState.Idle, "intent-received", now, trafficFailedOpen: false);
        var result = new GateTransitionResult(status, armRequest: request);
        _contexts.Add(intent.IntentId, new Context(intent, request, result));
        return result;
    }

    public GateTransitionResult ReceiveGateArmAck(GateArmAck ack)
    {
        ArgumentNullException.ThrowIfNull(ack);
        if (!_contexts.TryGetValue(ack.IntentId, out var context))
            throw new InvalidOperationException("Gate acknowledgement references an unknown intent.");
        if (context.Ack is not null)
        {
            if (context.Ack.Equals(ack))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate gate acknowledgement ID or intent has a different payload.");
        }
        if (context.IsTerminal)
            throw new InvalidOperationException("A terminal intent cannot accept a gate acknowledgement.");

        var receipt = RequireClock(_clock.Now());
        try
        {
            ack.ValidateFor(context.Request, receipt);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
        {
            return FailOpen(context, "gate-ack-invalid-or-expired", receipt);
        }

        context.Ack = ack;
        var status = Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Armed, "gate-armed", receipt, false, context.Request.RequiredCoverage);
        context.Result = new GateTransitionResult(status, context.Request);
        return context.Result;
    }

    public GateTransitionResult ReleaseAfterGateArmed() =>
        ReleaseAfterGateArmed(RequireSingleActiveContext().Intent.IntentId);

    public GateTransitionResult ReleaseAfterGateArmed(Guid intentId)
    {
        if (!_contexts.TryGetValue(intentId, out var context))
            throw new InvalidOperationException("Release references an unknown intent.");
        if (context.Disposition is not null)
            return context.Result with { IsDuplicate = true };
        if (context.Ack is null)
            throw new InvalidOperationException("A read cannot be released before a full-coverage gate acknowledgement.");
        var now = RequireClock(_clock.Now());
        var disposition = new FileReadDisposition(1, context.Intent.IntentId, context.Intent.Subject.ProcessIdentity, context.Intent.File, FileReadDispositionKind.ReleaseAfterGateArmed, context.Ack.AckId, context.Request.ArmWindow, "gate-armed", ++_sequence);
        context.Disposition = disposition;
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Armed, "read-release-authorized", now, false, context.Request.RequiredCoverage), context.Request, disposition);
        return context.Result;
    }

    public GateTransitionResult AcceptCompletion(FileReadCompletionAck completion) =>
        AcceptCompletion(completion, completion?.MinifilterGeneration ?? Guid.Empty);

    public GateTransitionResult AcceptCompletion(FileReadCompletionAck completion, Guid expectedMinifilterGeneration)
    {
        ArgumentNullException.ThrowIfNull(completion);
        OutboundGateLimits.GuidValue(expectedMinifilterGeneration, nameof(expectedMinifilterGeneration));
        if (!_contexts.TryGetValue(completion.IntentId, out var context))
            throw new InvalidOperationException("Completion references an unknown intent.");
        if (context.Completion is not null)
        {
            if (context.Completion.Equals(completion))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate completion ID has a different payload.");
        }
        if (completion.MinifilterGeneration != expectedMinifilterGeneration
            || (context.AcceptedMinifilterGeneration is not null && context.AcceptedMinifilterGeneration != completion.MinifilterGeneration)
            || context.Disposition is null
            || !completion.IsBoundTo(context.Disposition, expectedMinifilterGeneration))
            throw new InvalidOperationException("Completion is not bound to the exact accepted disposition.");
        context.AcceptedMinifilterGeneration = completion.MinifilterGeneration;
        context.Completion = completion;
        context.Result = context.Result with { IsDuplicate = false };
        return context.Result;
    }

    public GateTransitionResult ReceiveChallenge(NetworkGateChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        if (!_contexts.TryGetValue(challenge.IntentId, out var context))
            throw new InvalidOperationException("Challenge references an unknown intent.");
        if (context.Challenge is not null)
        {
            if (context.Challenge.Equals(challenge))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate challenge ID has a different payload.");
        }
        if (context.Ack is null || context.Disposition is null || context.Completion is null)
            throw new InvalidOperationException("A challenge requires an armed gate and completed read disposition.");
        if (!context.Intent.Subject.Matches(challenge.Subject) || challenge.RequiredCoverage.Flags == GateCoverageFlags.None)
            throw new InvalidOperationException("Challenge subject or coverage does not match the intent.");
        if (ActiveChallengeCountFor(challenge.Subject) >= MaximumChallengesPerSubject || ActiveChallengeCount() >= MaximumChallengesGlobal)
            return FailOpen(context, "active-challenge-capacity-exhausted", RequireClock(_clock.Now()), overflow: true);

        var now = RequireClock(_clock.Now());
        if (!challenge.DecisionWindow.Contains(now) || challenge.DecisionWindow.StartedAt.ClockInstanceId != now.ClockInstanceId)
            return FailOpen(context, "challenge-clock-or-deadline-invalid", now);
        context.Challenge = challenge;
        _challengeToIntent.Add(challenge.ChallengeId, challenge.IntentId);
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.AwaitingDecision, "challenge-received", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, challenge: challenge);
        return context.Result;
    }

    public GateTransitionResult ReceiveDecision(UserDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        if (!_challengeToIntent.TryGetValue(decision.ChallengeId, out var intentId) || !_contexts.TryGetValue(intentId, out var context) || context.Challenge is null)
            throw new InvalidOperationException("Decision references an unknown challenge.");
        if (context.Decision is not null)
        {
            if (context.Decision.Equals(decision))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate decision ID has a different payload.");
        }
        var now = RequireClock(_clock.Now());
        if (!context.Challenge.DecisionWindow.Contains(now))
            return FailOpen(context, "decision-deadline-expired", now);
        decision.ValidatePersistentScopeFor(context.Challenge, context.Intent.File);
        context.Decision = decision;
        if (decision.Decision == UserDecisionKind.Block)
        {
            context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Blocked, "user-blocked-current-flow", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, context.Challenge);
            return context.Result;
        }
        var ticket = IssueTicket(context, now);
        context.Ticket = ticket;
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.AwaitingDecision, "ticket-issued-simulation", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, context.Challenge, ticket);
        return context.Result;
    }

    public GateTransitionResult RedeemTicket(OneTimeTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        if (!_contexts.TryGetValue(ticket.IntentId, out var context) || context.Ticket is null)
            throw new InvalidOperationException("Ticket references an unknown or unissued intent.");
        if (context.Grant is not null)
        {
            if (context.Ticket.Equals(ticket))
                return context.Result with { IsDuplicate = true, Grant = context.Grant };
            throw new InvalidOperationException("A different ticket cannot redeem the same transition.");
        }
        if (!context.Ticket.Equals(ticket))
            throw new InvalidOperationException("Ticket binding does not match the issued ticket.");
        var now = RequireClock(_clock.Now());
        if (!ticket.ValidityWindow.Contains(now) || ticket.ValidityWindow.StartedAt.ClockInstanceId != now.ClockInstanceId)
            return FailOpen(context, "ticket-expired-or-clock-invalid", now);
        var grantWindow = NewWindow(now, OutboundGateLimits.MaximumGrantDuration);
        var grant = new EphemeralFlowGrant(1, _nonces.NextNonce(), ticket.TicketId, ticket.IntentId, ticket.Subject, ticket.Destination, ticket.FlowGeneration, ticket.PolicyEpoch, ticket.BootInstance, ticket.GrantMaxBytes, grantWindow);
        context.Grant = grant;
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Granted, "ticket-redeemed-simulation", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, context.Challenge, ticket, grant);
        return context.Result;
    }

    public IReadOnlyList<GateStatus> ProcessExpired()
    {
        var now = RequireClock(_clock.Now());
        var statuses = new List<GateStatus>();
        foreach (var context in _contexts.Values.Where(context => !context.IsTerminal).ToArray())
        {
            if ((context.Ack is null && !context.Request.ArmWindow.Contains(now))
                || (context.Challenge is not null && context.Decision is null && !context.Challenge.DecisionWindow.Contains(now))
                || (context.Ticket is not null && context.Grant is null && !context.Ticket.ValidityWindow.Contains(now)))
            {
                statuses.Add(FailOpen(context, "monotonic-deadline-expired", now).Status);
            }
        }
        return statuses;
    }

    public IReadOnlyList<GateStatus> HandleServiceRestart(Guid newBootInstance)
    {
        OutboundGateLimits.GuidValue(newBootInstance, nameof(newBootInstance));
        var now = RequireClock(_clock.Now());
        var statuses = new List<GateStatus>();
        foreach (var context in _contexts.Values.Where(context => !context.IsTerminal).ToArray())
            statuses.Add(FailOpen(context, "service-restart-invalidated-state", now).Status);
        return statuses;
    }

    public IReadOnlyList<GateStatus> ApplyPolicyEpoch(long policyEpoch)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(policyEpoch);
        if (policyEpoch < _policyEpoch)
            throw new ArgumentOutOfRangeException(nameof(policyEpoch), "Policy epoch cannot move backwards.");
        _policyEpoch = policyEpoch;
        var now = RequireClock(_clock.Now());
        var statuses = new List<GateStatus>();
        foreach (var context in _contexts.Values.Where(context => !context.IsTerminal && context.Request.PolicyEpoch != policyEpoch).ToArray())
            statuses.Add(FailOpen(context, "policy-epoch-changed", now).Status);
        return statuses;
    }

    private GateTransitionResult Unsupported(GateSubject subject, Guid intentId, string reason)
    {
        var now = RequireClock(_clock.Now());
        return new GateTransitionResult(Status(subject, intentId, GateRuntimeState.Unsupported, reason, now, false));
    }

    private GateTransitionResult FailOpenWithoutContext(GateSubject subject, Guid intentId, string reason, ServiceMonotonicTimestamp now, bool overflow = false)
    {
        if (overflow)
            _overflowCount++;
        _failedOpenCount++;
        var scope = new GateAffectedScope(1, GateAffectedScopeKind.Intent, intentId, subject);
        var alert = Alert(reason, scope, now);
        return new GateTransitionResult(Status(subject, intentId, GateRuntimeState.FailedOpen, reason, now, true), criticalAlert: alert);
    }

    private GateTransitionResult FailOpen(Context context, string reason, ServiceMonotonicTimestamp now, bool overflow = false)
    {
        if (context.IsTerminal)
            return context.Result;
        if (overflow)
            _overflowCount++;
        _failedOpenCount++;
        var status = Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.FailedOpen, reason, now, true, context.Request.RequiredCoverage);
        var alert = Alert(reason, new GateAffectedScope(1, GateAffectedScopeKind.Intent, context.Intent.IntentId, context.Intent.Subject), now);
        context.Result = new GateTransitionResult(status, context.Request, context.Disposition, context.Challenge, context.Ticket, context.Grant, alert);
        return context.Result;
    }

    private CriticalAlert Alert(string reason, GateAffectedScope scope, ServiceMonotonicTimestamp now)
    {
        var alert = new CriticalAlert(1, _nonces.NextNonce(), reason, scope, AuditUtc(now), now, _failedOpenCount, _overflowCount, true);
        _criticalAlerts.Add(alert);
        return alert;
    }

    private OneTimeTicket IssueTicket(Context context, ServiceMonotonicTimestamp now)
    {
        var validity = NewWindow(now, OutboundGateLimits.MaximumTicketValidity);
        var auditIssued = AuditUtc(now);
        return new OneTimeTicket(1, _nonces.NextNonce(), _nonces.NextNonce(), context.Intent.IntentId, context.Intent.Subject, context.Intent.File, context.Challenge!.Destination, context.Challenge.FlowGeneration, context.Request.PolicyEpoch, context.Intent.BootInstance, auditIssued, auditIssued.AddSeconds(5), validity, OutboundGateLimits.MaximumGrantBytes, (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds, [1]);
    }

    private GateStatus Status(GateSubject subject, Guid intentId, GateRuntimeState state, string reason, ServiceMonotonicTimestamp now, bool trafficFailedOpen, GateCoverage? coverage = null) =>
        new(1, _mode, state, coverage ?? new GateCoverage(1, GateCoverageFlags.NewTcp), reason, new GateAffectedScope(1, GateAffectedScopeKind.Intent, intentId, subject), AuditUtc(now), now, 0, _overflowCount, trafficFailedOpen);

    private static ServiceMonotonicTimestamp RequireClock(ServiceMonotonicTimestamp timestamp) => timestamp ?? throw new InvalidOperationException("Clock returned null.");

    private static ServiceMonotonicTimeRange NewWindow(ServiceMonotonicTimestamp start, TimeSpan duration) =>
        new(1, start, new ServiceMonotonicTimestamp(1, start.ClockInstanceId, checked(start.ElapsedMilliseconds + (long)duration.TotalMilliseconds)));

    private static DateTimeOffset AuditUtc(ServiceMonotonicTimestamp timestamp) => DateTimeOffset.UnixEpoch.AddMilliseconds(timestamp.ElapsedMilliseconds);

    private int PendingCount() => _contexts.Values.Count(context => !context.IsTerminal && context.Ack is null);
    private int PendingCountFor(GateSubject subject) => _contexts.Values.Count(context => !context.IsTerminal && context.Ack is null && context.Intent.Subject.Matches(subject));
    private int ActiveChallengeCount() => _contexts.Values.Count(context => !context.IsTerminal && context.Challenge is not null);
    private int ActiveChallengeCountFor(GateSubject subject) => _contexts.Values.Count(context => !context.IsTerminal && context.Challenge is not null && context.Intent.Subject.Matches(subject));
    private Context RequireSingleActiveContext() => _contexts.Values.SingleOrDefault(context => !context.IsTerminal) ?? throw new InvalidOperationException("Exactly one active intent is required for this operation.");

    private static GateCoverage RequiredCoverageFor(FileReadIntent intent) =>
        new(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);

    private sealed class Context
    {
        public Context(FileReadIntent intent, GateArmRequest request, GateTransitionResult result)
        {
            Intent = intent;
            Request = request;
            Result = result;
        }

        public FileReadIntent Intent { get; }
        public GateArmRequest Request { get; }
        public GateArmAck? Ack { get; set; }
        public FileReadDisposition? Disposition { get; set; }
        public FileReadCompletionAck? Completion { get; set; }
        public Guid? AcceptedMinifilterGeneration { get; set; }
        public NetworkGateChallenge? Challenge { get; set; }
        public UserDecision? Decision { get; set; }
        public OneTimeTicket? Ticket { get; set; }
        public EphemeralFlowGrant? Grant { get; set; }
        public GateTransitionResult Result { get; set; }
        public bool IsTerminal => Result.Status.State is GateRuntimeState.Granted or GateRuntimeState.Blocked or GateRuntimeState.FailedOpen or GateRuntimeState.Unsupported;
    }
}
