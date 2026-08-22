namespace EgressGuard.Core;

public interface IOutboundGateMonotonicClock
{
    ServiceMonotonicTimestamp Now();
}

public interface IOutboundGateNonceProvider
{
    Guid NextNonce();
}

public interface IOutboundGateAuditClock
{
    DateTimeOffset NowUtc();
}

public sealed record OutboundGateTrustedRuntimeState
{
    public Guid BootInstance { get; }
    public Guid WfpGeneration { get; }
    public Guid MinifilterGeneration { get; }

    public OutboundGateTrustedRuntimeState(Guid bootInstance, Guid wfpGeneration, Guid minifilterGeneration)
    {
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        OutboundGateLimits.GuidValue(wfpGeneration, nameof(wfpGeneration));
        OutboundGateLimits.GuidValue(minifilterGeneration, nameof(minifilterGeneration));
        BootInstance = bootInstance;
        WfpGeneration = wfpGeneration;
        MinifilterGeneration = minifilterGeneration;
    }
}

public sealed record GateStateMachineCounters(long FailedOpenCount, long OverflowCount, long ActiveIntentCount, long ActiveChallengeCount);

public sealed record GateStateMachineStorageSnapshot(
    int ActiveContextCount,
    int TerminalHistoryCount,
    int ChallengeMappingCount,
    int CriticalAlertCount,
    int ActiveContextCapacity,
    int TerminalHistoryCapacity,
    int ChallengeMappingCapacity,
    int CriticalAlertCapacity);

public sealed record GateTransitionResult
{
    public int Version { get; init; }
    public GateStatus Status { get; init; }
    public GateArmRequest? ArmRequest { get; init; }
    public FileReadDisposition? Disposition { get; init; }
    public FileReadCompletionAck? Completion { get; init; }
    public NetworkGateChallenge? Challenge { get; init; }
    public OneTimeTicket? Ticket { get; init; }
    public EphemeralFlowGrant? Grant { get; init; }
    public CriticalAlert? CriticalAlert { get; init; }
    public bool IsDuplicate { get; init; }

    internal GateTransitionResult(GateStatus status, GateArmRequest? armRequest = null, FileReadDisposition? disposition = null, NetworkGateChallenge? challenge = null, OneTimeTicket? ticket = null, EphemeralFlowGrant? grant = null, CriticalAlert? criticalAlert = null, bool isDuplicate = false, FileReadCompletionAck? completion = null)
    {
        Version = OutboundGateLimits.CurrentVersion;
        Status = status;
        ArmRequest = armRequest;
        Disposition = disposition;
        Completion = completion;
        Challenge = challenge;
        Ticket = ticket;
        Grant = grant;
        CriticalAlert = criticalAlert;
        IsDuplicate = isDuplicate;
    }
}

public sealed class OutboundGateStateMachine : IDisposable
{
    private const int MaximumPendingPerSubject = 4;
    private const int MaximumPendingGlobal = 64;
    private const int MaximumChallengesPerSubject = 4;
    private const int MaximumChallengesGlobal = 128;
    private const int MaximumActiveContexts = 256;
    private const int MaximumTerminalHistory = 256;
    private const int MaximumCriticalAlerts = 256;

    private readonly IOutboundGateMonotonicClock _clock;
    private readonly IOutboundGateNonceProvider _nonces;
    private readonly IOutboundGateAuditClock _auditClock;
    private readonly OutboundGateMode _mode;
    private readonly OneTimeGateTicketService? _ticketService;
    private readonly object _transitionSync = new();
    private readonly Dictionary<Guid, Context> _activeContexts = new();
    private readonly Dictionary<Guid, TerminalRecord> _terminalHistory = new();
    private readonly Queue<Guid> _terminalOrder = new();
    private readonly Dictionary<Guid, Guid> _challengeToIntent = new();
    private readonly Queue<CriticalAlert> _criticalAlerts = new();
    private OutboundGateTrustedRuntimeState? _trustedRuntime;
    private long _failedOpenCount;
    private long _overflowCount;
    private long _sequence;
    private long _policyEpoch;

    public OutboundGateStateMachine(
        IOutboundGateMonotonicClock clock,
        IOutboundGateNonceProvider nonces,
        IOutboundGateAuditClock auditClock,
        OutboundGateMode mode = OutboundGateMode.Disabled,
        long initialPolicyEpoch = 0,
        OutboundGateTrustedRuntimeState? trustedRuntime = null,
        OneTimeGateTicketService? ticketService = null)
    {
        _clock = clock ?? throw new ArgumentNullException(nameof(clock));
        _nonces = nonces ?? throw new ArgumentNullException(nameof(nonces));
        _auditClock = auditClock ?? throw new ArgumentNullException(nameof(auditClock));
        if (!Enum.IsDefined(mode))
            throw new ArgumentOutOfRangeException(nameof(mode));
        ArgumentOutOfRangeException.ThrowIfNegative(initialPolicyEpoch);
        if (mode == OutboundGateMode.Simulation && trustedRuntime is null)
            throw new ArgumentNullException(nameof(trustedRuntime), "Simulation requires service-owned boot and endpoint generations.");
        _mode = mode;
        _policyEpoch = initialPolicyEpoch;
        _trustedRuntime = trustedRuntime;
        _ticketService = mode == OutboundGateMode.Simulation
            ? ticketService ?? new OneTimeGateTicketService(_clock, _auditClock, _nonces, new HmacSha256BootTicketAuthenticator(trustedRuntime!.BootInstance), initialPolicyEpoch)
            : ticketService;
        if (_ticketService is not null
            && (_ticketService.PolicyEpoch != initialPolicyEpoch
                || (trustedRuntime is not null && _ticketService.BootInstance != trustedRuntime.BootInstance)))
            throw new ArgumentException("Ticket service runtime does not match the state-machine runtime.", nameof(ticketService));
    }

    public OutboundGateMode Mode => _mode;
    public long PolicyEpoch => _policyEpoch;
    public OutboundGateTrustedRuntimeState? TrustedRuntime => _trustedRuntime;
    public GateStateMachineCounters Counters => new(_failedOpenCount, _overflowCount, _activeContexts.Count, _challengeToIntent.Count);
    public IReadOnlyList<CriticalAlert> CriticalAlerts => _criticalAlerts.ToArray();
    public GateStateMachineStorageSnapshot Storage => new(
        _activeContexts.Count,
        _terminalHistory.Count,
        _challengeToIntent.Count,
        _criticalAlerts.Count,
        MaximumActiveContexts,
        MaximumTerminalHistory,
        MaximumChallengesGlobal,
        MaximumCriticalAlerts);

    public GateTransitionResult ReceiveIntent(FileReadIntent intent)
    {
        ArgumentNullException.ThrowIfNull(intent);
        if (_mode == OutboundGateMode.Disabled)
            return Unsupported(intent.Subject, intent.IntentId, "outbound-gate-disabled");

        if (TryGetExistingIntent(intent, out var duplicate))
            return duplicate!;

        var now = RequireClock(_clock.Now());
        var runtime = RequireTrustedRuntime();
        if (intent.BootInstance != runtime.BootInstance)
            return FailOpenWithoutContext(intent, "intent-boot-instance-invalid", now);
        if (!SameClock(now, intent.ReadWindow.Deadline)
            || now.ElapsedMilliseconds < intent.ReadWindow.StartedAt.ElapsedMilliseconds
            || DeadlineReached(now, intent.ReadWindow.Deadline))
            return FailOpenWithoutContext(intent, "intent-clock-or-deadline-invalid", now);

        if (_activeContexts.Count >= MaximumActiveContexts
            || PendingCountFor(intent.Subject) >= MaximumPendingPerSubject
            || PendingCount() >= MaximumPendingGlobal)
            return FailOpenWithoutContext(intent, "pending-intent-capacity-exhausted", now, overflow: true);

        var armWindow = NewClampedWindow(now, OutboundGateLimits.MaximumGateArmReadDuration, intent.ReadWindow.Deadline);
        if (armWindow is null)
            return FailOpenWithoutContext(intent, "intent-deadline-exhausted", now);

        var request = new GateArmRequest(
            OutboundGateLimits.CurrentVersion,
            intent.IntentId,
            intent.Subject,
            RequiredCoverageFor(intent),
            _policyEpoch,
            runtime.WfpGeneration,
            _nonces.NextNonce(),
            intent.ObservedAtUtc,
            armWindow);
        var status = Status(intent.Subject, intent.IntentId, GateRuntimeState.Idle, "intent-received", now, trafficFailedOpen: false, request.RequiredCoverage);
        var result = new GateTransitionResult(status, armRequest: request);
        _activeContexts.Add(intent.IntentId, new Context(intent, request, runtime, result));
        return result;
    }

    public GateTransitionResult ReceiveGateArmAck(GateArmAck ack)
    {
        ArgumentNullException.ThrowIfNull(ack);
        var context = RequireActiveContext(ack.IntentId, "Gate acknowledgement");
        if (context.Ack is not null)
        {
            if (AckMatches(context.Ack, ack))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate gate acknowledgement has a different payload.");
        }
        RequirePhase(context, ContextPhase.AwaitingArmAcknowledgement, "Gate acknowledgement");

        var receipt = RequireClock(_clock.Now());
        if (DeadlineReached(receipt, context.PhaseDeadline))
            return FailOpen(context, "gate-ack-deadline-expired", receipt);
        try
        {
            if (ack.DriverGeneration != context.ExpectedWfpGeneration)
                throw new InvalidOperationException("Gate acknowledgement has an untrusted WFP generation.");
            ack.ValidateFor(context.Request, receipt);
        }
        catch (Exception exception) when (exception is InvalidOperationException or ArgumentException)
        {
            return FailOpen(context, "gate-ack-invalid-or-expired", receipt);
        }

        context.Ack = ack;
        context.Phase = ContextPhase.AwaitingDisposition;
        var status = Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Armed, "gate-armed", receipt, false, context.Request.RequiredCoverage);
        context.Result = new GateTransitionResult(status, context.Request);
        return context.Result;
    }

    public GateTransitionResult ReleaseAfterGateArmed() =>
        ReleaseAfterGateArmed(RequireSingleActiveContext().Intent.IntentId);

    public GateTransitionResult ReleaseAfterGateArmed(Guid intentId)
    {
        if (!_activeContexts.ContainsKey(intentId) && _terminalHistory.TryGetValue(intentId, out var terminal))
        {
            if (terminal.Disposition is null)
                throw new InvalidOperationException("Release cannot mutate a terminal intent without an accepted disposition.");
            return terminal.ReplayResult with { IsDuplicate = true, Disposition = terminal.Disposition };
        }
        var context = RequireActiveContext(intentId, "Release");
        if (context.Disposition is not null)
            return context.Result with { IsDuplicate = true };
        RequirePhase(context, ContextPhase.AwaitingDisposition, "Release");
        if (context.Ack is null || context.Ack.DriverGeneration != context.ExpectedWfpGeneration)
            throw new InvalidOperationException("A read cannot be released before a trusted full-coverage gate acknowledgement.");
        var now = RequireClock(_clock.Now());
        if (DeadlineReached(now, context.PhaseDeadline))
            return FailOpen(context, "disposition-deadline-expired", now);

        var disposition = new FileReadDisposition(1, context.Intent.IntentId, context.Intent.Subject.ProcessIdentity, context.Intent.File, FileReadDispositionKind.ReleaseAfterGateArmed, context.Ack.AckId, context.Request.ArmWindow, "gate-armed", ++_sequence);
        context.Disposition = disposition;
        context.Phase = ContextPhase.AwaitingCompletion;
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Armed, "read-release-authorized", now, false, context.Request.RequiredCoverage), context.Request, disposition);
        return context.Result;
    }

    public GateTransitionResult ReleaseAfterGateArmed(FileReadDisposition disposition)
    {
        ArgumentNullException.ThrowIfNull(disposition);
        if (!_activeContexts.ContainsKey(disposition.IntentId) && _terminalHistory.TryGetValue(disposition.IntentId, out var terminal))
        {
            if (terminal.Disposition is null || !DispositionMatches(terminal.Disposition, disposition))
                throw new InvalidOperationException("Terminal disposition fingerprint does not match.");
            return terminal.ReplayResult with { IsDuplicate = true, Disposition = terminal.Disposition };
        }
        var context = RequireActiveContext(disposition.IntentId, "Release");
        if (context.Disposition is not null)
        {
            if (DispositionMatches(context.Disposition, disposition))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Disposition fingerprint does not match the accepted disposition.");
        }
        throw new InvalidOperationException("A disposition payload cannot create a release; use the intent transition.");
    }

    public GateTransitionResult AcceptCompletion(FileReadCompletionAck completion)
    {
        ArgumentNullException.ThrowIfNull(completion);
        if (!_activeContexts.ContainsKey(completion.IntentId) && _terminalHistory.TryGetValue(completion.IntentId, out var terminal))
        {
            if (terminal.Completion is null || !CompletionMatches(terminal.Completion, completion))
                throw new InvalidOperationException("Terminal completion fingerprint does not match.");
            return terminal.ReplayResult with { IsDuplicate = true, Completion = terminal.Completion, Disposition = terminal.Disposition };
        }
        var context = RequireActiveContext(completion.IntentId, "Completion");
        if (context.Completion is not null)
        {
            if (CompletionMatches(context.Completion, completion))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate completion has a different payload.");
        }
        RequirePhase(context, ContextPhase.AwaitingCompletion, "Completion");
        var now = RequireClock(_clock.Now());
        if (DeadlineReached(now, context.PhaseDeadline))
            return FailOpen(context, "completion-deadline-expired", now);
        if (context.Disposition is null
            || completion.Result != FileReadCompletionResult.Released
            || completion.MinifilterGeneration != context.ExpectedMinifilterGeneration
            || !completion.IsBoundTo(context.Disposition, context.ExpectedMinifilterGeneration))
        {
            context.CompletionAttempt = completion;
            return FailOpen(context, "completion-binding-or-generation-invalid", now);
        }

        context.Completion = completion;
        context.CompletionAttempt = completion;
        context.Phase = ContextPhase.AwaitingChallenge;
        context.PhaseDeadline = NewDeadline(now, OutboundGateLimits.MaximumDecisionHoldDuration);
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Armed, "read-completion-accepted", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition);
        return context.Result;
    }

    public GateTransitionResult ReceiveChallengeAdmissionFailure(ChallengeAdmissionFailure failure)
    {
        lock (_transitionSync)
            return ReceiveChallengeAdmissionFailureCore(failure);
    }

    private GateTransitionResult ReceiveChallengeAdmissionFailureCore(ChallengeAdmissionFailure failure)
    {
        ArgumentNullException.ThrowIfNull(failure);
        if (_mode != OutboundGateMode.Simulation)
            throw new InvalidOperationException("Challenge admission failures are supported only in Simulation mode.");

        var existingFailure = _terminalHistory.Values.FirstOrDefault(item => item.ChallengeAdmissionFailure?.FailureId == failure.FailureId);
        if (existingFailure?.ChallengeAdmissionFailure is { } acceptedFailure)
        {
            if (ChallengeAdmissionFailureMatches(acceptedFailure, failure))
                return existingFailure.ReplayResult with { IsDuplicate = true };
            throw new InvalidOperationException("Challenge admission failure ID is already bound to different metadata.");
        }
        if (_terminalHistory.ContainsKey(failure.IntentId))
            throw new InvalidOperationException("Challenge admission failure cannot mutate a terminal intent with a different fingerprint.");

        var context = RequireActiveContext(failure.IntentId, "Challenge admission failure");
        RequirePhase(context, ContextPhase.AwaitingChallenge, "Challenge admission failure");
        if (context.Challenge is not null || context.Decision is not null || context.Ticket is not null || context.Grant is not null)
            throw new InvalidOperationException("Challenge admission failure cannot replace existing challenge authority.");
        var runtime = RequireTrustedRuntime();
        var now = RequireClock(_clock.Now());
        if (!context.Intent.Subject.Matches(failure.Subject))
            throw new InvalidOperationException("Challenge admission failure subject does not match the intent.");
        if (failure.WfpGeneration != runtime.WfpGeneration || failure.WfpGeneration != context.ExpectedWfpGeneration)
            throw new InvalidOperationException("Challenge admission failure has an untrusted WFP generation.");
        if (failure.FailureKind != ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted)
            throw new InvalidOperationException("Challenge admission failure kind is not allowed.");
        if (failure.ObservedAt != now || DeadlineReached(now, context.PhaseDeadline))
            throw new InvalidOperationException("Challenge admission failure observation is stale or outside the active deadline.");

        return FailOpen(
            context,
            "challenge-admission-held-flow-capacity-exhausted",
            now,
            overflow: true,
            challengeAdmissionFailure: failure);
    }

    public GateTransitionResult ReceiveChallenge(NetworkGateChallenge challenge)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        var context = RequireActiveContext(challenge.IntentId, "Challenge");
        if (context.Challenge is not null)
        {
            if (ChallengeMatches(context.Challenge, challenge))
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate challenge has a different payload.");
        }
        RequirePhase(context, ContextPhase.AwaitingChallenge, "Challenge");
        var now = RequireClock(_clock.Now());
        if (DeadlineReached(now, context.PhaseDeadline))
            return FailOpen(context, "challenge-arrival-deadline-expired", now);
        if (!context.Intent.Subject.Matches(challenge.Subject)
            || challenge.RequiredCoverage != context.Request.RequiredCoverage
            || context.Ack is null
            || !context.Ack.ArmedCoverage.Contains(context.Request.RequiredCoverage))
            return FailOpen(context, "challenge-subject-or-coverage-invalid", now);
        if (!SameClock(now, challenge.DecisionWindow.Deadline)
            || !challenge.DecisionWindow.Contains(now)
            || DeadlineReached(now, challenge.DecisionWindow.Deadline))
            return FailOpen(context, "challenge-clock-or-deadline-invalid", now);
        if (ActiveChallengeCountFor(challenge.Subject) >= MaximumChallengesPerSubject || _challengeToIntent.Count >= MaximumChallengesGlobal)
            return FailOpen(context, "active-challenge-capacity-exhausted", now, overflow: true);
        if (_challengeToIntent.ContainsKey(challenge.ChallengeId)
            || _activeContexts.Values.Any(candidate => candidate.Challenge?.ChallengeId == challenge.ChallengeId))
            throw new InvalidOperationException("Challenge ID is already bound to another intent.");

        context.Challenge = challenge;
        context.Phase = ContextPhase.AwaitingDecision;
        context.PhaseDeadline = EarlierDeadline(NewDeadline(now, OutboundGateLimits.MaximumDecisionHoldDuration), challenge.DecisionWindow.Deadline);
        _challengeToIntent.Add(challenge.ChallengeId, challenge.IntentId);
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.AwaitingDecision, "challenge-received", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, challenge: challenge);
        return context.Result;
    }

    public GateTransitionResult ReceiveDecision(UserDecision decision)
    {
        lock (_transitionSync)
            return ReceiveDecisionCore(decision);
    }

    private GateTransitionResult ReceiveDecisionCore(UserDecision decision)
    {
        ArgumentNullException.ThrowIfNull(decision);
        var context = FindActiveContextForChallenge(decision.ChallengeId);
        if (context.Decision is not null)
        {
            if (context.Decision == decision)
                return context.Result with { IsDuplicate = true };
            throw new InvalidOperationException("Duplicate decision has a different payload.");
        }
        RequirePhase(context, ContextPhase.AwaitingDecision, "Decision");
        var now = RequireClock(_clock.Now());
        if (DeadlineReached(now, context.PhaseDeadline))
            return FailOpen(context, "decision-deadline-expired", now);
        decision.ValidatePersistentScopeFor(context.Challenge!, context.Intent.File);
        context.Decision = decision;
        RemoveChallengeMapping(context);
        if (decision.Decision == UserDecisionKind.Block)
            return CompleteBlocked(context, "user-blocked-current-flow", now);

        var issue = IssueTicket(context, now);
        if (issue.Kind != TicketServiceResultKind.Success || issue.Ticket is null)
            return FailOpen(context, issue.ReasonCode, now, overflow: issue.CapacityFailure);
        var ticket = issue.Ticket;
        context.Ticket = ticket;
        context.Phase = ContextPhase.TicketIssued;
        context.PhaseDeadline = ticket.ValidityWindow.Deadline;
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.AwaitingDecision, "ticket-issued-simulation", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, context.Challenge, ticket);
        return context.Result;
    }

    public PersistentDecisionTransitionResult ReceivePersistentDecision(UserDecision decision, long nextPolicyEpoch)
    {
        lock (_transitionSync)
            return ReceivePersistentDecisionCore(decision, nextPolicyEpoch);
    }

    private PersistentDecisionTransitionResult ReceivePersistentDecisionCore(UserDecision decision, long nextPolicyEpoch)
    {
        ArgumentNullException.ThrowIfNull(decision);
        if (_mode != OutboundGateMode.Simulation)
            throw new InvalidOperationException("Persistent decisions are supported only in Simulation mode.");

        var terminalFailure = _terminalHistory.Values.FirstOrDefault(item =>
            item.RejectedPersistentDecision?.Decision.ChallengeId == decision.ChallengeId);
        if (terminalFailure?.RejectedPersistentDecision is { } rejectedPersistentDecision)
        {
            if (rejectedPersistentDecision.Decision == decision
                && rejectedPersistentDecision.RequestedPolicyEpoch == nextPolicyEpoch)
            {
                var rejectedResult = rejectedPersistentDecision.Result;
                return new PersistentDecisionTransitionResult(
                    rejectedResult.Version,
                    rejectedResult.DecisionResult with { IsDuplicate = true },
                    rejectedResult.InvalidatedStatuses,
                    rejectedResult.PolicyEpoch,
                    policyEpochAccepted: false);
            }
            throw new InvalidOperationException("Duplicate rejected persistent decision has a different decision or policy epoch binding.");
        }

        var context = FindActiveContextForChallenge(decision.ChallengeId);
        if (context.PersistentDecisionResult is { } acceptedPersistentDecision)
        {
            if (context.Decision == decision && acceptedPersistentDecision.PolicyEpoch == nextPolicyEpoch)
            {
                return new PersistentDecisionTransitionResult(
                    acceptedPersistentDecision.Version,
                    acceptedPersistentDecision.DecisionResult with { IsDuplicate = true },
                    acceptedPersistentDecision.InvalidatedStatuses,
                    acceptedPersistentDecision.PolicyEpoch,
                    policyEpochAccepted: true);
            }
            throw new InvalidOperationException("Duplicate persistent decision has a different decision or policy epoch binding.");
        }
        if (context.Decision is not null)
            throw new InvalidOperationException("Persistent decision cannot replace an accepted ordinary decision.");

        RequirePhase(context, ContextPhase.AwaitingDecision, "Persistent decision");
        var now = RequireClock(_clock.Now());
        if (!SameClock(now, context.PhaseDeadline)
            || !context.Challenge!.DecisionWindow.Contains(now)
            || DeadlineReached(now, context.PhaseDeadline)
            || DeadlineReached(now, context.Challenge.DecisionWindow.Deadline))
        {
            return FailOpenPersistentDecision(
                context,
                decision,
                nextPolicyEpoch,
                "persistent-decision-clock-or-deadline-invalid",
                now);
        }

        ArgumentOutOfRangeException.ThrowIfNegative(nextPolicyEpoch);
        var expectedPolicyEpoch = checked(_policyEpoch + 1);
        if (nextPolicyEpoch != expectedPolicyEpoch)
            throw new ArgumentOutOfRangeException(nameof(nextPolicyEpoch), "Persistent decisions must advance the current policy epoch by exactly one.");

        if (!PersistentDecisionMatchesContext(decision, context))
        {
            return new PersistentDecisionTransitionResult(
                OutboundGateLimits.CurrentVersion,
                context.Result,
                Array.Empty<GateStatus>(),
                _policyEpoch,
                policyEpochAccepted: false);
        }
        if (context.EffectivePolicyEpoch != _policyEpoch || _ticketService?.PolicyEpoch != _policyEpoch)
            throw new InvalidOperationException("Persistent decision runtime epoch is inconsistent.");
        if (_activeContexts.Count - 1 > PersistentDecisionTransitionResult.MaximumInvalidatedStatusCount)
            throw new InvalidOperationException("Persistent decision invalidation would exceed the bounded status result.");

        _ticketService!.ApplyPolicyEpoch(nextPolicyEpoch);
        _policyEpoch = nextPolicyEpoch;
        context.EffectivePolicyEpoch = nextPolicyEpoch;

        var invalidatedStatuses = new List<GateStatus>(_activeContexts.Count - 1);
        foreach (var staleContext in _activeContexts.Values
                     .Where(candidate => !ReferenceEquals(candidate, context) && candidate.EffectivePolicyEpoch != nextPolicyEpoch)
                     .ToArray())
        {
            invalidatedStatuses.Add(staleContext.Phase == ContextPhase.Granted
                ? RevokeGrant(staleContext, "policy-epoch-revoked-grant", now).Status
                : FailOpen(staleContext, "policy-epoch-changed", now).Status);
        }

        context.Decision = decision;
        RemoveChallengeMapping(context);
        var issue = IssueTicket(context, now);
        GateTransitionResult decisionResult;
        if (issue.Kind != TicketServiceResultKind.Success || issue.Ticket is null)
        {
            decisionResult = FailOpen(context, issue.ReasonCode, now, overflow: issue.CapacityFailure);
        }
        else
        {
            var ticket = issue.Ticket;
            context.Ticket = ticket;
            context.Phase = ContextPhase.TicketIssued;
            context.PhaseDeadline = ticket.ValidityWindow.Deadline;
            decisionResult = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.AwaitingDecision, "ticket-issued-simulation", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, context.Challenge, ticket);
            context.Result = decisionResult;
        }

        var result = new PersistentDecisionTransitionResult(
            OutboundGateLimits.CurrentVersion,
            decisionResult,
            invalidatedStatuses,
            nextPolicyEpoch,
            policyEpochAccepted: true);
        if (_activeContexts.ContainsKey(context.Intent.IntentId))
            context.PersistentDecisionResult = result;
        return result;
    }

    public GateTransitionResult RedeemTicket(OneTimeTicket ticket)
    {
        lock (_transitionSync)
            return RedeemTicketCore(ticket);
    }

    private GateTransitionResult RedeemTicketCore(OneTimeTicket ticket)
    {
        ArgumentNullException.ThrowIfNull(ticket);
        var context = RequireActiveContext(ticket.IntentId, "Ticket");
        var now = RequireClock(_clock.Now());
        if (context.Phase == ContextPhase.Granted)
        {
            if (DeadlineReached(now, context.PhaseDeadline))
                return RevokeGrant(context, "grant-expired", now);
            throw new InvalidOperationException("A ticket cannot be redeemed after its one-time grant was created.");
        }
        RequirePhase(context, ContextPhase.TicketIssued, "Ticket redemption");
        var runtime = RequireTrustedRuntime();
        if (DeadlineReached(now, context.PhaseDeadline))
            return FailOpen(context, "ticket-expired", now);
        var binding = new TicketAuthorizationBinding(
            ticket.Version,
            context.Intent.IntentId,
            context.Intent.Subject,
            context.Intent.File,
            context.Challenge!.Destination,
            context.Challenge.FlowGeneration,
            runtime.BootInstance,
            _policyEpoch,
            OutboundGateLimits.MaximumGrantBytes,
            (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);
        var redemption = _ticketService!.TryRedeem(ticket, binding);
        if (redemption.Kind == TicketServiceResultKind.Rejected)
            throw new InvalidOperationException(redemption.ReasonCode);
        if (redemption.Kind != TicketServiceResultKind.Success || redemption.Grant is null)
            return FailOpen(context, redemption.ReasonCode, now, overflow: redemption.ReasonCode.Contains("capacity", StringComparison.Ordinal));
        var grant = redemption.Grant;
        context.Grant = grant;
        context.Phase = ContextPhase.Granted;
        context.PhaseDeadline = grant.GrantWindow.Deadline;
        context.Result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Granted, "ticket-redeemed-simulation", now, false, context.Request.RequiredCoverage), context.Request, context.Disposition, context.Challenge, ticket, grant);
        return context.Result;
    }

    public IReadOnlyList<GateStatus> ProcessExpired()
    {
        lock (_transitionSync)
            return ProcessExpiredCore();
    }

    private List<GateStatus> ProcessExpiredCore()
    {
        var now = RequireClock(_clock.Now());
        _ticketService?.PruneExpired();
        var statuses = new List<GateStatus>();
        foreach (var context in _activeContexts.Values.ToArray())
        {
            if (!DeadlineReached(now, context.PhaseDeadline))
                continue;
            statuses.Add(context.Phase == ContextPhase.Granted
                ? RevokeGrant(context, "grant-expired-or-clock-invalid", now).Status
                : FailOpen(context, "monotonic-deadline-expired", now).Status);
        }
        return statuses;
    }

    public IReadOnlyList<GateStatus> HandleServiceRestart(Guid newBootInstance)
    {
        lock (_transitionSync)
        {
            var runtime = RequireTrustedRuntime();
            return HandleServiceRestartCore(new OutboundGateTrustedRuntimeState(newBootInstance, runtime.WfpGeneration, runtime.MinifilterGeneration));
        }
    }

    public IReadOnlyList<GateStatus> HandleServiceRestart(OutboundGateTrustedRuntimeState newRuntime)
    {
        lock (_transitionSync)
            return HandleServiceRestartCore(newRuntime);
    }

    private List<GateStatus> HandleServiceRestartCore(OutboundGateTrustedRuntimeState newRuntime)
    {
        ArgumentNullException.ThrowIfNull(newRuntime);
        var now = RequireClock(_clock.Now());
        _ticketService?.ResetRuntime(newRuntime.BootInstance, _policyEpoch, new HmacSha256BootTicketAuthenticator(newRuntime.BootInstance));
        _trustedRuntime = newRuntime;
        var statuses = new List<GateStatus>();
        foreach (var context in _activeContexts.Values.ToArray())
        {
            statuses.Add(context.Phase == ContextPhase.Granted
                ? RevokeGrant(context, "service-restart-revoked-grant", now).Status
                : FailOpen(context, "service-restart-invalidated-state", now).Status);
        }
        return statuses;
    }

    public IReadOnlyList<GateStatus> ApplyPolicyEpoch(long policyEpoch)
    {
        lock (_transitionSync)
            return ApplyPolicyEpochCore(policyEpoch);
    }

    private IReadOnlyList<GateStatus> ApplyPolicyEpochCore(long policyEpoch)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(policyEpoch);
        if (policyEpoch < _policyEpoch)
            throw new ArgumentOutOfRangeException(nameof(policyEpoch), "Policy epoch cannot move backwards.");
        if (policyEpoch == _policyEpoch)
            return Array.Empty<GateStatus>();
        _ticketService?.ApplyPolicyEpoch(policyEpoch);
        _policyEpoch = policyEpoch;
        var now = RequireClock(_clock.Now());
        var statuses = new List<GateStatus>();
        foreach (var context in _activeContexts.Values.Where(context => context.EffectivePolicyEpoch != policyEpoch).ToArray())
        {
            statuses.Add(context.Phase == ContextPhase.Granted
                ? RevokeGrant(context, "policy-epoch-revoked-grant", now).Status
                : FailOpen(context, "policy-epoch-changed", now).Status);
        }
        return statuses;
    }

    private bool TryGetExistingIntent(FileReadIntent intent, out GateTransitionResult? result)
    {
        if (_activeContexts.TryGetValue(intent.IntentId, out var active))
        {
            if (!IntentMatches(active.Intent, intent))
                throw new InvalidOperationException("Duplicate intent ID has a different payload.");
            result = active.Result with { IsDuplicate = true };
            return true;
        }
        if (_terminalHistory.TryGetValue(intent.IntentId, out var terminal))
        {
            if (!IntentMatches(terminal.Intent, intent))
                throw new InvalidOperationException("Terminal intent ID has a different payload.");
            result = terminal.ReplayResult with { IsDuplicate = true };
            return true;
        }
        result = null;
        return false;
    }

    private Context RequireActiveContext(Guid intentId, string operation)
    {
        if (_activeContexts.TryGetValue(intentId, out var context))
            return context;
        if (_terminalHistory.ContainsKey(intentId))
            throw new InvalidOperationException($"{operation} cannot mutate a terminal intent.");
        throw new InvalidOperationException($"{operation} references an unknown intent.");
    }

    private Context FindActiveContextForChallenge(Guid challengeId)
    {
        if (_challengeToIntent.TryGetValue(challengeId, out var intentId))
            return RequireActiveContext(intentId, "Decision");
        var context = _activeContexts.Values.SingleOrDefault(candidate => candidate.Challenge?.ChallengeId == challengeId);
        return context ?? throw new InvalidOperationException("Decision references an unknown or terminal challenge.");
    }

    private static void RequirePhase(Context context, ContextPhase expected, string operation)
    {
        if (context.Phase != expected)
            throw new InvalidOperationException($"{operation} is invalid while the intent is in phase {context.Phase}.");
    }

    private GateTransitionResult Unsupported(GateSubject subject, Guid intentId, string reason)
    {
        var now = RequireClock(_clock.Now());
        return new GateTransitionResult(Status(subject, intentId, GateRuntimeState.Unsupported, reason, now, false));
    }

    private GateTransitionResult FailOpenWithoutContext(FileReadIntent intent, string reason, ServiceMonotonicTimestamp now, bool overflow = false)
    {
        if (overflow)
            _overflowCount++;
        _failedOpenCount++;
        var alert = Alert(reason, new GateAffectedScope(1, GateAffectedScopeKind.Intent, intent.IntentId, intent.Subject), now);
        var result = new GateTransitionResult(Status(intent.Subject, intent.IntentId, GateRuntimeState.FailedOpen, reason, now, true), criticalAlert: alert);
        RememberTerminal(intent, result);
        return result;
    }

    private GateTransitionResult FailOpen(Context context, string reason, ServiceMonotonicTimestamp now, bool overflow = false, ChallengeAdmissionFailure? challengeAdmissionFailure = null)
    {
        if (overflow)
            _overflowCount++;
        _failedOpenCount++;
        var alert = Alert(reason, new GateAffectedScope(1, GateAffectedScopeKind.Intent, context.Intent.IntentId, context.Intent.Subject), now);
        var result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.FailedOpen, reason, now, true, context.Request.RequiredCoverage), criticalAlert: alert, disposition: context.Disposition, completion: context.Completion);
        CompleteTerminal(context, result, challengeAdmissionFailure);
        return result;
    }

    private PersistentDecisionTransitionResult FailOpenPersistentDecision(
        Context context,
        UserDecision decision,
        long requestedPolicyEpoch,
        string reason,
        ServiceMonotonicTimestamp now)
    {
        _failedOpenCount++;
        var alert = Alert(reason, new GateAffectedScope(1, GateAffectedScopeKind.Intent, context.Intent.IntentId, context.Intent.Subject), now);
        var decisionResult = new GateTransitionResult(
            Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.FailedOpen, reason, now, true, context.Request.RequiredCoverage),
            criticalAlert: alert,
            disposition: context.Disposition,
            completion: context.Completion);
        var persistentResult = new PersistentDecisionTransitionResult(
            OutboundGateLimits.CurrentVersion,
            decisionResult,
            Array.Empty<GateStatus>(),
            _policyEpoch,
            policyEpochAccepted: false);
        CompleteTerminal(
            context,
            decisionResult,
            rejectedPersistentDecision: new RejectedPersistentDecision(decision, requestedPolicyEpoch, persistentResult));
        return persistentResult;
    }

    private GateTransitionResult CompleteBlocked(Context context, string reason, ServiceMonotonicTimestamp now)
    {
        var result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Blocked, reason, now, false, context.Request.RequiredCoverage));
        CompleteTerminal(context, result);
        return result;
    }

    private GateTransitionResult RevokeGrant(Context context, string reason, ServiceMonotonicTimestamp now)
    {
        var result = new GateTransitionResult(Status(context.Intent.Subject, context.Intent.IntentId, GateRuntimeState.Blocked, reason, now, false, context.Request.RequiredCoverage));
        CompleteTerminal(context, result);
        return result;
    }

    private void CompleteTerminal(
        Context context,
        GateTransitionResult result,
        ChallengeAdmissionFailure? challengeAdmissionFailure = null,
        RejectedPersistentDecision? rejectedPersistentDecision = null)
    {
        RemoveChallengeMapping(context);
        _activeContexts.Remove(context.Intent.IntentId);
        context.Result = result;
        var replayResult = new GateTransitionResult(
            result.Status,
            disposition: context.Disposition,
            criticalAlert: result.CriticalAlert,
            completion: context.Completion ?? context.CompletionAttempt);
        RememberTerminal(
            context.Intent,
            replayResult,
            context.Disposition,
            context.Completion ?? context.CompletionAttempt,
            challengeAdmissionFailure,
            rejectedPersistentDecision);
        context.Ack = null;
        context.Disposition = null;
        context.Completion = null;
        context.CompletionAttempt = null;
        context.Challenge = null;
        context.Decision = null;
        context.Ticket = null;
        context.Grant = null;
        context.PersistentDecisionResult = null;
    }

    private void RememberTerminal(
        FileReadIntent intent,
        GateTransitionResult result,
        FileReadDisposition? disposition = null,
        FileReadCompletionAck? completion = null,
        ChallengeAdmissionFailure? challengeAdmissionFailure = null,
        RejectedPersistentDecision? rejectedPersistentDecision = null)
    {
        if (_terminalHistory.ContainsKey(intent.IntentId))
            return;
        _terminalHistory.Add(intent.IntentId, new TerminalRecord(intent, result, disposition, completion, challengeAdmissionFailure, rejectedPersistentDecision));
        _terminalOrder.Enqueue(intent.IntentId);
        while (_terminalHistory.Count > MaximumTerminalHistory)
        {
            var oldest = _terminalOrder.Dequeue();
            _terminalHistory.Remove(oldest);
        }
    }

    private void RemoveChallengeMapping(Context context)
    {
        if (context.Challenge is not null)
            _challengeToIntent.Remove(context.Challenge.ChallengeId);
    }

    private CriticalAlert Alert(string reason, GateAffectedScope scope, ServiceMonotonicTimestamp now)
    {
        var alert = new CriticalAlert(1, _nonces.NextNonce(), reason, scope, AuditUtc(now), now, _failedOpenCount, _overflowCount, true);
        _criticalAlerts.Enqueue(alert);
        while (_criticalAlerts.Count > MaximumCriticalAlerts)
            _criticalAlerts.Dequeue();
        return alert;
    }

    private TicketIssueResult IssueTicket(Context context, ServiceMonotonicTimestamp now)
    {
        var runtime = RequireTrustedRuntime();
        var binding = new TicketAuthorizationBinding(
            context.Intent.Version,
            context.Intent.IntentId,
            context.Intent.Subject,
            context.Intent.File,
            context.Challenge!.Destination,
            context.Challenge.FlowGeneration,
            runtime.BootInstance,
            _policyEpoch,
            OutboundGateLimits.MaximumGrantBytes,
            (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds);
        return _ticketService!.TryIssue(binding);
    }

    public void Dispose()
    {
        lock (_transitionSync)
            _ticketService?.Dispose();
    }


    private GateStatus Status(GateSubject subject, Guid intentId, GateRuntimeState state, string reason, ServiceMonotonicTimestamp now, bool trafficFailedOpen, GateCoverage? coverage = null) =>
        new(1, _mode, state, coverage ?? new GateCoverage(1, GateCoverageFlags.NewTcp), reason, new GateAffectedScope(1, GateAffectedScopeKind.Intent, intentId, subject), AuditUtc(now), now, 0, _overflowCount, trafficFailedOpen);

    private OutboundGateTrustedRuntimeState RequireTrustedRuntime() =>
        _trustedRuntime ?? throw new InvalidOperationException("Trusted outbound-gate runtime state is unavailable.");

    private static ServiceMonotonicTimestamp RequireClock(ServiceMonotonicTimestamp timestamp) => timestamp ?? throw new InvalidOperationException("Clock returned null.");

    private static bool SameClock(ServiceMonotonicTimestamp left, ServiceMonotonicTimestamp right) =>
        left.Version == right.Version && left.ClockInstanceId == right.ClockInstanceId;

    private static bool IntentMatches(FileReadIntent left, FileReadIntent right) =>
        left.Version == right.Version
        && left.IntentId == right.IntentId
        && left.Subject.Matches(right.Subject)
        && left.File == right.File
        && left.Operation == right.Operation
        && left.ObservedAtUtc == right.ObservedAtUtc
        && left.ReadWindow == right.ReadWindow
        && left.BootInstance == right.BootInstance
        && left.Sequence == right.Sequence;

    private static bool AckMatches(GateArmAck left, GateArmAck right) =>
        left.Version == right.Version
        && left.AckId == right.AckId
        && left.IntentId == right.IntentId
        && left.Subject.Matches(right.Subject)
        && left.RequiredCoverage == right.RequiredCoverage
        && left.ArmedCoverage == right.ArmedCoverage
        && left.PolicyEpoch == right.PolicyEpoch
        && left.DriverGeneration == right.DriverGeneration
        && left.RequestNonce == right.RequestNonce
        && left.AckNonce == right.AckNonce
        && left.EndpointAcknowledgedAtUtc == right.EndpointAcknowledgedAtUtc
        && left.ArmWindow == right.ArmWindow
        && string.Equals(left.UnsupportedOrDegradedReason, right.UnsupportedOrDegradedReason, StringComparison.Ordinal);

    private static bool CompletionMatches(FileReadCompletionAck left, FileReadCompletionAck right) =>
        left.Version == right.Version
        && left.CompletionId == right.CompletionId
        && left.IntentId == right.IntentId
        && left.ProcessIdentity == right.ProcessIdentity
        && left.File == right.File
        && left.DispositionSequence == right.DispositionSequence
        && left.Disposition == right.Disposition
        && left.GateAckId == right.GateAckId
        && left.Result == right.Result
        && string.Equals(left.ReasonCode, right.ReasonCode, StringComparison.Ordinal)
        && left.MonotonicSequence == right.MonotonicSequence
        && left.MinifilterGeneration == right.MinifilterGeneration;

    private static bool ChallengeMatches(NetworkGateChallenge left, NetworkGateChallenge right) =>
        left.Version == right.Version
        && left.ChallengeId == right.ChallengeId
        && left.IntentId == right.IntentId
        && left.Subject.Matches(right.Subject)
        && left.Destination == right.Destination
        && left.FlowGeneration == right.FlowGeneration
        && left.ExistingFlow == right.ExistingFlow
        && left.RequiredCoverage == right.RequiredCoverage
        && left.CreatedAtUtc == right.CreatedAtUtc
        && left.DecisionWindow == right.DecisionWindow
        && string.Equals(left.LimitationReason, right.LimitationReason, StringComparison.Ordinal);

    private static bool PersistentDecisionMatchesContext(UserDecision decision, Context context)
    {
        var challenge = context.Challenge;
        var scope = decision.RequestedPersistentScope;
        return decision.Decision == UserDecisionKind.AlwaysAllow
            && scope is not null
            && scope.PolicyKind == PersistentAllowPolicyKind.RememberFor30Days
            && challenge is not null
            && decision.ChallengeId == challenge.ChallengeId
            && challenge.IntentId == context.Intent.IntentId
            && context.Intent.Subject.Matches(challenge.Subject)
            && context.Request.Subject.Matches(challenge.Subject)
            && scope.File == context.Intent.File
            && string.Equals(scope.ApplicationIdentity, context.Intent.Subject.ApplicationIdentity, StringComparison.Ordinal)
            && string.Equals(scope.ApplicationIdentity, challenge.Subject.ApplicationIdentity, StringComparison.Ordinal)
            && scope.Destination == challenge.Destination;
    }

    private static bool ChallengeAdmissionFailureMatches(ChallengeAdmissionFailure left, ChallengeAdmissionFailure right) =>
        left.Version == right.Version
        && left.FailureId == right.FailureId
        && left.IntentId == right.IntentId
        && left.Subject.Matches(right.Subject)
        && left.WfpGeneration == right.WfpGeneration
        && left.FailureKind == right.FailureKind
        && left.ObservedAt == right.ObservedAt;

    private static bool DeadlineReached(ServiceMonotonicTimestamp now, ServiceMonotonicTimestamp deadline) =>
        !SameClock(now, deadline) || now.ElapsedMilliseconds >= deadline.ElapsedMilliseconds;

    private static ServiceMonotonicTimestamp NewDeadline(ServiceMonotonicTimestamp start, TimeSpan duration) =>
        new(1, start.ClockInstanceId, checked(start.ElapsedMilliseconds + (long)duration.TotalMilliseconds));

    private static ServiceMonotonicTimestamp EarlierDeadline(ServiceMonotonicTimestamp first, ServiceMonotonicTimestamp second)
    {
        if (!SameClock(first, second))
            throw new InvalidOperationException("Cannot compare deadlines from different clock instances.");
        return first.ElapsedMilliseconds <= second.ElapsedMilliseconds ? first : second;
    }

    private static ServiceMonotonicTimeRange? NewClampedWindow(ServiceMonotonicTimestamp start, TimeSpan duration, ServiceMonotonicTimestamp outerDeadline)
    {
        if (!SameClock(start, outerDeadline))
            return null;
        var deadline = EarlierDeadline(NewDeadline(start, duration), outerDeadline);
        return deadline.ElapsedMilliseconds <= start.ElapsedMilliseconds ? null : new ServiceMonotonicTimeRange(1, start, deadline);
    }

    private static ServiceMonotonicTimeRange NewWindow(ServiceMonotonicTimestamp start, TimeSpan duration) =>
        new(1, start, NewDeadline(start, duration));

    private DateTimeOffset AuditUtc(ServiceMonotonicTimestamp timestamp)
    {
        _ = timestamp;
        var utc = _auditClock.NowUtc();
        if (utc == default)
            throw new InvalidOperationException("Audit clock returned the default timestamp.");
        return utc.ToUniversalTime();
    }

    private int PendingCount() => _activeContexts.Values.Count(IsPendingRead);
    private int PendingCountFor(GateSubject subject) => _activeContexts.Values.Count(context => IsPendingRead(context) && context.Intent.Subject.Matches(subject));
    private int ActiveChallengeCountFor(GateSubject subject) => _activeContexts.Values.Count(context => context.Phase == ContextPhase.AwaitingDecision && context.Intent.Subject.Matches(subject));
    private Context RequireSingleActiveContext() => _activeContexts.Values.SingleOrDefault() ?? throw new InvalidOperationException("Exactly one active intent is required for this operation.");

    private static GateCoverage RequiredCoverageFor(FileReadIntent intent) =>
        new(1, GateCoverageFlags.NewTcp | GateCoverageFlags.NewUdp | GateCoverageFlags.ExistingTcpStream | GateCoverageFlags.ExistingUdpDatagram | GateCoverageFlags.ReconnectRequiredSimulation);

    private enum ContextPhase
    {
        AwaitingArmAcknowledgement,
        AwaitingDisposition,
        AwaitingCompletion,
        AwaitingChallenge,
        AwaitingDecision,
        TicketIssued,
        Granted
    }

    private sealed class Context
    {
        public Context(FileReadIntent intent, GateArmRequest request, OutboundGateTrustedRuntimeState runtime, GateTransitionResult result)
        {
            Intent = intent;
            Request = request;
            ExpectedWfpGeneration = runtime.WfpGeneration;
            ExpectedMinifilterGeneration = runtime.MinifilterGeneration;
            EffectivePolicyEpoch = request.PolicyEpoch;
            PhaseDeadline = request.ArmWindow.Deadline;
            Result = result;
        }

        public FileReadIntent Intent { get; }
        public GateArmRequest Request { get; }
        public Guid ExpectedWfpGeneration { get; }
        public Guid ExpectedMinifilterGeneration { get; }
        public long EffectivePolicyEpoch { get; set; }
        public ContextPhase Phase { get; set; } = ContextPhase.AwaitingArmAcknowledgement;
        public ServiceMonotonicTimestamp PhaseDeadline { get; set; }
        public GateArmAck? Ack { get; set; }
        public FileReadDisposition? Disposition { get; set; }
        public FileReadCompletionAck? Completion { get; set; }
        public FileReadCompletionAck? CompletionAttempt { get; set; }
        public NetworkGateChallenge? Challenge { get; set; }
        public UserDecision? Decision { get; set; }
        public OneTimeTicket? Ticket { get; set; }
        public EphemeralFlowGrant? Grant { get; set; }
        public GateTransitionResult Result { get; set; }
        public PersistentDecisionTransitionResult? PersistentDecisionResult { get; set; }
    }

    private static bool IsPendingRead(Context context) => context.Phase is ContextPhase.AwaitingArmAcknowledgement or ContextPhase.AwaitingDisposition or ContextPhase.AwaitingCompletion;

    private static bool DispositionMatches(FileReadDisposition left, FileReadDisposition right) =>
        left.Version == right.Version
        && left.IntentId == right.IntentId
        && left.ProcessIdentity == right.ProcessIdentity
        && left.File == right.File
        && left.Disposition == right.Disposition
        && left.GateAckId == right.GateAckId
        && left.ReadWindow == right.ReadWindow
        && string.Equals(left.ReasonCode, right.ReasonCode, StringComparison.Ordinal)
        && left.Sequence == right.Sequence;

    private sealed record RejectedPersistentDecision(UserDecision Decision, long RequestedPolicyEpoch, PersistentDecisionTransitionResult Result);

    private sealed record TerminalRecord(
        FileReadIntent Intent,
        GateTransitionResult ReplayResult,
        FileReadDisposition? Disposition,
        FileReadCompletionAck? Completion,
        ChallengeAdmissionFailure? ChallengeAdmissionFailure,
        RejectedPersistentDecision? RejectedPersistentDecision);
}
