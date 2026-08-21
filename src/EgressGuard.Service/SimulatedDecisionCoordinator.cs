using System.Net;
using System.Security.Cryptography;
using System.Text;
using EgressGuard.Core;
using EgressGuard.Protocol;

namespace EgressGuard.Service;

internal static class SimulatedDecisionReasonCodes
{
    internal const string Disabled = "sim-ui-disabled";
    internal const string PromptActive = "sim-ui-prompt-active";
    internal const string AllowOnceAccepted = "sim-ui-allow-once-accepted";
    internal const string RememberAccepted = "sim-ui-remember-30-days-accepted";
    internal const string BlockCurrentAccepted = "sim-ui-block-current-accepted";
    internal const string RuleRevoked = "sim-ui-rule-revoked";
    internal const string RuleIdCollision = "sim-ui-rule-id-collision";
    internal const string RuleIdRegistryCapacityExhausted = "sim-ui-rule-id-retention-capacity-exhausted";
    internal const string RuleRevisionConflict = "sim-ui-rule-revision-conflict";
    internal const string RuleFileVersionInvalidated = "sim-ui-rule-file-version-invalidated";
    internal const string RulePolicyInvalidated = "sim-ui-rule-policy-invalidated";
    internal const string RuleExpired = "sim-ui-rule-expired";
    internal const string ReconnectRequired = "sim-ui-reconnect-required";
    internal const string CriticalFailOpen = "sim-ui-critical-fail-open";
    internal const string AdministratorRequired = "sim-ui-administrator-required";
    internal const string RequestInvalid = "sim-ui-request-invalid";
    internal const string ChallengeNotFound = "sim-ui-challenge-not-found";
    internal const string ChallengeExpired = "sim-ui-challenge-expired";
    internal const string ChallengeTerminal = "sim-ui-challenge-terminal";
    internal const string DecisionConflict = "sim-ui-decision-conflict";
    internal const string RememberedRuleCapacityExhausted = "sim-ui-remembered-rule-capacity-exhausted";
    internal const string ProjectionCapacityExhausted = "sim-ui-projection-capacity-exhausted";
    internal const string SubscriberCapacityExhausted = "sim-ui-subscriber-capacity-exhausted";
    internal const string RememberedRuleNotFound = "sim-ui-remembered-rule-not-found";
    internal const string RuleCommittedTrafficFailedOpen = "sim-ui-remembered-rule-committed-traffic-failed-open";
    internal const string FileVersionStale = "sim-ui-file-version-stale";
    internal const string PolicyEpochStale = "sim-ui-policy-epoch-stale";
    internal const string ResyncRequired = "sim-ui-resync-required";
    internal const string AuthorityResultInvalid = "sim-ui-authority-result-invalid";
}

internal sealed class SimulatedDecisionRequestException : Exception
{
    internal SimulatedDecisionRequestException(string code, string message) : base(message)
    {
        Code = code;
    }

    internal string Code { get; }
}

internal sealed record SimulatedDecisionCaller(string AuthenticatedCaller, bool IsAdministrator)
{
    internal static SimulatedDecisionCaller Administrator(string sid) => new(sid, true);
}

internal sealed record ProtectedFileDisplayMetadata
{
    internal ProtectedFileDisplayMetadata(string redactedFileLabel)
    {
        if (string.IsNullOrWhiteSpace(redactedFileLabel)
            || redactedFileLabel.Length > SimulatedDecisionProtocolLimits.MaximumRedactedFileLabelLength
            || redactedFileLabel.Any(character => character is not (' ' or '.' or '_' or '(' or ')' or '-')
                && character is not (>= 'A' and <= 'Z')
                && character is not (>= 'a' and <= 'z')
                && character is not (>= '0' and <= '9'))
            || redactedFileLabel.Contains(':', StringComparison.Ordinal)
            || redactedFileLabel.Contains('/', StringComparison.Ordinal)
            || redactedFileLabel.Contains('\\', StringComparison.Ordinal)
            || Path.IsPathRooted(redactedFileLabel)
            || redactedFileLabel is "." or "..")
            throw new ArgumentException("Redacted file label must be a bounded canonical ASCII basename.", nameof(redactedFileLabel));
        RedactedFileLabel = redactedFileLabel;
    }

    internal string RedactedFileLabel { get; }
}

internal enum SimulationRuntimeInvalidationKind
{
    ProjectionCapacityExhausted
}

internal sealed record AuthoritySimulationRuntimeOwnershipSnapshot(
    int CoreActiveContextCount,
    int ChallengeMappingCount,
    int HeldFlowCount,
    long HeldByteCount,
    int TicketReservationCount,
    int GrantReservationCount)
{
    internal bool IsZero => CoreActiveContextCount == 0
        && ChallengeMappingCount == 0
        && HeldFlowCount == 0
        && HeldByteCount == 0
        && TicketReservationCount == 0
        && GrantReservationCount == 0;
}

internal sealed record CoordinatorSimulationRuntimeOwnershipSnapshot(
    int PromptOwnershipCount,
    int JoinOwnershipCount,
    int RememberedRuleCount,
    int DecisionReceiptCount,
    int RuleIdRegistryEntryCount)
{
    internal bool IsZero => PromptOwnershipCount == 0
        && JoinOwnershipCount == 0
        && RememberedRuleCount == 0
        && DecisionReceiptCount == 0
        && RuleIdRegistryEntryCount == 0;
}

internal sealed record SimulationRuntimeInvalidationResult
{
    internal SimulationRuntimeInvalidationResult(
        int version,
        SimulationRuntimeInvalidationKind kind,
        IReadOnlyList<GateStatus> invalidatedStatuses,
        long failedOpenOperationCount,
        AuthoritySimulationRuntimeOwnershipSnapshot authorityOwnershipBefore,
        AuthoritySimulationRuntimeOwnershipSnapshot authorityOwnershipAfter,
        bool criticalFailOpenEvidenceRecorded)
    {
        Version = version;
        Kind = kind;
        InvalidatedStatuses = Array.AsReadOnly((invalidatedStatuses ?? throw new ArgumentNullException(nameof(invalidatedStatuses))).ToArray());
        FailedOpenOperationCount = failedOpenOperationCount;
        AuthorityOwnershipBefore = authorityOwnershipBefore ?? throw new ArgumentNullException(nameof(authorityOwnershipBefore));
        AuthorityOwnershipAfter = authorityOwnershipAfter ?? throw new ArgumentNullException(nameof(authorityOwnershipAfter));
        CriticalFailOpenEvidenceRecorded = criticalFailOpenEvidenceRecorded;
    }

    internal int Version { get; }
    internal SimulationRuntimeInvalidationKind Kind { get; }
    internal IReadOnlyList<GateStatus> InvalidatedStatuses { get; }
    internal long FailedOpenOperationCount { get; }
    internal AuthoritySimulationRuntimeOwnershipSnapshot AuthorityOwnershipBefore { get; }
    internal AuthoritySimulationRuntimeOwnershipSnapshot AuthorityOwnershipAfter { get; }
    internal bool CriticalFailOpenEvidenceRecorded { get; }
}

internal interface ISimulatedDecisionAuthority
{
    bool IsEnabled { get; }
    long PolicyEpoch { get; }
    ServiceMonotonicTimestamp MonotonicNow();
    DateTimeOffset AuditNowUtc();
    Guid NextDecisionId();
    Guid NextRuleId();
    GateTransitionResult ReceiveDecision(UserDecision decision);
    PersistentDecisionTransitionResult ReceivePersistentDecision(UserDecision decision, long nextPolicyEpoch);
    IReadOnlyList<GateStatus> ApplyPolicyEpoch(long policyEpoch);
    AuthoritySimulationRuntimeOwnershipSnapshot CaptureOwnership();
    SimulationRuntimeInvalidationResult InvalidateRuntimeForProjectionCapacityFailure();
}

internal sealed class DisabledSimulatedDecisionAuthority : ISimulatedDecisionAuthority
{
    private readonly Guid _clockInstance = Guid.NewGuid();
    private readonly long _started = Environment.TickCount64;

    public bool IsEnabled => false;
    public long PolicyEpoch => 0;
    public ServiceMonotonicTimestamp MonotonicNow() => new(1, _clockInstance, Math.Max(0, Environment.TickCount64 - _started));
    public DateTimeOffset AuditNowUtc() => DateTimeOffset.UtcNow;
    public Guid NextDecisionId() => throw Disabled();
    public Guid NextRuleId() => throw Disabled();
    public GateTransitionResult ReceiveDecision(UserDecision decision) => throw Disabled();
    public PersistentDecisionTransitionResult ReceivePersistentDecision(UserDecision decision, long nextPolicyEpoch) => throw Disabled();
    public IReadOnlyList<GateStatus> ApplyPolicyEpoch(long policyEpoch) => throw Disabled();
    public AuthoritySimulationRuntimeOwnershipSnapshot CaptureOwnership() => new(0, 0, 0, 0, 0, 0);
    public SimulationRuntimeInvalidationResult InvalidateRuntimeForProjectionCapacityFailure() => throw Disabled();

    private static InvalidOperationException Disabled() => new("The Simulation decision authority is disabled.");
}

internal sealed class SimulatedDecisionCoordinator : IDisposable
{
    private const int MaximumJoinCount = 128;
    private const int MaximumReceiptCount = 256;
    private const long RememberDurationMilliseconds = 30L * 24 * 60 * 60 * 1000;
    private const long DiagnosticRetentionMilliseconds = 5L * 60 * 1000;
    private readonly object _sync = new();
    private readonly ISimulatedDecisionAuthority _authority;
    private readonly SimulatedDecisionEventHub _eventHub;
    private readonly Dictionary<Guid, PromptContext> _prompts = [];
    private readonly Dictionary<Guid, PromptContext> _joins = [];
    private readonly Dictionary<Guid, RememberedRule> _rules = [];
    private readonly Dictionary<Guid, RuleRegistryEntry> _ruleRegistry = [];
    private readonly Dictionary<string, Receipt> _receipts = new(StringComparer.Ordinal);
    private readonly Queue<string> _receiptOrder = [];
    private readonly List<SimulatedReconnectRequiredProjection> _reconnectNotices = [];
    private readonly List<SimulatedGateStatusProjection> _statuses = [];
    private readonly List<SimulatedCriticalAlertProjection> _criticalAlerts = [];
    private long _sequence;
    private long _revision;
    private long _ruleIdCollisionCount;
    private long _ruleIdRegistryCapacityRejectedCount;
    private long _projectionCapacityFailureCount;
    private bool _disposed;

    internal SimulatedDecisionCoordinator(ISimulatedDecisionAuthority authority, SimulatedDecisionEventHub eventHub)
    {
        _authority = authority ?? throw new ArgumentNullException(nameof(authority));
        _eventHub = eventHub ?? throw new ArgumentNullException(nameof(eventHub));
    }

    internal bool SimulationEnabled => _authority.IsEnabled;

    internal long CurrentSequence
    {
        get
        {
            lock (_sync)
                return _sequence;
        }
    }

    internal CoordinatorSimulationRuntimeOwnershipSnapshot CaptureOwnership()
    {
        lock (_sync)
            return CaptureOwnershipCore();
    }

    internal SimulatedDecisionSnapshotMessage GetSnapshot(SimulatedDecisionCaller caller, int pipeInstanceCount)
    {
        ArgumentNullException.ThrowIfNull(caller);
        RequireAdministrator(caller);
        lock (_sync)
        {
            ThrowIfDisposed();
            SweepDiagnosticState();
            SweepExpiredRules();
            var enabled = _authority.IsEnabled;
            var authorization = new SimulatedDecisionAuthorizationProjection(
                canView: true,
                canAllowOnce: enabled,
                canRememberFor30Days: enabled,
                canBlockCurrent: enabled,
                canRevoke: enabled,
                enabled ? SimulatedDecisionReasonCodes.PromptActive : SimulatedDecisionReasonCodes.Disabled);
            return new SimulatedDecisionSnapshotMessage(
                ProtocolConstants.Version,
                _sequence,
                enabled,
                authorization,
                _prompts.Values.OrderBy(item => item.Revision).Select(ProjectPrompt).ToArray(),
                _reconnectNotices.ToArray(),
                _rules.Values.OrderBy(item => item.Revision).Select(item => item.Projection).ToArray(),
                _statuses.ToArray(),
                _criticalAlerts.ToArray(),
                new SimulatedDecisionCapacitySnapshot(
                    _eventHub.SubscriberCount,
                    SimulatedDecisionProtocolLimits.DecisionSubscriberCapacity,
                    Math.Clamp(pipeInstanceCount, 0, SimulatedDecisionProtocolLimits.PipeInstanceCapacity),
                    SimulatedDecisionProtocolLimits.PipeInstanceCapacity,
                    0,
                    SimulatedDecisionProtocolLimits.ReservedRequestReconnectCapacity,
                    _ruleRegistry.Count,
                    SimulatedDecisionProtocolLimits.RuleIdRegistryEntryCapacity),
                new SimulatedDecisionCounterSnapshot(
                    _ruleIdCollisionCount,
                    _ruleIdRegistryCapacityRejectedCount,
                    _eventHub.RejectedSubscriberCount,
                    _projectionCapacityFailureCount));
        }
    }

    internal SimulatedDecisionEventHub.SimulatedDecisionEventSubscription Subscribe(
        SimulatedDecisionCaller caller,
        long lastSequence)
    {
        ArgumentNullException.ThrowIfNull(caller);
        RequireAdministrator(caller);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (!_authority.IsEnabled)
                throw Error(SimulatedDecisionReasonCodes.Disabled, "The Simulation decision authority is disabled.");
            return _eventHub.Subscribe(lastSequence, _sequence);
        }
    }

    internal SimulatedDecisionResultMessage? AcceptTrustedChallenge(
        FileReadIntent intent,
        ProtectedFileDisplayMetadata display,
        NetworkGateChallenge challenge,
        GateStatus acceptedStatus)
    {
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(display);
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(acceptedStatus);
        lock (_sync)
        {
            ThrowIfDisposed();
            RequireEnabled();
            ValidateTrustedChallenge(intent, challenge, acceptedStatus);
            if (challenge.ExistingFlow)
                throw new ArgumentException("Existing flows require a reconnect projection and cannot create a decision prompt.", nameof(challenge));
            if (_joins.ContainsKey(challenge.ChallengeId))
                throw new InvalidOperationException("A trusted challenge identifier is already retained.");

            SweepDiagnosticState();
            var now = Now();
            var exactRule = FindExactLiveRule(intent.File, challenge.Subject.ApplicationIdentity, challenge.Destination, now);
            if (exactRule is not null)
            {
                var decision = BuildDecision(challenge, intent.File, UserDecisionKind.AlwaysAllow, exactRule.CreatingCaller);
                var authoritative = _authority.ReceiveDecision(decision);
                ValidateDecisionResult(authoritative, intent.IntentId);
                var result = CompleteAutoMatch(challenge, exactRule, authoritative);
                StoreDecisionReceipt(challenge.ChallengeId, SimulatedDecisionChoice.RememberFor30Days, result, now);
                return result;
            }

            var context = new PromptContext(intent, display, challenge, acceptedStatus, NextRevision());
            if (!CanReservePrompt(context))
            {
                RecoverProjectionCapacity(context);
                return null;
            }

            _joins.Add(challenge.ChallengeId, context);
            _prompts.Add(challenge.ChallengeId, context);
            Publish(PromptEvent(SimulatedDecisionEventKind.PromptUpserted, prompt: ProjectPrompt(context)));
            return null;
        }
    }

    internal void AcceptTrustedReconnect(
        FileReadIntent intent,
        ProtectedFileDisplayMetadata display,
        DestinationBinding destination,
        string? limitationReason)
    {
        ArgumentNullException.ThrowIfNull(intent);
        ArgumentNullException.ThrowIfNull(display);
        ArgumentNullException.ThrowIfNull(destination);
        lock (_sync)
        {
            ThrowIfDisposed();
            RequireEnabled();
            var notice = new SimulatedReconnectRequiredProjection(
                ProtocolConstants.Version,
                intent.IntentId,
                display.RedactedFileLabel,
                ProjectFile(intent.File),
                intent.Subject.ApplicationIdentity,
                ProjectSubject(intent.Subject),
                ProjectDestination(destination),
                SimulatedDecisionReasonCodes.ReconnectRequired,
                limitationReason,
                AuditNow(),
                NextRevision());
            AppendBounded(_reconnectNotices, notice, SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount);
            Publish(PromptEvent(SimulatedDecisionEventKind.ReconnectRequired, reconnect: notice));
        }
    }

    internal void ReconcileAuthoritativeStatus(GateStatus status, CriticalAlert? alert = null)
    {
        ArgumentNullException.ThrowIfNull(status);
        lock (_sync)
        {
            ThrowIfDisposed();
            ReconcileStatus(status);
            if (alert is not null)
                PublishCritical(ProjectAlert(alert));
        }
    }

    internal SimulatedDecisionResultMessage SubmitDecision(
        SimulatedDecisionCaller caller,
        SubmitSimulatedDecisionMessage request)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(request);
        RequireAdministrator(caller);
        lock (_sync)
        {
            ThrowIfDisposed();
            RequireEnabled();
            SweepDiagnosticState();
            var receiptKey = DecisionReceiptKey(request.ChallengeId);
            if (_receipts.TryGetValue(receiptKey, out var retained))
            {
                if (retained.Choice != request.Choice)
                    throw Error(SimulatedDecisionReasonCodes.DecisionConflict, "A different choice already terminalized this Simulation challenge.");
                if (retained.ErrorCode is not null)
                    throw Error(retained.ErrorCode, retained.ErrorMessage!);
                return Duplicate(retained.DecisionResult!);
            }

            if (!_prompts.TryGetValue(request.ChallengeId, out var context))
                throw Error(SimulatedDecisionReasonCodes.ChallengeNotFound, "The Simulation challenge is not active or retained.");
            if (context.DisabledReason is not null)
                throw Error(context.DisabledReason, "The Simulation challenge is disabled pending authoritative reconciliation.");

            return request.Choice == SimulatedDecisionChoice.RememberFor30Days
                ? SubmitRemember(caller, request, context)
                : SubmitCurrentDecision(caller, request, context);
        }
    }

    internal SimulatedRuleMutationResultMessage RevokeRule(
        SimulatedDecisionCaller caller,
        RevokeSimulatedRememberedRuleMessage request)
    {
        ArgumentNullException.ThrowIfNull(caller);
        ArgumentNullException.ThrowIfNull(request);
        RequireAdministrator(caller);
        lock (_sync)
        {
            ThrowIfDisposed();
            RequireEnabled();
            SweepDiagnosticState();
            SweepExpiredRules();
            var receiptKey = RevokeReceiptKey(request.RuleId, request.ExpectedRevision);
            if (_receipts.TryGetValue(receiptKey, out var retained))
                return Duplicate(retained.RuleMutationResult!);
            if (!_rules.TryGetValue(request.RuleId, out var rule))
                throw Error(SimulatedDecisionReasonCodes.RememberedRuleNotFound, "The remembered Simulation rule is not active.");
            if (rule.Revision != request.ExpectedRevision)
                throw Error(SimulatedDecisionReasonCodes.RuleRevisionConflict, "The remembered Simulation rule revision has changed.");

            var nextEpoch = checked(_authority.PolicyEpoch + 1);
            var statuses = _authority.ApplyPolicyEpoch(nextEpoch);
            ValidatePolicyStatuses(statuses);
            foreach (var survivor in _rules.Values)
                survivor.PolicyEpoch = nextEpoch;
            TombstoneRule(rule, SimulatedDecisionItemState.Revoked, SimulatedDecisionReasonCodes.RuleRevoked);
            foreach (var status in statuses)
                ReconcileStatus(status);
            var result = new SimulatedRuleMutationResultMessage(
                ProtocolConstants.Version,
                _sequence,
                request.RuleId,
                request.ExpectedRevision,
                SimulatedRuleMutationKind.Revoke,
                SimulatedDecisionItemState.Revoked,
                SimulatedDecisionReasonCodes.RuleRevoked,
                isDuplicate: false,
                rule.Revision);
            StoreReceipt(receiptKey, new Receipt(null, result, null, null, null, Deadline(Now(), DiagnosticRetentionMilliseconds)));
            return result;
        }
    }

    internal void InvalidateFileVersion(string volumeId, string fileId, FileVersionIdentity currentVersion)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(volumeId);
        ArgumentException.ThrowIfNullOrWhiteSpace(fileId);
        ArgumentNullException.ThrowIfNull(currentVersion);
        lock (_sync)
        {
            ThrowIfDisposed();
            var invalid = _rules.Values.Where(rule =>
                string.Equals(rule.File.VolumeId, volumeId, StringComparison.Ordinal)
                && string.Equals(rule.File.FileId, fileId, StringComparison.Ordinal)
                && rule.File != currentVersion).ToArray();
            RemoveRuleBatch(invalid, SimulatedDecisionItemState.FileVersionInvalidated, SimulatedDecisionReasonCodes.RuleFileVersionInvalidated);
        }
    }

    internal void ApplyExternalPolicyEpoch(long policyEpoch)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(policyEpoch);
        lock (_sync)
        {
            ThrowIfDisposed();
            if (policyEpoch <= _authority.PolicyEpoch)
                throw new ArgumentOutOfRangeException(nameof(policyEpoch), "External policy epoch must advance.");
            var statuses = _authority.ApplyPolicyEpoch(policyEpoch);
            ValidatePolicyStatuses(statuses);
            foreach (var rule in _rules.Values.ToArray())
                TombstoneRule(rule, SimulatedDecisionItemState.PolicyInvalidated, SimulatedDecisionReasonCodes.RulePolicyInvalidated);
            foreach (var status in statuses)
                ReconcileStatus(status);
            foreach (var challengeId in _prompts.Keys.ToArray())
                RemovePrompt(challengeId);
        }
    }

    private SimulatedDecisionResultMessage SubmitCurrentDecision(
        SimulatedDecisionCaller caller,
        SubmitSimulatedDecisionMessage request,
        PromptContext context)
    {
        var kind = request.Choice switch
        {
            SimulatedDecisionChoice.AllowOnce => UserDecisionKind.AllowOnce,
            SimulatedDecisionChoice.BlockCurrent => UserDecisionKind.Block,
            _ => throw Error(SimulatedDecisionReasonCodes.RequestInvalid, "The Simulation decision choice is invalid.")
        };
        var decision = BuildDecision(context.Challenge, context.Intent.File, kind, caller.AuthenticatedCaller);
        var authoritative = _authority.ReceiveDecision(decision);
        ValidateDecisionResult(authoritative, context.Intent.IntentId);
        var failedOpen = authoritative.Status.State == GateRuntimeState.FailedOpen;
        var state = failedOpen
            ? SimulatedDecisionItemState.FailedOpen
            : request.Choice == SimulatedDecisionChoice.AllowOnce
                ? SimulatedDecisionItemState.AllowedOnce
                : SimulatedDecisionItemState.BlockedCurrent;
        var reason = failedOpen
            ? authoritative.Status.ReasonCode
            : request.Choice == SimulatedDecisionChoice.AllowOnce
                ? SimulatedDecisionReasonCodes.AllowOnceAccepted
                : SimulatedDecisionReasonCodes.BlockCurrentAccepted;
        RemovePrompt(context.Challenge.ChallengeId);
        PublishStatus(ProjectStatus(authoritative.Status));
        if (authoritative.CriticalAlert is not null)
            PublishCritical(ProjectAlert(authoritative.CriticalAlert));
        var result = new SimulatedDecisionResultMessage(
            ProtocolConstants.Version,
            _sequence,
            request.ChallengeId,
            request.Choice,
            state,
            reason,
            failedOpen,
            null,
            isDuplicate: false,
            NextRevision());
        StoreDecisionReceipt(request.ChallengeId, request.Choice, result, Now());
        return result;
    }

    private SimulatedDecisionResultMessage SubmitRemember(
        SimulatedDecisionCaller caller,
        SubmitSimulatedDecisionMessage request,
        PromptContext context)
    {
        var now = Now();
        var exact = FindExactLiveRule(context.Intent.File, context.Challenge.Subject.ApplicationIdentity, context.Challenge.Destination, now);
        if (exact is not null)
        {
            var exactDecision = BuildDecision(context.Challenge, context.Intent.File, UserDecisionKind.AlwaysAllow, caller.AuthenticatedCaller);
            var exactAuthoritative = _authority.ReceiveDecision(exactDecision);
            ValidateDecisionResult(exactAuthoritative, context.Intent.IntentId);
            var exactResult = CompleteRememberDecision(context, exact, exactAuthoritative, SimulatedDecisionReasonCodes.RememberAccepted);
            StoreDecisionReceipt(request.ChallengeId, request.Choice, exactResult, now);
            return exactResult;
        }

        SweepExpiredRules();
        if (_rules.Count >= SimulatedDecisionProtocolLimits.MaximumRememberedRuleCount
            || _rules.Values.Count(rule => string.Equals(rule.ApplicationIdentity, context.Challenge.Subject.ApplicationIdentity, StringComparison.Ordinal))
                >= SimulatedDecisionProtocolLimits.MaximumRememberedRulesPerApplication)
            return AwaitingRememberResult(context, SimulatedDecisionReasonCodes.RememberedRuleCapacityExhausted);

        SweepTombstones();
        if (_ruleRegistry.Count >= SimulatedDecisionProtocolLimits.RuleIdRegistryEntryCapacity)
        {
            _ruleIdRegistryCapacityRejectedCount = checked(_ruleIdRegistryCapacityRejectedCount + 1);
            PublishDiagnosticAlert(context, SimulatedDecisionReasonCodes.RuleIdRegistryCapacityExhausted, "Simulation rule identifier retention capacity exhausted.");
            return AwaitingRememberResult(context, SimulatedDecisionReasonCodes.RuleIdRegistryCapacityExhausted);
        }

        var candidate = _authority.NextRuleId();
        if (candidate == Guid.Empty || _ruleRegistry.ContainsKey(candidate))
        {
            _ruleIdCollisionCount = checked(_ruleIdCollisionCount + 1);
            PublishDiagnosticAlert(context, SimulatedDecisionReasonCodes.RuleIdCollision, "Simulation rule identifier collision.");
            return AwaitingRememberResult(context, SimulatedDecisionReasonCodes.RuleIdCollision);
        }

        var ruleRevision = NextRevision();
        var pending = new RuleRegistryEntry(candidate, RuleRegistryState.PendingReservation, ruleRevision, null, null);
        _ruleRegistry.Add(candidate, pending);
        var decision = BuildDecision(context.Challenge, context.Intent.File, UserDecisionKind.AlwaysAllow, caller.AuthenticatedCaller, candidate);
        var requestedPolicyEpoch = checked(_authority.PolicyEpoch + 1);
        PersistentDecisionTransitionResult authoritative;
        try
        {
            authoritative = _authority.ReceivePersistentDecision(decision, requestedPolicyEpoch);
            ValidatePersistentResult(authoritative, context.Intent.IntentId, requestedPolicyEpoch);
        }
        catch
        {
            context.DisabledReason = SimulatedDecisionReasonCodes.AuthorityResultInvalid;
            context.Revision = NextRevision();
            Publish(PromptEvent(SimulatedDecisionEventKind.PromptUpserted, prompt: ProjectPrompt(context)));
            PublishDiagnosticAlert(context, SimulatedDecisionReasonCodes.AuthorityResultInvalid, "Simulation authority result requires reconciliation.");
            throw;
        }
        if (!authoritative.PolicyEpochAccepted)
        {
            _ruleRegistry.Remove(candidate);
            if (authoritative.DecisionResult.Status.State == GateRuntimeState.FailedOpen)
            {
                RemovePrompt(context.Challenge.ChallengeId);
                PublishStatus(ProjectStatus(authoritative.DecisionResult.Status));
                if (authoritative.DecisionResult.CriticalAlert is not null)
                    PublishCritical(ProjectAlert(authoritative.DecisionResult.CriticalAlert));
                StoreTerminalError(
                    context.Challenge.ChallengeId,
                    request.Choice,
                    SimulatedDecisionReasonCodes.ChallengeExpired,
                    "The Simulation challenge reached its monotonic deadline.",
                    now);
                throw Error(SimulatedDecisionReasonCodes.ChallengeExpired, "The Simulation challenge reached its monotonic deadline.");
            }

            return AwaitingRememberResult(context, authoritative.DecisionResult.Status.ReasonCode);
        }

        pending.State = RuleRegistryState.ActiveRuleId;
        var auditNow = AuditNow();
        var remembered = new RememberedRule(
            candidate,
            context.Intent.File,
            context.Display.RedactedFileLabel,
            context.Challenge.Subject.ApplicationIdentity,
            context.Challenge.Destination,
            caller.AuthenticatedCaller,
            now,
            Deadline(now, RememberDurationMilliseconds),
            auditNow,
            auditNow.AddDays(30),
            authoritative.PolicyEpoch,
            ruleRevision,
            SimulatedDecisionReasonCodes.RememberAccepted);
        _rules.Add(candidate, remembered);
        foreach (var survivor in _rules.Values)
            survivor.PolicyEpoch = authoritative.PolicyEpoch;
        foreach (var invalidated in authoritative.InvalidatedStatuses)
            ReconcileStatus(invalidated);
        var result = CompleteRememberDecision(
            context,
            remembered,
            authoritative.DecisionResult,
            authoritative.DecisionResult.Status.State == GateRuntimeState.FailedOpen
                ? SimulatedDecisionReasonCodes.RuleCommittedTrafficFailedOpen
                : SimulatedDecisionReasonCodes.RememberAccepted,
            publishRule: true);
        StoreDecisionReceipt(request.ChallengeId, request.Choice, result, now);
        return result;
    }

    private SimulatedDecisionResultMessage CompleteAutoMatch(
        NetworkGateChallenge challenge,
        RememberedRule rule,
        GateTransitionResult authoritative)
    {
        PublishStatus(ProjectStatus(authoritative.Status));
        if (authoritative.CriticalAlert is not null)
            PublishCritical(ProjectAlert(authoritative.CriticalAlert));
        var failedOpen = authoritative.Status.State == GateRuntimeState.FailedOpen;
        return new SimulatedDecisionResultMessage(
            ProtocolConstants.Version,
            _sequence,
            challenge.ChallengeId,
            SimulatedDecisionChoice.RememberFor30Days,
            failedOpen ? SimulatedDecisionItemState.FailedOpen : SimulatedDecisionItemState.Remembered,
            failedOpen ? SimulatedDecisionReasonCodes.RuleCommittedTrafficFailedOpen : SimulatedDecisionReasonCodes.RememberAccepted,
            failedOpen,
            new SimulatedRememberedRuleOutcome(rule.RuleId, rule.Revision, SimulatedDecisionItemState.Remembered, rule.ReasonCode),
            isDuplicate: false,
            NextRevision());
    }

    private SimulatedDecisionResultMessage CompleteRememberDecision(
        PromptContext context,
        RememberedRule rule,
        GateTransitionResult authoritative,
        string reason,
        bool publishRule = false)
    {
        ValidateDecisionResult(authoritative, context.Intent.IntentId);
        if (publishRule)
            Publish(PromptEvent(SimulatedDecisionEventKind.RememberedRuleUpserted, rule: rule.Projection));
        RemovePrompt(context.Challenge.ChallengeId);
        PublishStatus(ProjectStatus(authoritative.Status));
        if (authoritative.CriticalAlert is not null)
            PublishCritical(ProjectAlert(authoritative.CriticalAlert));
        var failedOpen = authoritative.Status.State == GateRuntimeState.FailedOpen;
        return new SimulatedDecisionResultMessage(
            ProtocolConstants.Version,
            _sequence,
            context.Challenge.ChallengeId,
            SimulatedDecisionChoice.RememberFor30Days,
            failedOpen ? SimulatedDecisionItemState.FailedOpen : SimulatedDecisionItemState.Remembered,
            reason,
            failedOpen,
            new SimulatedRememberedRuleOutcome(rule.RuleId, rule.Revision, SimulatedDecisionItemState.Remembered, rule.ReasonCode),
            isDuplicate: false,
            NextRevision());
    }

    private SimulatedDecisionResultMessage AwaitingRememberResult(PromptContext context, string reason) => new(
        ProtocolConstants.Version,
        _sequence,
        context.Challenge.ChallengeId,
        SimulatedDecisionChoice.RememberFor30Days,
        SimulatedDecisionItemState.AwaitingDecision,
        reason,
        trafficFailedOpen: false,
        rememberedRule: null,
        isDuplicate: false,
        context.Revision);

    private UserDecision BuildDecision(
        NetworkGateChallenge challenge,
        FileVersionIdentity file,
        UserDecisionKind kind,
        string caller,
        Guid? decisionId = null)
    {
        var scope = kind == UserDecisionKind.AlwaysAllow
            ? new RequestedPersistentScope(
                ProtocolConstants.Version,
                PersistentAllowPolicyKind.RememberFor30Days,
                file,
                challenge.Subject.ApplicationIdentity,
                challenge.Destination)
            : null;
        return new UserDecision(
            ProtocolConstants.Version,
            decisionId ?? _authority.NextDecisionId(),
            challenge.ChallengeId,
            kind,
            scope,
            AuditNow(),
            caller);
    }

    private void SweepExpiredRules()
    {
        if (_rules.Count == 0)
            return;
        var now = Now();
        var expired = _rules.Values.Where(rule => DeadlineReached(now, rule.ExpiresAt)).ToArray();
        RemoveRuleBatch(expired, SimulatedDecisionItemState.Expired, SimulatedDecisionReasonCodes.RuleExpired);
    }

    private void RemoveRuleBatch(
        IReadOnlyList<RememberedRule> rules,
        SimulatedDecisionItemState terminalState,
        string reason)
    {
        if (rules.Count == 0)
            return;
        var nextEpoch = checked(_authority.PolicyEpoch + 1);
        var statuses = _authority.ApplyPolicyEpoch(nextEpoch);
        ValidatePolicyStatuses(statuses);
        foreach (var survivor in _rules.Values)
            survivor.PolicyEpoch = nextEpoch;
        foreach (var rule in rules)
            TombstoneRule(rule, terminalState, reason);
        foreach (var status in statuses)
            ReconcileStatus(status);
    }

    private void TombstoneRule(RememberedRule rule, SimulatedDecisionItemState state, string reason)
    {
        if (!_rules.Remove(rule.RuleId))
            return;
        rule.Revision = NextRevision();
        rule.ReasonCode = reason;
        if (!_ruleRegistry.TryGetValue(rule.RuleId, out var entry))
            throw new InvalidOperationException("An active remembered rule has no RuleId registry entry.");
        entry.State = RuleRegistryState.RetainedTombstone;
        entry.Revision = rule.Revision;
        entry.TerminalReason = reason;
        entry.RetentionDeadline = Deadline(Now(), DiagnosticRetentionMilliseconds);
        Publish(PromptEvent(SimulatedDecisionEventKind.RememberedRuleRemoved, removedRuleId: rule.RuleId));
    }

    private void SweepDiagnosticState()
    {
        SweepTombstones();
        var now = Now();
        foreach (var key in _receipts.Where(item => DeadlineReached(now, item.Value.RetentionDeadline)).Select(item => item.Key).ToArray())
            _receipts.Remove(key);
        while (_receiptOrder.Count > 0 && !_receipts.ContainsKey(_receiptOrder.Peek()))
            _receiptOrder.Dequeue();
    }

    private void SweepTombstones()
    {
        var now = Now();
        foreach (var id in _ruleRegistry
                     .Where(item => item.Value.State == RuleRegistryState.RetainedTombstone
                         && item.Value.RetentionDeadline is not null
                         && DeadlineReached(now, item.Value.RetentionDeadline))
                     .Select(item => item.Key)
                     .ToArray())
            _ruleRegistry.Remove(id);
    }

    private void RecoverProjectionCapacity(PromptContext attempted)
    {
        var before = CaptureOwnershipCore();
        var authorityBefore = _authority.CaptureOwnership();
        var result = _authority.InvalidateRuntimeForProjectionCapacityFailure();
        var authorityAfter = _authority.CaptureOwnership();
        var returnedIntentIds = result.InvalidatedStatuses
            .Select(status => status.AffectedScope.IntentId)
            .ToArray();
        if (result.Version != ProtocolConstants.Version
            || result.Kind != SimulationRuntimeInvalidationKind.ProjectionCapacityExhausted
            || result.FailedOpenOperationCount < 0
            || result.AuthorityOwnershipBefore != authorityBefore
            || result.AuthorityOwnershipAfter != authorityAfter
            || result.AuthorityOwnershipBefore.IsZero
            || !result.AuthorityOwnershipAfter.IsZero
            || !result.CriticalFailOpenEvidenceRecorded
            || result.FailedOpenOperationCount == 0
            || result.FailedOpenOperationCount != result.InvalidatedStatuses.LongCount(status => status.TrafficFailedOpen)
            || result.InvalidatedStatuses.Count != result.AuthorityOwnershipBefore.CoreActiveContextCount
            || returnedIntentIds.Any(intentId => intentId is null)
            || returnedIntentIds.Where(intentId => intentId is not null).Distinct().Count() != returnedIntentIds.Length
            || before.IsZero
            || result.InvalidatedStatuses.Any(status => status is null
                || status.Version != ProtocolConstants.Version
                || status.Mode != OutboundGateMode.Simulation
                || status.State == GateRuntimeState.AwaitingDecision))
        {
            PublishDiagnosticAlert(attempted, SimulatedDecisionReasonCodes.AuthorityResultInvalid, "Simulation authority result requires reconciliation.");
            throw Error(SimulatedDecisionReasonCodes.AuthorityResultInvalid, "Projection-capacity recovery did not prove an all-zero authoritative state.");
        }

        foreach (var status in result.InvalidatedStatuses)
            ReconcileStatus(status);
        _prompts.Clear();
        _joins.Clear();
        _rules.Clear();
        _receipts.Clear();
        _receiptOrder.Clear();
        _ruleRegistry.Clear();
        var after = CaptureOwnershipCore();
        if (!after.IsZero)
            throw Error(SimulatedDecisionReasonCodes.AuthorityResultInvalid, "Projection-capacity recovery left Coordinator ownership active.");
        _projectionCapacityFailureCount = checked(_projectionCapacityFailureCount + 1);
        PublishDiagnosticAlert(attempted, SimulatedDecisionReasonCodes.ProjectionCapacityExhausted, SimulatedDecisionProtocolLimits.FailOpenPresentationText, trafficFailedOpen: true);
    }

    private bool CanReservePrompt(PromptContext context)
    {
        if (_prompts.Count >= SimulatedDecisionProtocolLimits.MaximumPromptCount
            || _joins.Count >= MaximumJoinCount)
            return false;
        return _prompts.Values.Count(other => ExactSubjectEquals(context.Challenge.Subject, other.Challenge.Subject))
            < SimulatedDecisionProtocolLimits.MaximumPromptsPerSubject;
    }

    private static bool ExactSubjectEquals(GateSubject left, GateSubject right) => left.Matches(right);

    private RememberedRule? FindExactLiveRule(
        FileVersionIdentity file,
        string applicationIdentity,
        DestinationBinding destination,
        ServiceMonotonicTimestamp now) => _rules.Values.FirstOrDefault(rule =>
            rule.File == file
            && string.Equals(rule.ApplicationIdentity, applicationIdentity, StringComparison.Ordinal)
            && rule.Destination == destination
            && rule.PolicyEpoch == _authority.PolicyEpoch
            && !DeadlineReached(now, rule.ExpiresAt));

    private void ReconcileStatus(GateStatus status)
    {
        ValidateStatus(status);
        if (status.AffectedScope.IntentId is Guid intentId)
        {
            var challengeId = _joins.Values.FirstOrDefault(item => item.Intent.IntentId == intentId)?.Challenge.ChallengeId;
            if (challengeId is Guid id && status.State != GateRuntimeState.AwaitingDecision)
                RemovePrompt(id);
        }
        PublishStatus(ProjectStatus(status));
    }

    private void RemovePrompt(Guid challengeId)
    {
        var removed = _prompts.Remove(challengeId);
        _joins.Remove(challengeId);
        if (removed)
            Publish(PromptEvent(SimulatedDecisionEventKind.PromptRemoved, removedChallengeId: challengeId));
    }

    private void PublishStatus(SimulatedGateStatusProjection status)
    {
        AppendBounded(_statuses, status, SimulatedDecisionProtocolLimits.MaximumStatusCount);
        Publish(PromptEvent(SimulatedDecisionEventKind.StatusChanged, status: status));
    }

    private void PublishCritical(SimulatedCriticalAlertProjection alert)
    {
        AppendBounded(_criticalAlerts, alert, SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount);
        Publish(PromptEvent(SimulatedDecisionEventKind.CriticalAlertRaised, alert: alert));
    }

    private void PublishDiagnosticAlert(
        PromptContext context,
        string reason,
        string presentation,
        bool trafficFailedOpen = false)
    {
        var revision = NextRevision();
        PublishCritical(new SimulatedCriticalAlertProjection(
            ProtocolConstants.Version,
            DeterministicAlertId(context.Challenge.ChallengeId, reason, revision),
            context.Intent.IntentId,
            ProjectSubject(context.Intent.Subject),
            reason,
            AuditNow(),
            0,
            0,
            trafficFailedOpen,
            presentation,
            revision));
    }

    private void Publish(SimulatedDecisionEventMessage unsequenced)
    {
        var sequence = checked(_sequence + 1);
        _sequence = sequence;
        var message = new SimulatedDecisionEventMessage(
            unsequenced.Version,
            sequence,
            unsequenced.Kind,
            unsequenced.Prompt,
            unsequenced.RemovedChallengeId,
            unsequenced.ReconnectNotice,
            unsequenced.RememberedRule,
            unsequenced.RemovedRuleId,
            unsequenced.Status,
            unsequenced.CriticalAlert,
            unsequenced.RequiresResync);
        _eventHub.Publish(message);
    }

    private static SimulatedDecisionEventMessage PromptEvent(
        SimulatedDecisionEventKind kind,
        SimulatedDecisionPromptProjection? prompt = null,
        Guid? removedChallengeId = null,
        SimulatedReconnectRequiredProjection? reconnect = null,
        SimulatedRememberedRuleProjection? rule = null,
        Guid? removedRuleId = null,
        SimulatedGateStatusProjection? status = null,
        SimulatedCriticalAlertProjection? alert = null) => new(
            ProtocolConstants.Version,
            0,
            kind,
            prompt,
            removedChallengeId,
            reconnect,
            rule,
            removedRuleId,
            status,
            alert,
            requiresResync: false);

    private SimulatedDecisionPromptProjection ProjectPrompt(PromptContext context)
    {
        var now = Now();
        var sameClock = SameClock(now, context.Challenge.DecisionWindow.Deadline);
        var remaining = sameClock
            ? Math.Clamp(context.Challenge.DecisionWindow.Deadline.ElapsedMilliseconds - now.ElapsedMilliseconds, 0, SimulatedDecisionProtocolLimits.MaximumDecisionRemainingMilliseconds)
            : 0;
        var accepting = remaining > 0 && context.DisabledReason is null;
        return new SimulatedDecisionPromptProjection(
            ProtocolConstants.Version,
            context.Challenge.ChallengeId,
            context.Intent.IntentId,
            context.Display.RedactedFileLabel,
            ProjectFile(context.Intent.File),
            context.Challenge.Subject.ApplicationIdentity,
            ProjectSubject(context.Challenge.Subject),
            ProjectDestination(context.Challenge.Destination),
            existingFlow: false,
            accepting ? GateRuntimeState.AwaitingDecision : GateRuntimeState.Idle,
            context.DisabledReason ?? (accepting ? SimulatedDecisionReasonCodes.PromptActive : SimulatedDecisionReasonCodes.ChallengeExpired),
            context.Challenge.LimitationReason,
            new SimulatedDecisionExpiryProjection(
                ProtocolConstants.Version,
                accepting ? remaining : 0,
                AuditNow(),
                accepting),
            context.Revision);
    }

    private static SimulatedFileVersionProjection ProjectFile(FileVersionIdentity file) => new(
        ProtocolConstants.Version,
        file.VersionToken,
        file.SizeBytes,
        file.LastWriteTimeUtc,
        file.ChangeTimeUtc,
        file.Usn);

    private static SimulatedSubjectProjection ProjectSubject(GateSubject subject)
    {
        var group = subject.ProcessGroupId is not null;
        return new SimulatedSubjectProjection(
            ProtocolConstants.Version,
            group ? SimulatedDecisionSubjectKind.ExactProcessGroup : SimulatedDecisionSubjectKind.ExactProcess,
            subject.ProcessIdentity,
            subject.ProcessGroupId,
            subject.GroupMembers,
            group,
            group ? SimulatedDecisionProtocolLimits.GroupCollateralWarning : null);
    }

    private static SimulatedDestinationProjection ProjectDestination(DestinationBinding destination) => new(
        ProtocolConstants.Version,
        destination.Address,
        destination.IpVersion,
        destination.RemotePort,
        destination.Protocol,
        destination.DomainEvidence,
        destination.DomainProvenance,
        destination.DomainObservedAtUtc);

    private SimulatedGateStatusProjection ProjectStatus(GateStatus status) => new(
        ProtocolConstants.Version,
        status.AffectedScope.IntentId,
        status.State,
        status.ReasonCode,
        status.AuditTimeUtc,
        status.TrafficFailedOpen,
        status.DroppedCount,
        status.OverflowCount,
        NextRevision());

    private SimulatedCriticalAlertProjection ProjectAlert(CriticalAlert alert) => new(
        ProtocolConstants.Version,
        alert.AlertId,
        alert.AffectedScope.IntentId,
        alert.AffectedScope.Subject is null ? null : ProjectSubject(alert.AffectedScope.Subject),
        alert.ReasonCode,
        alert.AuditTimeUtc,
        alert.DroppedCount,
        alert.OverflowCount,
        alert.TrafficFailedOpen,
        alert.TrafficFailedOpen ? SimulatedDecisionProtocolLimits.FailOpenPresentationText : "Simulation critical alert.",
        NextRevision());

    private void StoreDecisionReceipt(
        Guid challengeId,
        SimulatedDecisionChoice choice,
        SimulatedDecisionResultMessage result,
        ServiceMonotonicTimestamp now) => StoreReceipt(
            DecisionReceiptKey(challengeId),
            new Receipt(result, null, choice, null, null, Deadline(now, DiagnosticRetentionMilliseconds)));

    private void StoreTerminalError(
        Guid challengeId,
        SimulatedDecisionChoice choice,
        string code,
        string message,
        ServiceMonotonicTimestamp now) => StoreReceipt(
            DecisionReceiptKey(challengeId),
            new Receipt(null, null, choice, code, message, Deadline(now, DiagnosticRetentionMilliseconds)));

    private void StoreReceipt(string key, Receipt receipt)
    {
        if (_receipts.ContainsKey(key))
            return;
        while (_receipts.Count >= MaximumReceiptCount && _receiptOrder.Count > 0)
            _receipts.Remove(_receiptOrder.Dequeue());
        _receipts.Add(key, receipt);
        _receiptOrder.Enqueue(key);
    }

    private static SimulatedDecisionResultMessage Duplicate(SimulatedDecisionResultMessage result) => new(
        result.Version,
        result.Sequence,
        result.ChallengeId,
        result.Choice,
        result.DecisionState,
        result.DecisionReasonCode,
        result.TrafficFailedOpen,
        result.RememberedRule,
        isDuplicate: true,
        result.Revision);

    private static SimulatedRuleMutationResultMessage Duplicate(SimulatedRuleMutationResultMessage result) => new(
        result.Version,
        result.Sequence,
        result.RuleId,
        result.ExpectedRevision,
        result.Mutation,
        result.State,
        result.ReasonCode,
        isDuplicate: true,
        result.Revision);

    private CoordinatorSimulationRuntimeOwnershipSnapshot CaptureOwnershipCore() => new(
        _prompts.Count,
        _joins.Count,
        _rules.Count,
        _receipts.Count,
        _ruleRegistry.Count);

    private static void ValidateTrustedChallenge(
        FileReadIntent intent,
        NetworkGateChallenge challenge,
        GateStatus status)
    {
        if (intent.IntentId != challenge.IntentId
            || !intent.Subject.Matches(challenge.Subject)
            || status.State != GateRuntimeState.AwaitingDecision
            || status.AffectedScope.IntentId != intent.IntentId
            || status.TrafficFailedOpen)
            throw new ArgumentException("Trusted intent, challenge and accepted status are not exactly bound.");
    }

    private static void ValidateDecisionResult(GateTransitionResult result, Guid intentId)
    {
        ArgumentNullException.ThrowIfNull(result);
        ValidateStatus(result.Status);
        if (result.Status.AffectedScope.IntentId != intentId)
            throw new InvalidOperationException("Authority decision result is bound to a different intent.");
    }

    private static void ValidatePersistentResult(
        PersistentDecisionTransitionResult result,
        Guid intentId,
        long requestedPolicyEpoch)
    {
        ArgumentNullException.ThrowIfNull(result);
        if (result.Version != ProtocolConstants.Version
            || result.PolicyEpoch < 0
            || (result.PolicyEpochAccepted && result.PolicyEpoch != requestedPolicyEpoch)
            || (!result.PolicyEpochAccepted && result.PolicyEpoch != requestedPolicyEpoch - 1))
            throw new InvalidOperationException("Persistent authority result has an invalid version or epoch.");
        ValidateDecisionResult(result.DecisionResult, intentId);
        ValidatePolicyStatuses(result.InvalidatedStatuses);
        if (!result.PolicyEpochAccepted && result.InvalidatedStatuses.Count != 0)
            throw new InvalidOperationException("Rejected persistent authority result reported invalidations.");
    }

    private static void ValidatePolicyStatuses(IReadOnlyList<GateStatus> statuses)
    {
        ArgumentNullException.ThrowIfNull(statuses);
        foreach (var status in statuses)
            ValidateStatus(status);
    }

    private static void ValidateStatus(GateStatus status)
    {
        ArgumentNullException.ThrowIfNull(status);
        if (status.Version != ProtocolConstants.Version
            || status.Mode != OutboundGateMode.Simulation
            || status.AffectedScope is null)
            throw new InvalidOperationException("Authority status violates the Simulation contract.");
    }

    private static void RequireAdministrator(SimulatedDecisionCaller caller)
    {
        if (!caller.IsAdministrator)
            throw Error(SimulatedDecisionReasonCodes.AdministratorRequired, "A local Administrator is required for Simulation decision metadata.");
        if (string.IsNullOrWhiteSpace(caller.AuthenticatedCaller) || caller.AuthenticatedCaller.Length > 128)
            throw Error(SimulatedDecisionReasonCodes.AdministratorRequired, "The impersonated caller identity is unavailable.");
    }

    private void RequireEnabled()
    {
        if (!_authority.IsEnabled)
            throw Error(SimulatedDecisionReasonCodes.Disabled, "The Simulation decision authority is disabled.");
    }

    private ServiceMonotonicTimestamp Now()
    {
        var now = _authority.MonotonicNow();
        return now ?? throw new InvalidOperationException("Simulation authority returned no monotonic timestamp.");
    }

    private DateTimeOffset AuditNow()
    {
        var now = _authority.AuditNowUtc();
        if (now == default)
            throw new InvalidOperationException("Simulation authority returned no audit timestamp.");
        return now.ToUniversalTime();
    }

    private long NextRevision() => _revision = checked(_revision + 1);

    private static ServiceMonotonicTimestamp Deadline(ServiceMonotonicTimestamp now, long milliseconds) => new(
        ProtocolConstants.Version,
        now.ClockInstanceId,
        checked(now.ElapsedMilliseconds + milliseconds));

    private static bool SameClock(ServiceMonotonicTimestamp left, ServiceMonotonicTimestamp right) =>
        left.Version == right.Version && left.ClockInstanceId == right.ClockInstanceId;

    private static bool DeadlineReached(ServiceMonotonicTimestamp now, ServiceMonotonicTimestamp deadline) =>
        !SameClock(now, deadline) || now.ElapsedMilliseconds >= deadline.ElapsedMilliseconds;

    private static string DecisionReceiptKey(Guid challengeId) => $"d:{challengeId:D}";
    private static string RevokeReceiptKey(Guid ruleId, long revision) => $"r:{ruleId:D}:{revision}";

    private static Guid DeterministicAlertId(Guid challengeId, string reason, long revision)
    {
        var input = Encoding.UTF8.GetBytes($"{challengeId:D}:{reason}:{revision}");
        var hash = SHA256.HashData(input);
        return new Guid(hash.AsSpan(0, 16));
    }

    private static void AppendBounded<T>(List<T> items, T item, int capacity)
    {
        if (items.Count == capacity)
            items.RemoveAt(0);
        items.Add(item);
    }

    private static SimulatedDecisionRequestException Error(string code, string message) => new(code, message);

    private void ThrowIfDisposed() => ObjectDisposedException.ThrowIf(_disposed, this);

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
                return;
            _disposed = true;
            _prompts.Clear();
            _joins.Clear();
            _rules.Clear();
            _ruleRegistry.Clear();
            _receipts.Clear();
            _receiptOrder.Clear();
            _reconnectNotices.Clear();
            _statuses.Clear();
            _criticalAlerts.Clear();
        }
    }

    private sealed class PromptContext
    {
        internal PromptContext(
            FileReadIntent intent,
            ProtectedFileDisplayMetadata display,
            NetworkGateChallenge challenge,
            GateStatus status,
            long revision)
        {
            Intent = intent;
            Display = display;
            Challenge = challenge;
            Status = status;
            Revision = revision;
        }

        internal FileReadIntent Intent { get; }
        internal ProtectedFileDisplayMetadata Display { get; }
        internal NetworkGateChallenge Challenge { get; }
        internal GateStatus Status { get; }
        internal long Revision { get; set; }
        internal string? DisabledReason { get; set; }
    }

    private sealed class RememberedRule
    {
        internal RememberedRule(
            Guid ruleId,
            FileVersionIdentity file,
            string redactedFileLabel,
            string applicationIdentity,
            DestinationBinding destination,
            string creatingCaller,
            ServiceMonotonicTimestamp createdAt,
            ServiceMonotonicTimestamp expiresAt,
            DateTimeOffset createdAtUtc,
            DateTimeOffset expiresAtUtc,
            long policyEpoch,
            long revision,
            string reasonCode)
        {
            RuleId = ruleId;
            File = file;
            RedactedFileLabel = redactedFileLabel;
            ApplicationIdentity = applicationIdentity;
            Destination = destination;
            CreatingCaller = creatingCaller;
            CreatedAt = createdAt;
            ExpiresAt = expiresAt;
            CreatedAtUtc = createdAtUtc;
            ExpiresAtUtc = expiresAtUtc;
            PolicyEpoch = policyEpoch;
            Revision = revision;
            ReasonCode = reasonCode;
        }

        internal Guid RuleId { get; }
        internal FileVersionIdentity File { get; }
        internal string RedactedFileLabel { get; }
        internal string ApplicationIdentity { get; }
        internal DestinationBinding Destination { get; }
        internal string CreatingCaller { get; }
        internal ServiceMonotonicTimestamp CreatedAt { get; }
        internal ServiceMonotonicTimestamp ExpiresAt { get; }
        internal DateTimeOffset CreatedAtUtc { get; }
        internal DateTimeOffset ExpiresAtUtc { get; }
        internal long PolicyEpoch { get; set; }
        internal long Revision { get; set; }
        internal string ReasonCode { get; set; }
        internal SimulatedRememberedRuleProjection Projection => new(
            ProtocolConstants.Version,
            RuleId,
            RedactedFileLabel,
            ProjectFile(File),
            ApplicationIdentity,
            ProjectDestination(Destination),
            CreatedAtUtc,
            ExpiresAtUtc,
            SimulatedDecisionItemState.Remembered,
            ReasonCode,
            Revision);
    }

    private enum RuleRegistryState
    {
        PendingReservation,
        ActiveRuleId,
        RetainedTombstone
    }

    private sealed class RuleRegistryEntry(
        Guid ruleId,
        RuleRegistryState state,
        long revision,
        string? terminalReason,
        ServiceMonotonicTimestamp? retentionDeadline)
    {
        internal Guid RuleId { get; } = ruleId;
        internal RuleRegistryState State { get; set; } = state;
        internal long Revision { get; set; } = revision;
        internal string? TerminalReason { get; set; } = terminalReason;
        internal ServiceMonotonicTimestamp? RetentionDeadline { get; set; } = retentionDeadline;
    }

    private sealed record Receipt(
        SimulatedDecisionResultMessage? DecisionResult,
        SimulatedRuleMutationResultMessage? RuleMutationResult,
        SimulatedDecisionChoice? Choice,
        string? ErrorCode,
        string? ErrorMessage,
        ServiceMonotonicTimestamp RetentionDeadline);
}
