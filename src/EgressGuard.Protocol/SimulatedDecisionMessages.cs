using System.Net;
using EgressGuard.Core;

namespace EgressGuard.Protocol;

public static class SimulatedDecisionProtocolLimits
{
    public const int MaximumRedactedFileLabelLength = 96;
    public const int MaximumPromptCount = 128;
    public const int MaximumReconnectNoticeCount = 64;
    public const int MaximumRememberedRuleCount = 64;
    public const int MaximumStatusCount = 64;
    public const int MaximumCriticalAlertCount = 64;
    public const int MaximumGroupMembers = 32;
    public const long MaximumDecisionRemainingMilliseconds = 15_000;
    public const int DecisionSubscriberCapacity = 2;
    public const int PipeInstanceCapacity = 8;
    public const int ReservedRequestReconnectCapacity = 2;
    public const int RuleIdRegistryEntryCapacity = 256;
    public const string GroupCollateralWarning = "This decision affects the displayed browser process group and may delay unrelated activity in that group.";
    public const string FailOpenPresentationText = "Traffic was allowed (fail-open). This operation is no longer protected.";

    internal static void RequireVersion(int version)
    {
        if (version != ProtocolConstants.Version)
            throw new ArgumentOutOfRangeException(nameof(version), version, $"Expected protocol version {ProtocolConstants.Version}.");
    }

    internal static string Required(string? value, string name, int maximumLength)
    {
        if (value is null || string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
            throw new ArgumentException($"{name} must contain 1-{maximumLength} characters.", name);
        return value;
    }

    internal static string? Optional(string? value, string name, int maximumLength)
    {
        if (value is not null && (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength))
            throw new ArgumentException($"{name} must be null or contain 1-{maximumLength} characters.", name);
        return value;
    }

    internal static long NonNegative(long value, string name)
    {
        if (value < 0)
            throw new ArgumentOutOfRangeException(name, value, $"{name} cannot be negative.");
        return value;
    }

    internal static DateTimeOffset Utc(DateTimeOffset value, string name)
    {
        if (value == default)
            throw new ArgumentException($"{name} is required.", name);
        return value.ToUniversalTime();
    }

    internal static void GuidValue(Guid value, string name)
    {
        if (value == Guid.Empty)
            throw new ArgumentException($"{name} is required.", name);
    }

    internal static IReadOnlyList<T> Copy<T>(IReadOnlyList<T>? values, string name, int maximum)
    {
        if (values is null || values.Count > maximum)
            throw new ArgumentException($"{name} must contain at most {maximum} items.", name);
        var copy = values.ToArray();
        if (copy.Any(item => item is null))
            throw new ArgumentException($"{name} cannot contain null items.", name);
        return copy;
    }

    internal static void Process(ProcessIdentity identity, string name)
    {
        OutboundGateLimits.Process(identity, name);
    }

    internal static string Application(string value, string name) =>
        OutboundGateLimits.ApplicationIdentity(value, name);

    internal static string Reason(string value, string name = "reasonCode") =>
        Required(value, name, OutboundGateLimits.MaximumReasonLength);

    internal static string? Limitation(string? value, string name = "limitationReason") =>
        Optional(value, name, OutboundGateLimits.MaximumReasonLength);

    internal static void Counter(long value, string name)
    {
        OutboundGateLimits.Counter(value, name);
    }

    internal static void State(SimulatedDecisionItemState state, string name)
    {
        if (!Enum.IsDefined(state))
            throw new ArgumentOutOfRangeException(name, state, "Unknown simulated-decision item state.");
    }

    internal static bool IsRememberedRuleState(SimulatedDecisionItemState state) =>
        state is SimulatedDecisionItemState.Remembered
            or SimulatedDecisionItemState.Expired
            or SimulatedDecisionItemState.Revoked
            or SimulatedDecisionItemState.FileVersionInvalidated
            or SimulatedDecisionItemState.PolicyInvalidated;

    internal static int CompareProcessIdentity(ProcessIdentity left, ProcessIdentity right)
    {
        var pid = left.ProcessId.CompareTo(right.ProcessId);
        return pid != 0 ? pid : left.StartTime.UtcTicks.CompareTo(right.StartTime.UtcTicks);
    }

    internal static string RedactedFileLabel(string value)
    {
        var label = Required(value, nameof(value), MaximumRedactedFileLabelLength);
        if (label.Any(char.IsControl)
            || label.Contains(':', StringComparison.Ordinal)
            || label.Contains('/', StringComparison.Ordinal)
            || label.Contains('\\', StringComparison.Ordinal)
            || Path.IsPathRooted(label)
            || label is "." or "..")
            throw new ArgumentException("Redacted file label must be a safe basename without path syntax.", nameof(value));
        return label;
    }

    internal static void RequireUnique<T>(IReadOnlyList<T> values, string name)
    {
        if (values.Distinct().Count() != values.Count)
            throw new ArgumentException($"{name} must contain unique values.", name);
    }
}

public enum SimulatedDecisionChoice
{
    Unspecified,
    AllowOnce,
    RememberFor30Days,
    BlockCurrent
}

public sealed record GetSimulatedDecisionSnapshotMessage
{
    public int Version { get; }

    public GetSimulatedDecisionSnapshotMessage(int version)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        Version = version;
    }
}

public sealed record SubscribeSimulatedDecisionEventsMessage
{
    public int Version { get; }
    public long LastSequence { get; }

    public SubscribeSimulatedDecisionEventsMessage(int version, long lastSequence)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        Version = version;
        LastSequence = SimulatedDecisionProtocolLimits.NonNegative(lastSequence, nameof(lastSequence));
    }
}

public sealed record SubmitSimulatedDecisionMessage
{
    public int Version { get; }
    public Guid ChallengeId { get; }
    public SimulatedDecisionChoice Choice { get; }

    public SubmitSimulatedDecisionMessage(int version, Guid challengeId, SimulatedDecisionChoice choice)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(challengeId, nameof(challengeId));
        if (!Enum.IsDefined(choice) || choice == SimulatedDecisionChoice.Unspecified)
            throw new ArgumentOutOfRangeException(nameof(choice), choice, "A concrete simulated-decision choice is required.");
        Version = version;
        ChallengeId = challengeId;
        Choice = choice;
    }
}

public sealed record RevokeSimulatedRememberedRuleMessage
{
    public int Version { get; }
    public Guid RuleId { get; }
    public long ExpectedRevision { get; }

    public RevokeSimulatedRememberedRuleMessage(int version, Guid ruleId, long expectedRevision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(ruleId, nameof(ruleId));
        Version = version;
        RuleId = ruleId;
        ExpectedRevision = SimulatedDecisionProtocolLimits.NonNegative(expectedRevision, nameof(expectedRevision));
    }
}

public enum SimulatedDecisionSubjectKind
{
    ExactProcess,
    ExactProcessGroup
}

public enum SimulatedDecisionItemState
{
    AwaitingDecision,
    AllowedOnce,
    Remembered,
    BlockedCurrent,
    Expired,
    FailedOpen,
    ReconnectRequired,
    Revoked,
    FileVersionInvalidated,
    PolicyInvalidated
}

public sealed record SimulatedFileVersionProjection
{
    public int Version { get; }
    public string VersionToken { get; }
    public long SizeBytes { get; }
    public DateTimeOffset LastWriteTimeUtc { get; }
    public DateTimeOffset ChangeTimeUtc { get; }
    public long? Usn { get; }

    public SimulatedFileVersionProjection(int version, string versionToken, long sizeBytes, DateTimeOffset lastWriteTimeUtc, DateTimeOffset changeTimeUtc, long? usn)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        Version = version;
        VersionToken = SimulatedDecisionProtocolLimits.Required(versionToken, nameof(versionToken), OutboundGateLimits.MaximumIdentifierLength);
        if (sizeBytes is < 0 or > OutboundGateLimits.MaximumFileSizeBytes)
            throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        if (usn < 0)
            throw new ArgumentOutOfRangeException(nameof(usn));
        SizeBytes = sizeBytes;
        LastWriteTimeUtc = SimulatedDecisionProtocolLimits.Utc(lastWriteTimeUtc, nameof(lastWriteTimeUtc));
        ChangeTimeUtc = SimulatedDecisionProtocolLimits.Utc(changeTimeUtc, nameof(changeTimeUtc));
        Usn = usn;
    }
}

public sealed record SimulatedSubjectProjection
{
    public int Version { get; }
    public SimulatedDecisionSubjectKind Kind { get; }
    public ProcessIdentity PrimaryProcess { get; }
    public Guid? ProcessGroupId { get; }
    public IReadOnlyList<ProcessIdentity> ExactMembers { get; }
    public bool HasCollateralScope { get; }
    public string? CollateralWarning { get; }

    public SimulatedSubjectProjection(int version, SimulatedDecisionSubjectKind kind, ProcessIdentity primaryProcess, Guid? processGroupId, IReadOnlyList<ProcessIdentity>? exactMembers, bool hasCollateralScope, string? collateralWarning)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        if (!Enum.IsDefined(kind))
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown simulated-decision subject kind.");
        SimulatedDecisionProtocolLimits.Process(primaryProcess, nameof(primaryProcess));
        var members = SimulatedDecisionProtocolLimits.Copy(exactMembers, nameof(exactMembers), SimulatedDecisionProtocolLimits.MaximumGroupMembers);
        foreach (var member in members)
            SimulatedDecisionProtocolLimits.Process(member, nameof(exactMembers));
        SimulatedDecisionProtocolLimits.RequireUnique(members, nameof(exactMembers));
        if (!members.Contains(primaryProcess))
            throw new ArgumentException("Exact members must contain the primary process.", nameof(exactMembers));
        if (members.Zip(members.Skip(1)).Any(pair => SimulatedDecisionProtocolLimits.CompareProcessIdentity(pair.First, pair.Second) >= 0))
            throw new ArgumentException("Exact members must be in canonical PID/start-time order.", nameof(exactMembers));

        if (kind == SimulatedDecisionSubjectKind.ExactProcess)
        {
            if (processGroupId is not null || members.Count != 1 || hasCollateralScope || collateralWarning is not null)
                throw new ArgumentException("Exact-process scope cannot contain group or collateral metadata.");
        }
        else
        {
            if (processGroupId is null || processGroupId == Guid.Empty || members.Count is < 2 or > SimulatedDecisionProtocolLimits.MaximumGroupMembers || !hasCollateralScope || collateralWarning != SimulatedDecisionProtocolLimits.GroupCollateralWarning)
                throw new ArgumentException("Exact-process-group scope must carry the fixed collateral contract.");
        }

        Version = version;
        Kind = kind;
        PrimaryProcess = primaryProcess;
        ProcessGroupId = processGroupId;
        ExactMembers = members;
        HasCollateralScope = hasCollateralScope;
        CollateralWarning = SimulatedDecisionProtocolLimits.Optional(collateralWarning, nameof(collateralWarning), OutboundGateLimits.MaximumReasonLength);
    }
}

public sealed record SimulatedDestinationProjection
{
    public int Version { get; }
    public IPAddress Address { get; }
    public IpVersion IpVersion { get; }
    public int RemotePort { get; }
    public TransportProtocol Protocol { get; }
    public string? DomainEvidence { get; }
    public DomainEvidenceProvenance DomainProvenance { get; }

    public SimulatedDestinationProjection(int version, IPAddress address, IpVersion ipVersion, int remotePort, TransportProtocol protocol, string? domainEvidence, DomainEvidenceProvenance domainProvenance)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
            throw new ArgumentException("IPv4-mapped IPv6 addresses must be normalized before projection.", nameof(address));
        if (!Enum.IsDefined(ipVersion) || !Enum.IsDefined(protocol)
            || remotePort is < 1 or > 65535
            || (ipVersion == IpVersion.IPv4 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            || (ipVersion == IpVersion.IPv6 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6))
            throw new ArgumentOutOfRangeException(nameof(remotePort), "Destination address family, port and protocol must be valid.");
        if (!Enum.IsDefined(domainProvenance))
            throw new ArgumentOutOfRangeException(nameof(domainProvenance));
        if ((domainEvidence is null && domainProvenance != DomainEvidenceProvenance.None)
            || (domainEvidence is not null && domainProvenance == DomainEvidenceProvenance.None))
            throw new ArgumentException("Domain evidence and provenance must be present together.", nameof(domainEvidence));
        Version = version;
        Address = address;
        IpVersion = ipVersion;
        RemotePort = remotePort;
        Protocol = protocol;
        DomainEvidence = SimulatedDecisionProtocolLimits.Optional(domainEvidence, nameof(domainEvidence), OutboundGateLimits.MaximumDomainLength);
        DomainProvenance = domainProvenance;
    }
}

public sealed record SimulatedDecisionExpiryProjection
{
    public int Version { get; }
    public long RemainingMilliseconds { get; }
    public DateTimeOffset ProjectedAtUtc { get; }
    public bool AcceptingDecisions { get; }

    public SimulatedDecisionExpiryProjection(int version, long remainingMilliseconds, DateTimeOffset projectedAtUtc, bool acceptingDecisions)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        if (remainingMilliseconds is < 0 or > SimulatedDecisionProtocolLimits.MaximumDecisionRemainingMilliseconds
            || (acceptingDecisions && remainingMilliseconds < 1)
            || (!acceptingDecisions && remainingMilliseconds != 0))
            throw new ArgumentOutOfRangeException(nameof(remainingMilliseconds), "Prompt expiry must be 0 when closed and 1-15000 ms when accepting.");
        Version = version;
        RemainingMilliseconds = remainingMilliseconds;
        ProjectedAtUtc = SimulatedDecisionProtocolLimits.Utc(projectedAtUtc, nameof(projectedAtUtc));
        AcceptingDecisions = acceptingDecisions;
    }
}

public sealed record SimulatedDecisionPromptProjection
{
    public int Version { get; }
    public Guid ChallengeId { get; }
    public Guid IntentId { get; }
    public string RedactedFileLabel { get; }
    public SimulatedFileVersionProjection FileVersion { get; }
    public string ApplicationIdentity { get; }
    public SimulatedSubjectProjection Subject { get; }
    public SimulatedDestinationProjection Destination { get; }
    public bool ExistingFlow { get; }
    public GateRuntimeState State { get; }
    public string ReasonCode { get; }
    public string? LimitationReason { get; }
    public SimulatedDecisionExpiryProjection Expiry { get; }
    public long Revision { get; }

    public SimulatedDecisionPromptProjection(int version, Guid challengeId, Guid intentId, string redactedFileLabel, SimulatedFileVersionProjection fileVersion, string applicationIdentity, SimulatedSubjectProjection subject, SimulatedDestinationProjection destination, bool existingFlow, GateRuntimeState state, string reasonCode, string? limitationReason, SimulatedDecisionExpiryProjection expiry, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(challengeId, nameof(challengeId));
        SimulatedDecisionProtocolLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(fileVersion);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(expiry);
        if (existingFlow)
            throw new ArgumentException("Decision prompts cannot represent an existing multiplexed flow.", nameof(existingFlow));
        if (!Enum.IsDefined(state) || state == GateRuntimeState.Unsupported)
            throw new ArgumentOutOfRangeException(nameof(state), state, "Prompt state is not valid for a simulated decision projection.");
        var accepting = state == GateRuntimeState.AwaitingDecision;
        if (expiry.AcceptingDecisions != accepting)
            throw new ArgumentException("Prompt state and expiry acceptance must agree.", nameof(expiry));
        Version = version;
        ChallengeId = challengeId;
        IntentId = intentId;
        RedactedFileLabel = SimulatedDecisionProtocolLimits.RedactedFileLabel(redactedFileLabel);
        FileVersion = fileVersion;
        ApplicationIdentity = SimulatedDecisionProtocolLimits.Application(applicationIdentity, nameof(applicationIdentity));
        Subject = subject;
        Destination = destination;
        ExistingFlow = existingFlow;
        State = state;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
        LimitationReason = SimulatedDecisionProtocolLimits.Limitation(limitationReason);
        Expiry = expiry;
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}

public sealed record SimulatedReconnectRequiredProjection
{
    public int Version { get; }
    public Guid IntentId { get; }
    public string RedactedFileLabel { get; }
    public SimulatedFileVersionProjection FileVersion { get; }
    public string ApplicationIdentity { get; }
    public SimulatedSubjectProjection Subject { get; }
    public SimulatedDestinationProjection Destination { get; }
    public string ReasonCode { get; }
    public string? LimitationReason { get; }
    public DateTimeOffset AuditTimeUtc { get; }
    public long Revision { get; }

    public SimulatedReconnectRequiredProjection(int version, Guid intentId, string redactedFileLabel, SimulatedFileVersionProjection fileVersion, string applicationIdentity, SimulatedSubjectProjection subject, SimulatedDestinationProjection destination, string reasonCode, string? limitationReason, DateTimeOffset auditTimeUtc, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(fileVersion);
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        Version = version;
        IntentId = intentId;
        RedactedFileLabel = SimulatedDecisionProtocolLimits.RedactedFileLabel(redactedFileLabel);
        FileVersion = fileVersion;
        ApplicationIdentity = SimulatedDecisionProtocolLimits.Application(applicationIdentity, nameof(applicationIdentity));
        Subject = subject;
        Destination = destination;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
        LimitationReason = SimulatedDecisionProtocolLimits.Limitation(limitationReason);
        AuditTimeUtc = SimulatedDecisionProtocolLimits.Utc(auditTimeUtc, nameof(auditTimeUtc));
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}

public sealed record SimulatedRememberedRuleProjection
{
    public int Version { get; }
    public Guid RuleId { get; }
    public string RedactedFileLabel { get; }
    public SimulatedFileVersionProjection FileVersion { get; }
    public string ApplicationIdentity { get; }
    public SimulatedDestinationProjection Destination { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public SimulatedDecisionItemState State { get; }
    public string ReasonCode { get; }
    public long Revision { get; }

    public SimulatedRememberedRuleProjection(int version, Guid ruleId, string redactedFileLabel, SimulatedFileVersionProjection fileVersion, string applicationIdentity, SimulatedDestinationProjection destination, DateTimeOffset createdAtUtc, DateTimeOffset expiresAtUtc, SimulatedDecisionItemState state, string reasonCode, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(ruleId, nameof(ruleId));
        ArgumentNullException.ThrowIfNull(fileVersion);
        ArgumentNullException.ThrowIfNull(destination);
        var created = SimulatedDecisionProtocolLimits.Utc(createdAtUtc, nameof(createdAtUtc));
        var expires = SimulatedDecisionProtocolLimits.Utc(expiresAtUtc, nameof(expiresAtUtc));
        if (expires <= created)
            throw new ArgumentOutOfRangeException(nameof(expiresAtUtc), "A remembered rule must expire after creation.");
        SimulatedDecisionProtocolLimits.State(state, nameof(state));
        if (!SimulatedDecisionProtocolLimits.IsRememberedRuleState(state))
            throw new ArgumentOutOfRangeException(nameof(state), state, "State is not valid for a remembered-rule projection.");
        Version = version;
        RuleId = ruleId;
        RedactedFileLabel = SimulatedDecisionProtocolLimits.RedactedFileLabel(redactedFileLabel);
        FileVersion = fileVersion;
        ApplicationIdentity = SimulatedDecisionProtocolLimits.Application(applicationIdentity, nameof(applicationIdentity));
        Destination = destination;
        CreatedAtUtc = created;
        ExpiresAtUtc = expires;
        State = state;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}

public sealed record SimulatedGateStatusProjection
{
    public int Version { get; }
    public Guid? IntentId { get; }
    public GateRuntimeState State { get; }
    public string ReasonCode { get; }
    public DateTimeOffset AuditTimeUtc { get; }
    public bool TrafficFailedOpen { get; }
    public long DroppedCount { get; }
    public long OverflowCount { get; }
    public long Revision { get; }

    public SimulatedGateStatusProjection(int version, Guid? intentId, GateRuntimeState state, string reasonCode, DateTimeOffset auditTimeUtc, bool trafficFailedOpen, long droppedCount, long overflowCount, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        if (intentId == Guid.Empty)
            throw new ArgumentException("IntentId cannot be empty when present.", nameof(intentId));
        if (!Enum.IsDefined(state))
            throw new ArgumentOutOfRangeException(nameof(state), state, "Unknown gate runtime state.");
        Version = version;
        IntentId = intentId;
        State = state;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
        AuditTimeUtc = SimulatedDecisionProtocolLimits.Utc(auditTimeUtc, nameof(auditTimeUtc));
        TrafficFailedOpen = trafficFailedOpen;
        SimulatedDecisionProtocolLimits.Counter(droppedCount, nameof(droppedCount));
        SimulatedDecisionProtocolLimits.Counter(overflowCount, nameof(overflowCount));
        DroppedCount = droppedCount;
        OverflowCount = overflowCount;
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}

public sealed record SimulatedCriticalAlertProjection
{
    public int Version { get; }
    public Guid AlertId { get; }
    public Guid? IntentId { get; }
    public SimulatedSubjectProjection? Subject { get; }
    public string ReasonCode { get; }
    public DateTimeOffset AuditTimeUtc { get; }
    public long DroppedCount { get; }
    public long OverflowCount { get; }
    public bool TrafficFailedOpen { get; }
    public string PresentationText { get; }
    public long Revision { get; }

    public SimulatedCriticalAlertProjection(int version, Guid alertId, Guid? intentId, SimulatedSubjectProjection? subject, string reasonCode, DateTimeOffset auditTimeUtc, long droppedCount, long overflowCount, bool trafficFailedOpen, string presentationText, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(alertId, nameof(alertId));
        if (intentId == Guid.Empty)
            throw new ArgumentException("IntentId cannot be empty when present.", nameof(intentId));
        if (subject is not null && subject.Version != version)
            throw new ArgumentException("Subject must use the projection version.", nameof(subject));
        Version = version;
        AlertId = alertId;
        IntentId = intentId;
        Subject = subject;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
        AuditTimeUtc = SimulatedDecisionProtocolLimits.Utc(auditTimeUtc, nameof(auditTimeUtc));
        SimulatedDecisionProtocolLimits.Counter(droppedCount, nameof(droppedCount));
        SimulatedDecisionProtocolLimits.Counter(overflowCount, nameof(overflowCount));
        if (trafficFailedOpen && presentationText != SimulatedDecisionProtocolLimits.FailOpenPresentationText)
            throw new ArgumentException("Fail-open alerts must use the fixed presentation text.", nameof(presentationText));
        TrafficFailedOpen = trafficFailedOpen;
        PresentationText = SimulatedDecisionProtocolLimits.Required(presentationText, nameof(presentationText), OutboundGateLimits.MaximumReasonLength);
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}

public sealed record SimulatedDecisionAuthorizationProjection
{
    public bool CanView { get; }
    public bool CanAllowOnce { get; }
    public bool CanRememberFor30Days { get; }
    public bool CanBlockCurrent { get; }
    public bool CanRevoke { get; }
    public string ReasonCode { get; }

    public SimulatedDecisionAuthorizationProjection(bool canView, bool canAllowOnce, bool canRememberFor30Days, bool canBlockCurrent, bool canRevoke, string reasonCode)
    {
        if (!canView && (canAllowOnce || canRememberFor30Days || canBlockCurrent || canRevoke))
            throw new ArgumentException("Mutation permissions cannot be granted when viewing is denied.");
        CanView = canView;
        CanAllowOnce = canAllowOnce;
        CanRememberFor30Days = canRememberFor30Days;
        CanBlockCurrent = canBlockCurrent;
        CanRevoke = canRevoke;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
    }
}

public sealed record SimulatedDecisionCapacitySnapshot
{
    public int DecisionSubscriberCount { get; }
    public int DecisionSubscriberCapacity { get; }
    public int PipeInstanceCount { get; }
    public int PipeInstanceCapacity { get; }
    public int ReservedRequestReconnectCount { get; }
    public int ReservedRequestReconnectCapacity { get; }
    public int RuleIdRegistryEntryCount { get; }
    public int RuleIdRegistryEntryCapacity { get; }

    public SimulatedDecisionCapacitySnapshot(int decisionSubscriberCount, int decisionSubscriberCapacity, int pipeInstanceCount, int pipeInstanceCapacity, int reservedRequestReconnectCount, int reservedRequestReconnectCapacity, int ruleIdRegistryEntryCount, int ruleIdRegistryEntryCapacity)
    {
        RequireCount(decisionSubscriberCount, SimulatedDecisionProtocolLimits.DecisionSubscriberCapacity, nameof(decisionSubscriberCount));
        RequireExactCapacity(decisionSubscriberCapacity, SimulatedDecisionProtocolLimits.DecisionSubscriberCapacity, nameof(decisionSubscriberCapacity));
        RequireCount(pipeInstanceCount, SimulatedDecisionProtocolLimits.PipeInstanceCapacity, nameof(pipeInstanceCount));
        RequireExactCapacity(pipeInstanceCapacity, SimulatedDecisionProtocolLimits.PipeInstanceCapacity, nameof(pipeInstanceCapacity));
        RequireCount(reservedRequestReconnectCount, SimulatedDecisionProtocolLimits.ReservedRequestReconnectCapacity, nameof(reservedRequestReconnectCount));
        RequireExactCapacity(reservedRequestReconnectCapacity, SimulatedDecisionProtocolLimits.ReservedRequestReconnectCapacity, nameof(reservedRequestReconnectCapacity));
        RequireCount(ruleIdRegistryEntryCount, SimulatedDecisionProtocolLimits.RuleIdRegistryEntryCapacity, nameof(ruleIdRegistryEntryCount));
        RequireExactCapacity(ruleIdRegistryEntryCapacity, SimulatedDecisionProtocolLimits.RuleIdRegistryEntryCapacity, nameof(ruleIdRegistryEntryCapacity));
        DecisionSubscriberCount = decisionSubscriberCount;
        DecisionSubscriberCapacity = decisionSubscriberCapacity;
        PipeInstanceCount = pipeInstanceCount;
        PipeInstanceCapacity = pipeInstanceCapacity;
        ReservedRequestReconnectCount = reservedRequestReconnectCount;
        ReservedRequestReconnectCapacity = reservedRequestReconnectCapacity;
        RuleIdRegistryEntryCount = ruleIdRegistryEntryCount;
        RuleIdRegistryEntryCapacity = ruleIdRegistryEntryCapacity;
    }

    private static void RequireCount(int value, int maximum, string name)
    {
        if (value is < 0 || value > maximum)
            throw new ArgumentOutOfRangeException(name, value, $"{name} must be between 0 and {maximum}.");
    }

    private static void RequireExactCapacity(int value, int expected, string name)
    {
        if (value != expected)
            throw new ArgumentOutOfRangeException(name, value, $"{name} must be the frozen capacity {expected}.");
    }
}

public sealed record SimulatedDecisionCounterSnapshot
{
    public long RuleIdCollisionCount { get; }
    public long RuleIdRegistryCapacityRejectedCount { get; }
    public long DecisionSubscriberRejectedCount { get; }
    public long ProjectionCapacityFailureCount { get; }

    public SimulatedDecisionCounterSnapshot(long ruleIdCollisionCount, long ruleIdRegistryCapacityRejectedCount, long decisionSubscriberRejectedCount, long projectionCapacityFailureCount)
    {
        SimulatedDecisionProtocolLimits.Counter(ruleIdCollisionCount, nameof(ruleIdCollisionCount));
        SimulatedDecisionProtocolLimits.Counter(ruleIdRegistryCapacityRejectedCount, nameof(ruleIdRegistryCapacityRejectedCount));
        SimulatedDecisionProtocolLimits.Counter(decisionSubscriberRejectedCount, nameof(decisionSubscriberRejectedCount));
        SimulatedDecisionProtocolLimits.Counter(projectionCapacityFailureCount, nameof(projectionCapacityFailureCount));
        RuleIdCollisionCount = ruleIdCollisionCount;
        RuleIdRegistryCapacityRejectedCount = ruleIdRegistryCapacityRejectedCount;
        DecisionSubscriberRejectedCount = decisionSubscriberRejectedCount;
        ProjectionCapacityFailureCount = projectionCapacityFailureCount;
    }
}

public sealed record SimulatedDecisionSnapshotMessage
{
    public int Version { get; }
    public long Sequence { get; }
    public bool SimulationEnabled { get; }
    public SimulatedDecisionAuthorizationProjection Authorization { get; }
    public IReadOnlyList<SimulatedDecisionPromptProjection> ActivePrompts { get; }
    public IReadOnlyList<SimulatedReconnectRequiredProjection> ReconnectNotices { get; }
    public IReadOnlyList<SimulatedRememberedRuleProjection> RememberedRules { get; }
    public IReadOnlyList<SimulatedGateStatusProjection> RecentStatuses { get; }
    public IReadOnlyList<SimulatedCriticalAlertProjection> CriticalAlerts { get; }
    public SimulatedDecisionCapacitySnapshot Capacity { get; }
    public SimulatedDecisionCounterSnapshot Counters { get; }

    public SimulatedDecisionSnapshotMessage(int version, long sequence, bool simulationEnabled, SimulatedDecisionAuthorizationProjection authorization, IReadOnlyList<SimulatedDecisionPromptProjection>? activePrompts, IReadOnlyList<SimulatedReconnectRequiredProjection>? reconnectNotices, IReadOnlyList<SimulatedRememberedRuleProjection>? rememberedRules, IReadOnlyList<SimulatedGateStatusProjection>? recentStatuses, IReadOnlyList<SimulatedCriticalAlertProjection>? criticalAlerts, SimulatedDecisionCapacitySnapshot capacity, SimulatedDecisionCounterSnapshot counters)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(authorization);
        ArgumentNullException.ThrowIfNull(capacity);
        ArgumentNullException.ThrowIfNull(counters);
        Version = version;
        Sequence = SimulatedDecisionProtocolLimits.NonNegative(sequence, nameof(sequence));
        SimulationEnabled = simulationEnabled;
        Authorization = authorization;
        ActivePrompts = SimulatedDecisionProtocolLimits.Copy(activePrompts, nameof(activePrompts), SimulatedDecisionProtocolLimits.MaximumPromptCount);
        ReconnectNotices = SimulatedDecisionProtocolLimits.Copy(reconnectNotices, nameof(reconnectNotices), SimulatedDecisionProtocolLimits.MaximumReconnectNoticeCount);
        RememberedRules = SimulatedDecisionProtocolLimits.Copy(rememberedRules, nameof(rememberedRules), SimulatedDecisionProtocolLimits.MaximumRememberedRuleCount);
        RecentStatuses = SimulatedDecisionProtocolLimits.Copy(recentStatuses, nameof(recentStatuses), SimulatedDecisionProtocolLimits.MaximumStatusCount);
        CriticalAlerts = SimulatedDecisionProtocolLimits.Copy(criticalAlerts, nameof(criticalAlerts), SimulatedDecisionProtocolLimits.MaximumCriticalAlertCount);
        SimulatedDecisionProtocolLimits.RequireUnique(ActivePrompts.Select(item => item.ChallengeId).ToArray(), nameof(activePrompts));
        SimulatedDecisionProtocolLimits.RequireUnique(ReconnectNotices.Select(item => item.IntentId).ToArray(), nameof(reconnectNotices));
        SimulatedDecisionProtocolLimits.RequireUnique(RememberedRules.Select(item => item.RuleId).ToArray(), nameof(rememberedRules));
        Capacity = capacity;
        Counters = counters;
    }
}

public enum SimulatedDecisionEventKind
{
    PromptUpserted,
    PromptRemoved,
    ReconnectRequired,
    RememberedRuleUpserted,
    RememberedRuleRemoved,
    StatusChanged,
    CriticalAlertRaised,
    ResyncRequired
}

public sealed record SimulatedDecisionEventMessage
{
    public int Version { get; }
    public long Sequence { get; }
    public SimulatedDecisionEventKind Kind { get; }
    public SimulatedDecisionPromptProjection? Prompt { get; }
    public Guid? RemovedChallengeId { get; }
    public SimulatedReconnectRequiredProjection? ReconnectNotice { get; }
    public SimulatedRememberedRuleProjection? RememberedRule { get; }
    public Guid? RemovedRuleId { get; }
    public SimulatedGateStatusProjection? Status { get; }
    public SimulatedCriticalAlertProjection? CriticalAlert { get; }
    public bool RequiresResync { get; }

    public SimulatedDecisionEventMessage(int version, long sequence, SimulatedDecisionEventKind kind, SimulatedDecisionPromptProjection? prompt, Guid? removedChallengeId, SimulatedReconnectRequiredProjection? reconnectNotice, SimulatedRememberedRuleProjection? rememberedRule, Guid? removedRuleId, SimulatedGateStatusProjection? status, SimulatedCriticalAlertProjection? criticalAlert, bool requiresResync)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        if (!Enum.IsDefined(kind))
            throw new ArgumentOutOfRangeException(nameof(kind), kind, "Unknown simulated-decision event kind.");
        if (removedChallengeId == Guid.Empty || removedRuleId == Guid.Empty)
            throw new ArgumentException("Removed identifiers cannot be empty when present.");
        Version = version;
        Sequence = SimulatedDecisionProtocolLimits.NonNegative(sequence, nameof(sequence));
        Kind = kind;
        Prompt = prompt;
        RemovedChallengeId = removedChallengeId;
        ReconnectNotice = reconnectNotice;
        RememberedRule = rememberedRule;
        RemovedRuleId = removedRuleId;
        Status = status;
        CriticalAlert = criticalAlert;
        RequiresResync = requiresResync;
        ValidateOneOf();
    }

    private void ValidateOneOf()
    {
        var payloadCount = (Prompt is not null ? 1 : 0)
            + (RemovedChallengeId is not null ? 1 : 0)
            + (ReconnectNotice is not null ? 1 : 0)
            + (RememberedRule is not null ? 1 : 0)
            + (RemovedRuleId is not null ? 1 : 0)
            + (Status is not null ? 1 : 0)
            + (CriticalAlert is not null ? 1 : 0);
        var valid = Kind switch
        {
            SimulatedDecisionEventKind.PromptUpserted => Prompt is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.PromptRemoved => RemovedChallengeId is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.ReconnectRequired => ReconnectNotice is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.RememberedRuleUpserted => RememberedRule is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.RememberedRuleRemoved => RemovedRuleId is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.StatusChanged => Status is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.CriticalAlertRaised => CriticalAlert is not null && payloadCount == 1 && !RequiresResync,
            SimulatedDecisionEventKind.ResyncRequired => payloadCount == 0 && RequiresResync,
            _ => false
        };
        if (!valid)
            throw new ArgumentException("Event payload must contain exactly the member selected by its kind.");
    }
}

public sealed record SimulatedRememberedRuleOutcome
{
    public Guid RuleId { get; }
    public long Revision { get; }
    public SimulatedDecisionItemState State { get; }
    public string ReasonCode { get; }

    public SimulatedRememberedRuleOutcome(Guid ruleId, long revision, SimulatedDecisionItemState state, string reasonCode)
    {
        SimulatedDecisionProtocolLimits.GuidValue(ruleId, nameof(ruleId));
        SimulatedDecisionProtocolLimits.State(state, nameof(state));
        if (!SimulatedDecisionProtocolLimits.IsRememberedRuleState(state))
            throw new ArgumentOutOfRangeException(nameof(state), state, "State is not valid for a remembered-rule outcome.");
        RuleId = ruleId;
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
        State = state;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
    }
}

public sealed record SimulatedDecisionResultMessage
{
    public int Version { get; }
    public long Sequence { get; }
    public Guid ChallengeId { get; }
    public SimulatedDecisionChoice Choice { get; }
    public SimulatedDecisionItemState DecisionState { get; }
    public string DecisionReasonCode { get; }
    public bool TrafficFailedOpen { get; }
    public SimulatedRememberedRuleOutcome? RememberedRule { get; }
    public bool IsDuplicate { get; }
    public long Revision { get; }

    public SimulatedDecisionResultMessage(int version, long sequence, Guid challengeId, SimulatedDecisionChoice choice, SimulatedDecisionItemState decisionState, string decisionReasonCode, bool trafficFailedOpen, SimulatedRememberedRuleOutcome? rememberedRule, bool isDuplicate, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(challengeId, nameof(challengeId));
        if (!Enum.IsDefined(choice) || choice == SimulatedDecisionChoice.Unspecified)
            throw new ArgumentOutOfRangeException(nameof(choice), choice, "A concrete decision choice is required.");
        SimulatedDecisionProtocolLimits.State(decisionState, nameof(decisionState));
        if (decisionState == SimulatedDecisionItemState.ReconnectRequired)
            throw new ArgumentOutOfRangeException(nameof(decisionState), decisionState, "Reconnect is not a decision result.");
        if (trafficFailedOpen != (decisionState == SimulatedDecisionItemState.FailedOpen))
            throw new ArgumentException("TrafficFailedOpen must agree with DecisionState.", nameof(trafficFailedOpen));
        if (choice is SimulatedDecisionChoice.AllowOnce or SimulatedDecisionChoice.BlockCurrent)
        {
            if (rememberedRule is not null)
                throw new ArgumentException("AllowOnce and BlockCurrent cannot carry a remembered-rule outcome.", nameof(rememberedRule));
        }
        else if (rememberedRule is null)
        {
            if (decisionState != SimulatedDecisionItemState.AwaitingDecision)
                throw new ArgumentException("A completed RememberFor30Days result must carry a remembered-rule outcome.", nameof(rememberedRule));
        }
        else if (rememberedRule.State != SimulatedDecisionItemState.Remembered)
        {
            throw new ArgumentException("A completed RememberFor30Days result must report a Remembered rule.", nameof(rememberedRule));
        }
        Version = version;
        Sequence = SimulatedDecisionProtocolLimits.NonNegative(sequence, nameof(sequence));
        ChallengeId = challengeId;
        Choice = choice;
        DecisionState = decisionState;
        DecisionReasonCode = SimulatedDecisionProtocolLimits.Reason(decisionReasonCode, nameof(decisionReasonCode));
        TrafficFailedOpen = trafficFailedOpen;
        RememberedRule = rememberedRule;
        IsDuplicate = isDuplicate;
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}

public enum SimulatedRuleMutationKind
{
    Revoke
}

public sealed record SimulatedRuleMutationResultMessage
{
    public int Version { get; }
    public long Sequence { get; }
    public Guid RuleId { get; }
    public long ExpectedRevision { get; }
    public SimulatedRuleMutationKind Mutation { get; }
    public SimulatedDecisionItemState State { get; }
    public string ReasonCode { get; }
    public bool IsDuplicate { get; }
    public long Revision { get; }

    public SimulatedRuleMutationResultMessage(int version, long sequence, Guid ruleId, long expectedRevision, SimulatedRuleMutationKind mutation, SimulatedDecisionItemState state, string reasonCode, bool isDuplicate, long revision)
    {
        SimulatedDecisionProtocolLimits.RequireVersion(version);
        SimulatedDecisionProtocolLimits.GuidValue(ruleId, nameof(ruleId));
        if (!Enum.IsDefined(mutation) || mutation != SimulatedRuleMutationKind.Revoke)
            throw new ArgumentOutOfRangeException(nameof(mutation), mutation, "Only remembered-rule revoke is supported.");
        if (state != SimulatedDecisionItemState.Revoked)
            throw new ArgumentOutOfRangeException(nameof(state), state, "A revoke result must be Revoked.");
        Version = version;
        Sequence = SimulatedDecisionProtocolLimits.NonNegative(sequence, nameof(sequence));
        RuleId = ruleId;
        ExpectedRevision = SimulatedDecisionProtocolLimits.NonNegative(expectedRevision, nameof(expectedRevision));
        Mutation = mutation;
        State = state;
        ReasonCode = SimulatedDecisionProtocolLimits.Reason(reasonCode);
        IsDuplicate = isDuplicate;
        Revision = SimulatedDecisionProtocolLimits.NonNegative(revision, nameof(revision));
    }
}
