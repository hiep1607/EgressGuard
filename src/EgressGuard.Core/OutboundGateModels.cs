using System.Net;

namespace EgressGuard.Core;

public static class OutboundGateLimits
{
    public const int CurrentVersion = 1;
    public const int MaximumIdentifierLength = 128;
    public const int MaximumReasonLength = 256;
    public const int MaximumDomainLength = 253;
    public const int MaximumGroupMembers = 32;
    public const int MaximumAuthenticatorBytes = 64;
    public const long MaximumFileSizeBytes = 1L << 50;
    public const long MaximumGrantBytes = 512L * 1024 * 1024;
    public static readonly TimeSpan MaximumGrantDuration = TimeSpan.FromMinutes(5);

    public static void RequireVersion(int version)
    {
        if (version != CurrentVersion)
            throw new ArgumentOutOfRangeException(nameof(version), version, $"Unsupported outbound-gate contract version; expected {CurrentVersion}.");
    }

    public static string Required(string value, string name, int maximumLength)
    {
        if (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength)
            throw new ArgumentException($"{name} must contain 1-{maximumLength} characters.", name);
        return value;
    }

    public static string? Optional(string? value, string name, int maximumLength)
    {
        if (value is not null && value.Length > maximumLength)
            throw new ArgumentException($"{name} must contain at most {maximumLength} characters.", name);
        return value;
    }

    public static DateTimeOffset Utc(DateTimeOffset value, string name)
    {
        if (value == default)
            throw new ArgumentException($"{name} is required.", name);
        return value.ToUniversalTime();
    }

    public static void Process(ProcessIdentity identity, string name = nameof(ProcessIdentity))
    {
        if (identity.ProcessId <= 0 || identity.StartTime == default)
            throw new ArgumentException($"{name} must contain a positive PID and a non-default start time.", name);
    }

    public static void GuidValue(Guid value, string name)
    {
        if (value == Guid.Empty)
            throw new ArgumentException($"{name} is required.", name);
    }

    public static IReadOnlyList<T> CopyBounded<T>(IReadOnlyList<T>? values, string name, int maximum, bool requireAtLeastOne = false)
    {
        if (values is null || values.Count > maximum || (requireAtLeastOne && values.Count == 0))
            throw new ArgumentException($"{name} has an invalid item count.", name);
        return values.ToArray();
    }
}

#pragma warning disable CA1711 // Protocol vocabulary intentionally uses a flags enum.
[Flags]
public enum GateCoverageFlags
{
    None = 0,
    NewTcp = 1 << 0,
    NewUdp = 1 << 1,
    ExistingTcpStream = 1 << 2,
    ExistingUdpDatagram = 1 << 3,
    ReconnectRequiredSimulation = 1 << 4
}
#pragma warning restore CA1711

public sealed record GateCoverage
{
    private const GateCoverageFlags KnownFlags = GateCoverageFlags.NewTcp
        | GateCoverageFlags.NewUdp
        | GateCoverageFlags.ExistingTcpStream
        | GateCoverageFlags.ExistingUdpDatagram
        | GateCoverageFlags.ReconnectRequiredSimulation;

    public int Version { get; }
    public GateCoverageFlags Flags { get; }

    public GateCoverage(int version, GateCoverageFlags flags)
    {
        OutboundGateLimits.RequireVersion(version);
        if ((flags & ~KnownFlags) != 0)
            throw new ArgumentOutOfRangeException(nameof(flags), flags, "Unknown gate coverage capability.");
        Version = version;
        Flags = flags;
    }

    public bool Contains(GateCoverage required) => Version == required.Version && (Flags & required.Flags) == required.Flags;
}

public sealed record FileVersionIdentity
{
    public int Version { get; }
    public string VolumeId { get; }
    public string FileId { get; }
    public DateTimeOffset CreationTimeUtc { get; }
    public long SizeBytes { get; }
    public DateTimeOffset LastWriteTimeUtc { get; }
    public string VersionToken { get; }

    public FileVersionIdentity(int version, string volumeId, string fileId, DateTimeOffset creationTimeUtc, long sizeBytes, DateTimeOffset lastWriteTimeUtc, string versionToken)
    {
        OutboundGateLimits.RequireVersion(version);
        if (sizeBytes is < 0 or > OutboundGateLimits.MaximumFileSizeBytes)
            throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        Version = version;
        VolumeId = OutboundGateLimits.Required(volumeId, nameof(volumeId), OutboundGateLimits.MaximumIdentifierLength);
        FileId = OutboundGateLimits.Required(fileId, nameof(fileId), OutboundGateLimits.MaximumIdentifierLength);
        CreationTimeUtc = OutboundGateLimits.Utc(creationTimeUtc, nameof(creationTimeUtc));
        SizeBytes = sizeBytes;
        LastWriteTimeUtc = OutboundGateLimits.Utc(lastWriteTimeUtc, nameof(lastWriteTimeUtc));
        VersionToken = OutboundGateLimits.Required(versionToken, nameof(versionToken), OutboundGateLimits.MaximumIdentifierLength);
    }
}

public sealed record GateSubject
{
    public int Version { get; }
    public ProcessIdentity ProcessIdentity { get; }
    public string ApplicationIdentity { get; }
    public Guid? ProcessGroupId { get; }
    public IReadOnlyList<ProcessIdentity> GroupMembers { get; }

    public GateSubject(int version, ProcessIdentity processIdentity, string applicationIdentity, Guid? processGroupId, IReadOnlyList<ProcessIdentity>? groupMembers)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.Process(processIdentity);
        if (applicationIdentity.Contains('\\') || applicationIdentity.Contains('/'))
            throw new ArgumentException("Application identity must be canonical identity, not a file path.", nameof(applicationIdentity));
        var members = OutboundGateLimits.CopyBounded(groupMembers, nameof(groupMembers), OutboundGateLimits.MaximumGroupMembers, requireAtLeastOne: true);
        foreach (var member in members)
            OutboundGateLimits.Process(member);
        if (!members.Contains(processIdentity))
            throw new ArgumentException("Group members must contain the exact subject process identity.", nameof(groupMembers));
        if (processGroupId is null && members.Count != 1)
            throw new ArgumentException("Multiple process members require a process-group identity.", nameof(processGroupId));
        if (processGroupId == Guid.Empty)
            throw new ArgumentException("Process-group identity cannot be empty.", nameof(processGroupId));
        Version = version;
        ProcessIdentity = processIdentity;
        ApplicationIdentity = OutboundGateLimits.Required(applicationIdentity, nameof(applicationIdentity), OutboundGateLimits.MaximumIdentifierLength);
        ProcessGroupId = processGroupId;
        GroupMembers = members;
    }

    public bool Matches(GateSubject other) =>
        other is not null
        && Version == other.Version
        && ProcessIdentity == other.ProcessIdentity
        && string.Equals(ApplicationIdentity, other.ApplicationIdentity, StringComparison.Ordinal)
        && ProcessGroupId == other.ProcessGroupId
        && GroupMembers.SequenceEqual(other.GroupMembers);
}

public sealed record DestinationBinding
{
    public int Version { get; }
    public IPAddress Address { get; }
    public IpVersion IpVersion { get; }
    public int RemotePort { get; }
    public TransportProtocol Protocol { get; }
    public string? DomainEvidence { get; }

    public DestinationBinding(int version, IPAddress address, IpVersion ipVersion, int remotePort, TransportProtocol protocol, string? domainEvidence)
    {
        OutboundGateLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(address);
        if (!Enum.IsDefined(ipVersion) || !Enum.IsDefined(protocol)
            || remotePort is < 1 or > 65535
            || (ipVersion == IpVersion.IPv4 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            || (ipVersion == IpVersion.IPv6 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6))
            throw new ArgumentOutOfRangeException(nameof(remotePort), "Destination address family and port must be valid.");
        Version = version;
        Address = address;
        IpVersion = ipVersion;
        RemotePort = remotePort;
        Protocol = protocol;
        DomainEvidence = OutboundGateLimits.Optional(domainEvidence, nameof(domainEvidence), OutboundGateLimits.MaximumDomainLength);
    }
}

public sealed record FileReadIntent
{
    public int Version { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public FileVersionIdentity File { get; }
    public FileActivityOperation Operation { get; }
    public DateTimeOffset ObservedAtUtc { get; }
    public long DeadlineTicks { get; }
    public Guid BootInstance { get; }
    public long Sequence { get; }

    public FileReadIntent(int version, Guid intentId, GateSubject subject, FileVersionIdentity file, FileActivityOperation operation, DateTimeOffset observedAtUtc, long deadlineTicks, Guid bootInstance, long sequence)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(file);
        if (operation is not (FileActivityOperation.Read or FileActivityOperation.OpenCreate) || deadlineTicks <= 0 || sequence <= 0)
            throw new ArgumentOutOfRangeException(nameof(operation), "Read intent operation, deadline and sequence must be valid.");
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        Version = version;
        IntentId = intentId;
        Subject = subject;
        File = file;
        Operation = operation;
        ObservedAtUtc = OutboundGateLimits.Utc(observedAtUtc, nameof(observedAtUtc));
        DeadlineTicks = deadlineTicks;
        BootInstance = bootInstance;
        Sequence = sequence;
    }
}

public sealed record GateArmRequest
{
    public int Version { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public GateCoverage RequiredCoverage { get; }
    public long PolicyEpoch { get; }
    public Guid DriverGeneration { get; }
    public Guid RequestNonce { get; }
    public DateTimeOffset ArmedDeadlineUtc { get; }
    public long ArmedDeadlineTicks { get; }

    public GateArmRequest(int version, Guid intentId, GateSubject subject, GateCoverage requiredCoverage, long policyEpoch, Guid driverGeneration, Guid requestNonce, DateTimeOffset armedDeadlineUtc, long armedDeadlineTicks)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(requiredCoverage);
        if (requiredCoverage.Flags == GateCoverageFlags.None || policyEpoch < 0 || armedDeadlineTicks <= 0)
            throw new ArgumentOutOfRangeException(nameof(requiredCoverage), "Required coverage, policy epoch and monotonic deadline must be valid.");
        OutboundGateLimits.GuidValue(driverGeneration, nameof(driverGeneration));
        OutboundGateLimits.GuidValue(requestNonce, nameof(requestNonce));
        Version = version;
        IntentId = intentId;
        Subject = subject;
        RequiredCoverage = requiredCoverage;
        PolicyEpoch = policyEpoch;
        DriverGeneration = driverGeneration;
        RequestNonce = requestNonce;
        ArmedDeadlineUtc = OutboundGateLimits.Utc(armedDeadlineUtc, nameof(armedDeadlineUtc));
        ArmedDeadlineTicks = armedDeadlineTicks;
    }
}

public sealed record GateArmAck
{
    public int Version { get; }
    public Guid AckId { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public GateCoverage RequiredCoverage { get; }
    public GateCoverage ArmedCoverage { get; }
    public long PolicyEpoch { get; }
    public Guid DriverGeneration { get; }
    public Guid RequestNonce { get; }
    public Guid AckNonce { get; }
    public DateTimeOffset AcknowledgedAtUtc { get; }
    public DateTimeOffset ArmedDeadlineUtc { get; }
    public long ArmedDeadlineTicks { get; }
    public string? UnsupportedOrDegradedReason { get; }

    public GateArmAck(int version, Guid ackId, Guid intentId, GateSubject subject, GateCoverage requiredCoverage, GateCoverage armedCoverage, long policyEpoch, Guid driverGeneration, Guid requestNonce, Guid ackNonce, DateTimeOffset acknowledgedAtUtc, DateTimeOffset armedDeadlineUtc, long armedDeadlineTicks, string? unsupportedOrDegradedReason)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(ackId, nameof(ackId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(requiredCoverage);
        ArgumentNullException.ThrowIfNull(armedCoverage);
        if (requiredCoverage.Flags == GateCoverageFlags.None)
            throw new ArgumentOutOfRangeException(nameof(requiredCoverage));
        OutboundGateLimits.GuidValue(driverGeneration, nameof(driverGeneration));
        OutboundGateLimits.GuidValue(requestNonce, nameof(requestNonce));
        OutboundGateLimits.GuidValue(ackNonce, nameof(ackNonce));
        if (policyEpoch < 0 || armedDeadlineTicks <= 0)
            throw new ArgumentOutOfRangeException(nameof(policyEpoch));
        Version = version;
        AckId = ackId;
        IntentId = intentId;
        Subject = subject;
        RequiredCoverage = requiredCoverage;
        ArmedCoverage = armedCoverage;
        PolicyEpoch = policyEpoch;
        DriverGeneration = driverGeneration;
        RequestNonce = requestNonce;
        AckNonce = ackNonce;
        AcknowledgedAtUtc = OutboundGateLimits.Utc(acknowledgedAtUtc, nameof(acknowledgedAtUtc));
        ArmedDeadlineUtc = OutboundGateLimits.Utc(armedDeadlineUtc, nameof(armedDeadlineUtc));
        ArmedDeadlineTicks = armedDeadlineTicks;
        UnsupportedOrDegradedReason = OutboundGateLimits.Optional(unsupportedOrDegradedReason, nameof(unsupportedOrDegradedReason), OutboundGateLimits.MaximumReasonLength);
    }

    public bool HasFullCoverageFor(GateArmRequest request) =>
        request is not null
        && IntentId == request.IntentId
        && Subject.Matches(request.Subject)
        && RequiredCoverage.Version == request.RequiredCoverage.Version
        && RequiredCoverage.Flags == request.RequiredCoverage.Flags
        && PolicyEpoch == request.PolicyEpoch
        && DriverGeneration == request.DriverGeneration
        && RequestNonce == request.RequestNonce
        && ArmedDeadlineUtc == request.ArmedDeadlineUtc
        && ArmedDeadlineTicks == request.ArmedDeadlineTicks
        && ArmedCoverage.Contains(request.RequiredCoverage)
        && string.IsNullOrWhiteSpace(UnsupportedOrDegradedReason);

    public void ValidateFor(GateArmRequest request)
    {
        if (!HasFullCoverageFor(request))
            throw new InvalidOperationException("Gate acknowledgement is partial, stale or bound to a different request.");
    }
}

public enum FileReadDispositionKind
{
    ReleaseAfterGateArmed,
    FailOpenRelease,
    Cancel
}

public sealed record FileReadDisposition
{
    public int Version { get; }
    public Guid IntentId { get; }
    public ProcessIdentity ProcessIdentity { get; }
    public FileVersionIdentity File { get; }
    public FileReadDispositionKind Disposition { get; }
    public Guid? GateAckId { get; }
    public long DeadlineTicks { get; }
    public string ReasonCode { get; }
    public long Sequence { get; }

    public FileReadDisposition(int version, Guid intentId, ProcessIdentity processIdentity, FileVersionIdentity file, FileReadDispositionKind disposition, Guid? gateAckId, long deadlineTicks, string reasonCode, long sequence)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        OutboundGateLimits.Process(processIdentity);
        ArgumentNullException.ThrowIfNull(file);
        OutboundGateLimits.Required(reasonCode, nameof(reasonCode), OutboundGateLimits.MaximumReasonLength);
        if (deadlineTicks <= 0 || sequence <= 0 || (disposition == FileReadDispositionKind.ReleaseAfterGateArmed && gateAckId is null))
            throw new ArgumentOutOfRangeException(nameof(disposition));
        Version = version;
        IntentId = intentId;
        ProcessIdentity = processIdentity;
        File = file;
        Disposition = disposition;
        GateAckId = gateAckId;
        DeadlineTicks = deadlineTicks;
        ReasonCode = reasonCode;
        Sequence = sequence;
    }
}

public enum FileReadCompletionResult
{
    Released,
    FailedOpen,
    Canceled
}

public sealed record FileReadCompletionAck
{
    public int Version { get; }
    public Guid CompletionId { get; }
    public Guid IntentId { get; }
    public ProcessIdentity ProcessIdentity { get; }
    public FileVersionIdentity File { get; }
    public long DispositionSequence { get; }
    public FileReadCompletionResult Result { get; }
    public string ReasonCode { get; }
    public long MonotonicSequence { get; }

    public FileReadCompletionAck(int version, Guid completionId, Guid intentId, ProcessIdentity processIdentity, FileVersionIdentity file, long dispositionSequence, FileReadCompletionResult result, string reasonCode, long monotonicSequence)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(completionId, nameof(completionId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        OutboundGateLimits.Process(processIdentity);
        ArgumentNullException.ThrowIfNull(file);
        OutboundGateLimits.Required(reasonCode, nameof(reasonCode), OutboundGateLimits.MaximumReasonLength);
        if (!Enum.IsDefined(result) || dispositionSequence <= 0 || monotonicSequence <= 0)
            throw new ArgumentOutOfRangeException(nameof(dispositionSequence));
        Version = version;
        CompletionId = completionId;
        IntentId = intentId;
        ProcessIdentity = processIdentity;
        File = file;
        DispositionSequence = dispositionSequence;
        Result = result;
        ReasonCode = reasonCode;
        MonotonicSequence = monotonicSequence;
    }
}

public sealed record NetworkGateChallenge
{
    public int Version { get; }
    public Guid ChallengeId { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public DestinationBinding Destination { get; }
    public long FlowGeneration { get; }
    public bool ExistingFlow { get; }
    public GateCoverage RequiredCoverage { get; }
    public long DecisionDeadlineTicks { get; }
    public DateTimeOffset CreatedAtUtc { get; }
    public string? LimitationReason { get; }

    public NetworkGateChallenge(int version, Guid challengeId, Guid intentId, GateSubject subject, DestinationBinding destination, long flowGeneration, bool existingFlow, GateCoverage requiredCoverage, long decisionDeadlineTicks, DateTimeOffset createdAtUtc, string? limitationReason)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(challengeId, nameof(challengeId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(requiredCoverage);
        if (requiredCoverage.Flags == GateCoverageFlags.None || flowGeneration <= 0 || decisionDeadlineTicks <= 0)
            throw new ArgumentOutOfRangeException(nameof(flowGeneration));
        Version = version;
        ChallengeId = challengeId;
        IntentId = intentId;
        Subject = subject;
        Destination = destination;
        FlowGeneration = flowGeneration;
        ExistingFlow = existingFlow;
        RequiredCoverage = requiredCoverage;
        DecisionDeadlineTicks = decisionDeadlineTicks;
        CreatedAtUtc = OutboundGateLimits.Utc(createdAtUtc, nameof(createdAtUtc));
        LimitationReason = OutboundGateLimits.Optional(limitationReason, nameof(limitationReason), OutboundGateLimits.MaximumReasonLength);
    }
}

public enum UserDecisionKind
{
    AllowOnce,
    AlwaysAllow,
    Block
}

public sealed record UserDecision
{
    public int Version { get; }
    public Guid DecisionId { get; }
    public Guid ChallengeId { get; }
    public UserDecisionKind Decision { get; }
    public DateTimeOffset UiTimestampUtc { get; }
    public string AuthenticatedCaller { get; }

    public UserDecision(int version, Guid decisionId, Guid challengeId, UserDecisionKind decision, DateTimeOffset uiTimestampUtc, string authenticatedCaller)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(decisionId, nameof(decisionId));
        OutboundGateLimits.GuidValue(challengeId, nameof(challengeId));
        if (!Enum.IsDefined(decision))
            throw new ArgumentOutOfRangeException(nameof(decision));
        Version = version;
        DecisionId = decisionId;
        ChallengeId = challengeId;
        Decision = decision;
        UiTimestampUtc = OutboundGateLimits.Utc(uiTimestampUtc, nameof(uiTimestampUtc));
        AuthenticatedCaller = OutboundGateLimits.Required(authenticatedCaller, nameof(authenticatedCaller), OutboundGateLimits.MaximumIdentifierLength);
    }
}

public sealed record OneTimeTicket
{
    public int Version { get; }
    public Guid TicketId { get; }
    public Guid Nonce { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public FileVersionIdentity File { get; }
    public DestinationBinding Destination { get; }
    public long FlowGeneration { get; }
    public long PolicyEpoch { get; }
    public Guid BootInstance { get; }
    public DateTimeOffset IssuedAtUtc { get; }
    public DateTimeOffset ExpiresAtUtc { get; }
    public long NotBeforeTicks { get; }
    public long ExpiresAtTicks { get; }
    public long GrantMaxBytes { get; }
    public long GrantMaxDurationTicks { get; }
    public IReadOnlyList<byte> AuthenticatorProof { get; }

    public OneTimeTicket(int version, Guid ticketId, Guid nonce, Guid intentId, GateSubject subject, FileVersionIdentity file, DestinationBinding destination, long flowGeneration, long policyEpoch, Guid bootInstance, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc, long notBeforeTicks, long expiresAtTicks, long grantMaxBytes, long grantMaxDurationTicks, IReadOnlyList<byte>? authenticatorProof)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(ticketId, nameof(ticketId));
        OutboundGateLimits.GuidValue(nonce, nameof(nonce));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(destination);
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        var issued = OutboundGateLimits.Utc(issuedAtUtc, nameof(issuedAtUtc));
        var expires = OutboundGateLimits.Utc(expiresAtUtc, nameof(expiresAtUtc));
        if (flowGeneration <= 0 || policyEpoch < 0 || expires <= issued || notBeforeTicks <= 0 || expiresAtTicks <= notBeforeTicks || grantMaxBytes is < 1 or > OutboundGateLimits.MaximumGrantBytes || grantMaxDurationTicks < 1 || grantMaxDurationTicks > OutboundGateLimits.MaximumGrantDuration.Ticks)
            throw new ArgumentOutOfRangeException(nameof(flowGeneration), "Ticket bindings, expiry and grant bounds are invalid.");
        var proof = OutboundGateLimits.CopyBounded(authenticatorProof, nameof(authenticatorProof), OutboundGateLimits.MaximumAuthenticatorBytes, requireAtLeastOne: true);
        Version = version;
        TicketId = ticketId;
        Nonce = nonce;
        IntentId = intentId;
        Subject = subject;
        File = file;
        Destination = destination;
        FlowGeneration = flowGeneration;
        PolicyEpoch = policyEpoch;
        BootInstance = bootInstance;
        IssuedAtUtc = issued;
        ExpiresAtUtc = expires;
        NotBeforeTicks = notBeforeTicks;
        ExpiresAtTicks = expiresAtTicks;
        GrantMaxBytes = grantMaxBytes;
        GrantMaxDurationTicks = grantMaxDurationTicks;
        AuthenticatorProof = proof;
    }
}

public sealed record EphemeralFlowGrant
{
    public int Version { get; }
    public Guid GrantId { get; }
    public Guid TicketId { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public DestinationBinding Destination { get; }
    public long FlowGeneration { get; }
    public long PolicyEpoch { get; }
    public Guid BootInstance { get; }
    public long MaximumBytes { get; }
    public long ExpiresAtTicks { get; }

    public EphemeralFlowGrant(int version, Guid grantId, Guid ticketId, Guid intentId, GateSubject subject, DestinationBinding destination, long flowGeneration, long policyEpoch, Guid bootInstance, long maximumBytes, long expiresAtTicks)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(grantId, nameof(grantId));
        OutboundGateLimits.GuidValue(ticketId, nameof(ticketId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        if (flowGeneration <= 0 || policyEpoch < 0 || maximumBytes is < 1 or > OutboundGateLimits.MaximumGrantBytes || expiresAtTicks <= 0)
            throw new ArgumentOutOfRangeException(nameof(maximumBytes));
        Version = version;
        GrantId = grantId;
        TicketId = ticketId;
        IntentId = intentId;
        Subject = subject;
        Destination = destination;
        FlowGeneration = flowGeneration;
        PolicyEpoch = policyEpoch;
        BootInstance = bootInstance;
        MaximumBytes = maximumBytes;
        ExpiresAtTicks = expiresAtTicks;
    }
}

public enum OutboundGateMode
{
    Disabled,
    Simulation
}

public enum GateRuntimeState
{
    Idle,
    Armed,
    AwaitingDecision,
    Granted,
    Blocked,
    FailedOpen,
    Unsupported
}

public sealed record GateStatus
{
    public int Version { get; }
    public OutboundGateMode Mode { get; }
    public GateRuntimeState State { get; }
    public Guid? IntentId { get; }
    public GateCoverage Coverage { get; }
    public long ChangedAtTicks { get; }
    public DateTimeOffset ChangedAtUtc { get; }
    public string? Reason { get; }

    public GateStatus(int version, OutboundGateMode mode, GateRuntimeState state, Guid? intentId, GateCoverage coverage, long changedAtTicks, DateTimeOffset changedAtUtc, string? reason)
    {
        OutboundGateLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(coverage);
        if (!Enum.IsDefined(mode) || !Enum.IsDefined(state))
            throw new ArgumentOutOfRangeException(nameof(state));
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(changedAtTicks);
        Version = version;
        Mode = mode;
        State = state;
        IntentId = intentId;
        Coverage = coverage;
        ChangedAtTicks = changedAtTicks;
        ChangedAtUtc = OutboundGateLimits.Utc(changedAtUtc, nameof(changedAtUtc));
        Reason = OutboundGateLimits.Optional(reason, nameof(reason), OutboundGateLimits.MaximumReasonLength);
    }
}
