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
    public const int AuthenticatorProofBytes = 32;
    public const long MaximumFileSizeBytes = 1L << 50;
    public const long MaximumGrantBytes = 512L * 1024 * 1024;
    public const long MaximumDiagnosticCounter = uint.MaxValue;
    public const long MaximumServiceMonotonicMilliseconds = 10L * 365 * 24 * 60 * 60 * 1000;
    public static readonly TimeSpan MaximumGateArmReadDuration = TimeSpan.FromSeconds(2);
    public static readonly TimeSpan MaximumDecisionHoldDuration = TimeSpan.FromSeconds(15);
    public static readonly TimeSpan MaximumTicketValidity = TimeSpan.FromSeconds(5);
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

    public static string ApplicationIdentity(string? value, string name)
    {
        var identity = Required(value!, name, MaximumIdentifierLength);
        if (identity.Contains('\\') || identity.Contains('/'))
            throw new ArgumentException("Application identity must be canonical identity, not a file path.", name);
        return identity;
    }

    public static string? Optional(string? value, string name, int maximumLength)
    {
        if (value is not null && (string.IsNullOrWhiteSpace(value) || value.Length > maximumLength))
            throw new ArgumentException($"{name} must be null or contain 1-{maximumLength} characters.", name);
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

    public static void NullableGuid(Guid? value, string name)
    {
        if (value == Guid.Empty)
            throw new ArgumentException($"{name} cannot be empty when present.", name);
    }

    public static void Counter(long value, string name)
    {
        if (value is < 0 or > MaximumDiagnosticCounter)
            throw new ArgumentOutOfRangeException(name, value, $"{name} must be between 0 and {MaximumDiagnosticCounter}.");
    }

    public static IReadOnlyList<T> CopyBounded<T>(IReadOnlyList<T>? values, string name, int maximum, bool requireAtLeastOne = false)
    {
        if (values is null || values.Count > maximum || (requireAtLeastOne && values.Count == 0))
            throw new ArgumentException($"{name} has an invalid item count.", name);
        return values.ToArray();
    }
}

public sealed record ServiceMonotonicTimestamp
{
    public int Version { get; }
    public Guid ClockInstanceId { get; }
    public long ElapsedMilliseconds { get; }

    public ServiceMonotonicTimestamp(int version, Guid clockInstanceId, long elapsedMilliseconds)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(clockInstanceId, nameof(clockInstanceId));
        if (elapsedMilliseconds is < 0 or > OutboundGateLimits.MaximumServiceMonotonicMilliseconds)
            throw new ArgumentOutOfRangeException(nameof(elapsedMilliseconds));
        Version = version;
        ClockInstanceId = clockInstanceId;
        ElapsedMilliseconds = elapsedMilliseconds;
    }
}

public sealed record ServiceMonotonicTimeRange
{
    public int Version { get; }
    public ServiceMonotonicTimestamp StartedAt { get; }
    public ServiceMonotonicTimestamp Deadline { get; }
    public long DurationMilliseconds => Deadline.ElapsedMilliseconds - StartedAt.ElapsedMilliseconds;

    public ServiceMonotonicTimeRange(int version, ServiceMonotonicTimestamp startedAt, ServiceMonotonicTimestamp deadline)
    {
        OutboundGateLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(startedAt);
        ArgumentNullException.ThrowIfNull(deadline);
        if (startedAt.Version != version || deadline.Version != version
            || startedAt.ClockInstanceId != deadline.ClockInstanceId
            || deadline.ElapsedMilliseconds <= startedAt.ElapsedMilliseconds)
            throw new ArgumentException("Service monotonic range must use one clock instance and a deadline after its start.", nameof(deadline));
        Version = version;
        StartedAt = startedAt;
        Deadline = deadline;
    }

    public void ValidateMaximum(TimeSpan maximum, string name)
    {
        if (DurationMilliseconds > maximum.TotalMilliseconds)
            throw new ArgumentOutOfRangeException(name, DurationMilliseconds, $"{name} exceeds {maximum.TotalMilliseconds} milliseconds.");
    }

    public bool Contains(ServiceMonotonicTimestamp timestamp) =>
        timestamp is not null
        && timestamp.Version == Version
        && timestamp.ClockInstanceId == StartedAt.ClockInstanceId
        && timestamp.ElapsedMilliseconds >= StartedAt.ElapsedMilliseconds
        && timestamp.ElapsedMilliseconds <= Deadline.ElapsedMilliseconds;
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
    public DateTimeOffset ChangeTimeUtc { get; }
    public long? Usn { get; }
    public string VersionToken { get; }

    public FileVersionIdentity(int version, string volumeId, string fileId, DateTimeOffset creationTimeUtc, long sizeBytes, DateTimeOffset lastWriteTimeUtc, DateTimeOffset changeTimeUtc, long? usn, string versionToken)
    {
        OutboundGateLimits.RequireVersion(version);
        if (sizeBytes is < 0 or > OutboundGateLimits.MaximumFileSizeBytes)
            throw new ArgumentOutOfRangeException(nameof(sizeBytes));
        if (usn < 0)
            throw new ArgumentOutOfRangeException(nameof(usn));
        Version = version;
        VolumeId = OutboundGateLimits.Required(volumeId, nameof(volumeId), OutboundGateLimits.MaximumIdentifierLength);
        FileId = OutboundGateLimits.Required(fileId, nameof(fileId), OutboundGateLimits.MaximumIdentifierLength);
        CreationTimeUtc = OutboundGateLimits.Utc(creationTimeUtc, nameof(creationTimeUtc));
        SizeBytes = sizeBytes;
        LastWriteTimeUtc = OutboundGateLimits.Utc(lastWriteTimeUtc, nameof(lastWriteTimeUtc));
        ChangeTimeUtc = OutboundGateLimits.Utc(changeTimeUtc, nameof(changeTimeUtc));
        Usn = usn;
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
        var canonicalApplicationIdentity = OutboundGateLimits.ApplicationIdentity(applicationIdentity, nameof(applicationIdentity));
        var members = OutboundGateLimits.CopyBounded(groupMembers, nameof(groupMembers), OutboundGateLimits.MaximumGroupMembers, requireAtLeastOne: true);
        foreach (var member in members)
            OutboundGateLimits.Process(member);
        if (!members.Contains(processIdentity))
            throw new ArgumentException("Group members must contain the exact subject process identity.", nameof(groupMembers));
        if (members.Distinct().Count() != members.Count
            || members.Zip(members.Skip(1)).Any(pair => CompareProcessIdentity(pair.First, pair.Second) >= 0))
            throw new ArgumentException("Group members must be unique and in canonical PID/start-time order.", nameof(groupMembers));
        if (processGroupId is null && members.Count != 1)
            throw new ArgumentException("Multiple process members require a process-group identity.", nameof(processGroupId));
        if (processGroupId == Guid.Empty)
            throw new ArgumentException("Process-group identity cannot be empty.", nameof(processGroupId));
        Version = version;
        ProcessIdentity = processIdentity;
        ApplicationIdentity = canonicalApplicationIdentity;
        ProcessGroupId = processGroupId;
        GroupMembers = members;
    }

    private static int CompareProcessIdentity(ProcessIdentity left, ProcessIdentity right)
    {
        var pid = left.ProcessId.CompareTo(right.ProcessId);
        return pid != 0 ? pid : left.StartTime.UtcTicks.CompareTo(right.StartTime.UtcTicks);
    }

    public bool Matches(GateSubject other) =>
        other is not null
        && Version == other.Version
        && ProcessIdentity == other.ProcessIdentity
        && string.Equals(ApplicationIdentity, other.ApplicationIdentity, StringComparison.Ordinal)
        && ProcessGroupId == other.ProcessGroupId
        && GroupMembers.SequenceEqual(other.GroupMembers);
}

public enum DomainEvidenceProvenance
{
    None,
    DnsObservation,
    PlatformAuthoritative,
    CryptographicBinding
}

public enum NetworkTrafficDirection
{
    Unspecified,
    Outbound,
    Inbound
}

public sealed record DestinationBinding
{
    public int Version { get; }
    public IPAddress Address { get; }
    public IpVersion IpVersion { get; }
    public int RemotePort { get; }
    public TransportProtocol Protocol { get; }
    public NetworkTrafficDirection Direction { get; }
    public uint? NetworkCompartmentId { get; }
    public ulong? InterfaceLuid { get; }
    public string? DomainEvidence { get; }
    public DomainEvidenceProvenance DomainProvenance { get; }
    public DateTimeOffset? DomainObservedAtUtc { get; }

    public DestinationBinding(int version, IPAddress address, IpVersion ipVersion, int remotePort, TransportProtocol protocol, NetworkTrafficDirection direction, uint? networkCompartmentId, ulong? interfaceLuid, string? domainEvidence, DomainEvidenceProvenance domainProvenance, DateTimeOffset? domainObservedAtUtc)
    {
        OutboundGateLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(address);
        if (address.IsIPv4MappedToIPv6)
            throw new ArgumentException("IPv4-mapped IPv6 addresses must be normalized before binding.", nameof(address));
        if (!Enum.IsDefined(ipVersion) || !Enum.IsDefined(protocol)
            || remotePort is < 1 or > 65535
            || (ipVersion == IpVersion.IPv4 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork)
            || (ipVersion == IpVersion.IPv6 && address.AddressFamily != System.Net.Sockets.AddressFamily.InterNetworkV6))
            throw new ArgumentOutOfRangeException(nameof(remotePort), "Destination address family and port must be valid.");
        if (!Enum.IsDefined(direction) || direction != NetworkTrafficDirection.Outbound)
            throw new ArgumentOutOfRangeException(nameof(direction), direction, "Only outbound destination bindings are supported.");
        if (networkCompartmentId == 0)
            throw new ArgumentOutOfRangeException(nameof(networkCompartmentId), "Network compartment evidence cannot be zero when present.");
        if (interfaceLuid == 0)
            throw new ArgumentOutOfRangeException(nameof(interfaceLuid), "Interface LUID evidence cannot be zero when present.");
        if (!Enum.IsDefined(domainProvenance))
            throw new ArgumentOutOfRangeException(nameof(domainProvenance));
        if ((domainEvidence is null && (domainProvenance != DomainEvidenceProvenance.None || domainObservedAtUtc is not null))
            || (domainEvidence is not null && (domainProvenance == DomainEvidenceProvenance.None || domainObservedAtUtc is null)))
            throw new ArgumentException("Domain evidence requires both provenance and observation time; absent evidence requires neither.", nameof(domainEvidence));
        Version = version;
        Address = address;
        IpVersion = ipVersion;
        RemotePort = remotePort;
        Protocol = protocol;
        Direction = direction;
        NetworkCompartmentId = networkCompartmentId;
        InterfaceLuid = interfaceLuid;
        DomainEvidence = OutboundGateLimits.Optional(domainEvidence, nameof(domainEvidence), OutboundGateLimits.MaximumDomainLength);
        DomainProvenance = domainProvenance;
        DomainObservedAtUtc = domainObservedAtUtc is null ? null : OutboundGateLimits.Utc(domainObservedAtUtc.Value, nameof(domainObservedAtUtc));
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
    public ServiceMonotonicTimeRange ReadWindow { get; }
    public Guid BootInstance { get; }
    public long Sequence { get; }

    public FileReadIntent(int version, Guid intentId, GateSubject subject, FileVersionIdentity file, FileActivityOperation operation, DateTimeOffset observedAtUtc, ServiceMonotonicTimeRange readWindow, Guid bootInstance, long sequence)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(readWindow);
        readWindow.ValidateMaximum(OutboundGateLimits.MaximumGateArmReadDuration, nameof(readWindow));
        if (operation is not (FileActivityOperation.Read or FileActivityOperation.OpenCreate) || sequence <= 0)
            throw new ArgumentOutOfRangeException(nameof(operation), "Read intent operation and sequence must be valid.");
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        Version = version;
        IntentId = intentId;
        Subject = subject;
        File = file;
        Operation = operation;
        ObservedAtUtc = OutboundGateLimits.Utc(observedAtUtc, nameof(observedAtUtc));
        ReadWindow = readWindow;
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
    public DateTimeOffset RequestedAtUtc { get; }
    public ServiceMonotonicTimeRange ArmWindow { get; }

    public GateArmRequest(int version, Guid intentId, GateSubject subject, GateCoverage requiredCoverage, long policyEpoch, Guid driverGeneration, Guid requestNonce, DateTimeOffset requestedAtUtc, ServiceMonotonicTimeRange armWindow)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(requiredCoverage);
        ArgumentNullException.ThrowIfNull(armWindow);
        armWindow.ValidateMaximum(OutboundGateLimits.MaximumGateArmReadDuration, nameof(armWindow));
        if (requiredCoverage.Flags == GateCoverageFlags.None || policyEpoch < 0)
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
        RequestedAtUtc = OutboundGateLimits.Utc(requestedAtUtc, nameof(requestedAtUtc));
        ArmWindow = armWindow;
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
    public DateTimeOffset EndpointAcknowledgedAtUtc { get; }
    public ServiceMonotonicTimeRange ArmWindow { get; }
    public string? UnsupportedOrDegradedReason { get; }

    public GateArmAck(int version, Guid ackId, Guid intentId, GateSubject subject, GateCoverage requiredCoverage, GateCoverage armedCoverage, long policyEpoch, Guid driverGeneration, Guid requestNonce, Guid ackNonce, DateTimeOffset endpointAcknowledgedAtUtc, ServiceMonotonicTimeRange armWindow, string? unsupportedOrDegradedReason)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(ackId, nameof(ackId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(requiredCoverage);
        ArgumentNullException.ThrowIfNull(armedCoverage);
        ArgumentNullException.ThrowIfNull(armWindow);
        armWindow.ValidateMaximum(OutboundGateLimits.MaximumGateArmReadDuration, nameof(armWindow));
        if (requiredCoverage.Flags == GateCoverageFlags.None)
            throw new ArgumentOutOfRangeException(nameof(requiredCoverage));
        OutboundGateLimits.GuidValue(driverGeneration, nameof(driverGeneration));
        OutboundGateLimits.GuidValue(requestNonce, nameof(requestNonce));
        OutboundGateLimits.GuidValue(ackNonce, nameof(ackNonce));
        ArgumentOutOfRangeException.ThrowIfNegative(policyEpoch);
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
        EndpointAcknowledgedAtUtc = OutboundGateLimits.Utc(endpointAcknowledgedAtUtc, nameof(endpointAcknowledgedAtUtc));
        ArmWindow = armWindow;
        UnsupportedOrDegradedReason = OutboundGateLimits.Optional(unsupportedOrDegradedReason, nameof(unsupportedOrDegradedReason), OutboundGateLimits.MaximumReasonLength);
    }

    public bool HasFullCoverageFor(GateArmRequest request, ServiceMonotonicTimestamp serviceReceivedAt) =>
        request is not null
        && serviceReceivedAt is not null
        && IntentId == request.IntentId
        && Subject.Matches(request.Subject)
        && RequiredCoverage.Version == request.RequiredCoverage.Version
        && RequiredCoverage.Flags == request.RequiredCoverage.Flags
        && PolicyEpoch == request.PolicyEpoch
        && DriverGeneration == request.DriverGeneration
        && RequestNonce == request.RequestNonce
        && ArmWindow == request.ArmWindow
        && request.ArmWindow.Contains(serviceReceivedAt)
        && ArmedCoverage.Contains(request.RequiredCoverage)
        && string.IsNullOrWhiteSpace(UnsupportedOrDegradedReason);

    public void ValidateFor(GateArmRequest request, ServiceMonotonicTimestamp serviceReceivedAt)
    {
        ArgumentNullException.ThrowIfNull(request);
        ArgumentNullException.ThrowIfNull(serviceReceivedAt);
        if (!HasFullCoverageFor(request, serviceReceivedAt))
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
    public ServiceMonotonicTimeRange ReadWindow { get; }
    public string ReasonCode { get; }
    public long Sequence { get; }

    public FileReadDisposition(int version, Guid intentId, ProcessIdentity processIdentity, FileVersionIdentity file, FileReadDispositionKind disposition, Guid? gateAckId, ServiceMonotonicTimeRange readWindow, string reasonCode, long sequence)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        OutboundGateLimits.Process(processIdentity);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(readWindow);
        readWindow.ValidateMaximum(OutboundGateLimits.MaximumGateArmReadDuration, nameof(readWindow));
        var validatedReasonCode = OutboundGateLimits.Required(reasonCode, nameof(reasonCode), OutboundGateLimits.MaximumReasonLength);
        OutboundGateLimits.NullableGuid(gateAckId, nameof(gateAckId));
        if (!Enum.IsDefined(disposition)
            || sequence <= 0
            || (disposition == FileReadDispositionKind.ReleaseAfterGateArmed && gateAckId is null)
            || (disposition != FileReadDispositionKind.ReleaseAfterGateArmed && gateAckId is not null))
            throw new ArgumentOutOfRangeException(nameof(disposition));
        Version = version;
        IntentId = intentId;
        ProcessIdentity = processIdentity;
        File = file;
        Disposition = disposition;
        GateAckId = gateAckId;
        ReadWindow = readWindow;
        ReasonCode = validatedReasonCode;
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
    public FileReadDispositionKind Disposition { get; }
    public Guid? GateAckId { get; }
    public FileReadCompletionResult Result { get; }
    public string ReasonCode { get; }
    public long MonotonicSequence { get; }
    public Guid MinifilterGeneration { get; }

    public FileReadCompletionAck(int version, Guid completionId, Guid intentId, ProcessIdentity processIdentity, FileVersionIdentity file, long dispositionSequence, FileReadDispositionKind disposition, Guid? gateAckId, FileReadCompletionResult result, string reasonCode, long monotonicSequence, Guid minifilterGeneration)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(completionId, nameof(completionId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        OutboundGateLimits.Process(processIdentity);
        ArgumentNullException.ThrowIfNull(file);
        var validatedReasonCode = OutboundGateLimits.Required(reasonCode, nameof(reasonCode), OutboundGateLimits.MaximumReasonLength);
        OutboundGateLimits.NullableGuid(gateAckId, nameof(gateAckId));
        OutboundGateLimits.GuidValue(minifilterGeneration, nameof(minifilterGeneration));
        if (!Enum.IsDefined(disposition) || !Enum.IsDefined(result)
            || dispositionSequence <= 0 || monotonicSequence <= 0
            || (disposition == FileReadDispositionKind.ReleaseAfterGateArmed && gateAckId is null)
            || (disposition != FileReadDispositionKind.ReleaseAfterGateArmed && gateAckId is not null))
            throw new ArgumentOutOfRangeException(nameof(dispositionSequence));
        Version = version;
        CompletionId = completionId;
        IntentId = intentId;
        ProcessIdentity = processIdentity;
        File = file;
        DispositionSequence = dispositionSequence;
        Disposition = disposition;
        GateAckId = gateAckId;
        Result = result;
        ReasonCode = validatedReasonCode;
        MonotonicSequence = monotonicSequence;
        MinifilterGeneration = minifilterGeneration;
    }

    public bool IsBoundTo(FileReadDisposition disposition, Guid minifilterGeneration) =>
        disposition is not null
        && minifilterGeneration != Guid.Empty
        && MinifilterGeneration == minifilterGeneration
        && IntentId == disposition.IntentId
        && ProcessIdentity == disposition.ProcessIdentity
        && File == disposition.File
        && DispositionSequence == disposition.Sequence
        && Disposition == disposition.Disposition
        && GateAckId == disposition.GateAckId;
}

public enum ChallengeAdmissionFailureKind
{
    Unspecified,
    HeldFlowCapacityExhausted
}

public sealed record ChallengeAdmissionFailure
{
    public int Version { get; }
    public Guid FailureId { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public Guid WfpGeneration { get; }
    public ChallengeAdmissionFailureKind FailureKind { get; }
    public ServiceMonotonicTimestamp ObservedAt { get; }

    public ChallengeAdmissionFailure(int version, Guid failureId, Guid intentId, GateSubject subject, Guid wfpGeneration, ChallengeAdmissionFailureKind failureKind, ServiceMonotonicTimestamp observedAt)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(failureId, nameof(failureId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        OutboundGateLimits.GuidValue(wfpGeneration, nameof(wfpGeneration));
        if (!Enum.IsDefined(failureKind) || failureKind != ChallengeAdmissionFailureKind.HeldFlowCapacityExhausted)
            throw new ArgumentOutOfRangeException(nameof(failureKind));
        ArgumentNullException.ThrowIfNull(observedAt);
        Version = version;
        FailureId = failureId;
        IntentId = intentId;
        Subject = subject;
        WfpGeneration = wfpGeneration;
        FailureKind = failureKind;
        ObservedAt = observedAt;
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
    public DateTimeOffset CreatedAtUtc { get; }
    public ServiceMonotonicTimeRange DecisionWindow { get; }
    public string? LimitationReason { get; }

    public NetworkGateChallenge(int version, Guid challengeId, Guid intentId, GateSubject subject, DestinationBinding destination, long flowGeneration, bool existingFlow, GateCoverage requiredCoverage, DateTimeOffset createdAtUtc, ServiceMonotonicTimeRange decisionWindow, string? limitationReason)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(challengeId, nameof(challengeId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(requiredCoverage);
        ArgumentNullException.ThrowIfNull(decisionWindow);
        decisionWindow.ValidateMaximum(OutboundGateLimits.MaximumDecisionHoldDuration, nameof(decisionWindow));
        if (requiredCoverage.Flags == GateCoverageFlags.None || flowGeneration <= 0)
            throw new ArgumentOutOfRangeException(nameof(flowGeneration));
        Version = version;
        ChallengeId = challengeId;
        IntentId = intentId;
        Subject = subject;
        Destination = destination;
        FlowGeneration = flowGeneration;
        ExistingFlow = existingFlow;
        RequiredCoverage = requiredCoverage;
        CreatedAtUtc = OutboundGateLimits.Utc(createdAtUtc, nameof(createdAtUtc));
        DecisionWindow = decisionWindow;
        LimitationReason = OutboundGateLimits.Optional(limitationReason, nameof(limitationReason), OutboundGateLimits.MaximumReasonLength);
    }
}

public enum UserDecisionKind
{
    AllowOnce,
    AlwaysAllow,
    Block
}

public enum PersistentAllowPolicyKind
{
    RememberFor30Days
}

public sealed record RequestedPersistentScope
{
    public int Version { get; }
    public PersistentAllowPolicyKind PolicyKind { get; }
    public FileVersionIdentity File { get; }
    public string ApplicationIdentity { get; }
    public DestinationBinding Destination { get; }

    public RequestedPersistentScope(int version, PersistentAllowPolicyKind policyKind, FileVersionIdentity file, string applicationIdentity, DestinationBinding destination)
    {
        OutboundGateLimits.RequireVersion(version);
        if (!Enum.IsDefined(policyKind) || policyKind != PersistentAllowPolicyKind.RememberFor30Days)
            throw new ArgumentOutOfRangeException(nameof(policyKind));
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(destination);
        Version = version;
        PolicyKind = policyKind;
        File = file;
        ApplicationIdentity = OutboundGateLimits.ApplicationIdentity(applicationIdentity, nameof(applicationIdentity));
        Destination = destination;
    }
}

public sealed record UserDecision
{
    public int Version { get; }
    public Guid DecisionId { get; }
    public Guid ChallengeId { get; }
    public UserDecisionKind Decision { get; }
    public RequestedPersistentScope? RequestedPersistentScope { get; }
    public DateTimeOffset UiTimestampUtc { get; }
    public string AuthenticatedCaller { get; }

    public UserDecision(int version, Guid decisionId, Guid challengeId, UserDecisionKind decision, RequestedPersistentScope? requestedPersistentScope, DateTimeOffset uiTimestampUtc, string authenticatedCaller)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(decisionId, nameof(decisionId));
        OutboundGateLimits.GuidValue(challengeId, nameof(challengeId));
        if (!Enum.IsDefined(decision))
            throw new ArgumentOutOfRangeException(nameof(decision));
        if ((decision == UserDecisionKind.AlwaysAllow) != (requestedPersistentScope is not null))
            throw new ArgumentException("AlwaysAllow requires the fixed RememberFor30Days scope; other decisions must not carry persistent scope.", nameof(requestedPersistentScope));
        Version = version;
        DecisionId = decisionId;
        ChallengeId = challengeId;
        Decision = decision;
        RequestedPersistentScope = requestedPersistentScope;
        UiTimestampUtc = OutboundGateLimits.Utc(uiTimestampUtc, nameof(uiTimestampUtc));
        AuthenticatedCaller = OutboundGateLimits.Required(authenticatedCaller, nameof(authenticatedCaller), OutboundGateLimits.MaximumIdentifierLength);
    }

    public void ValidatePersistentScopeFor(NetworkGateChallenge challenge, FileVersionIdentity file)
    {
        ArgumentNullException.ThrowIfNull(challenge);
        ArgumentNullException.ThrowIfNull(file);
        if (ChallengeId != challenge.ChallengeId)
            throw new InvalidOperationException("Decision is bound to a different challenge.");
        if (Decision != UserDecisionKind.AlwaysAllow)
            return;
        if (RequestedPersistentScope is null
            || RequestedPersistentScope.PolicyKind != PersistentAllowPolicyKind.RememberFor30Days
            || RequestedPersistentScope.File != file
            || !string.Equals(RequestedPersistentScope.ApplicationIdentity, challenge.Subject.ApplicationIdentity, StringComparison.Ordinal)
            || RequestedPersistentScope.Destination != challenge.Destination)
            throw new InvalidOperationException("AlwaysAllow scope does not exactly match the file version, application identity, destination and protocol under decision.");
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
    public ServiceMonotonicTimeRange ValidityWindow { get; }
    public long GrantMaxBytes { get; }
    public long GrantMaxDurationMilliseconds { get; }
    public IReadOnlyList<byte> AuthenticatorProof { get; }

    public OneTimeTicket(int version, Guid ticketId, Guid nonce, Guid intentId, GateSubject subject, FileVersionIdentity file, DestinationBinding destination, long flowGeneration, long policyEpoch, Guid bootInstance, DateTimeOffset issuedAtUtc, DateTimeOffset expiresAtUtc, ServiceMonotonicTimeRange validityWindow, long grantMaxBytes, long grantMaxDurationMilliseconds, IReadOnlyList<byte>? authenticatorProof)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(ticketId, nameof(ticketId));
        OutboundGateLimits.GuidValue(nonce, nameof(nonce));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(validityWindow);
        validityWindow.ValidateMaximum(OutboundGateLimits.MaximumTicketValidity, nameof(validityWindow));
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        var issued = OutboundGateLimits.Utc(issuedAtUtc, nameof(issuedAtUtc));
        var expires = OutboundGateLimits.Utc(expiresAtUtc, nameof(expiresAtUtc));
        if (flowGeneration <= 0 || policyEpoch < 0
            || expires <= issued || expires - issued > OutboundGateLimits.MaximumTicketValidity
            || grantMaxBytes is < 1 or > OutboundGateLimits.MaximumGrantBytes
            || grantMaxDurationMilliseconds < 1 || grantMaxDurationMilliseconds > OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds)
            throw new ArgumentOutOfRangeException(nameof(flowGeneration), "Ticket bindings, expiry and grant bounds are invalid.");
        var proof = OutboundGateLimits.CopyBounded(authenticatorProof, nameof(authenticatorProof), OutboundGateLimits.AuthenticatorProofBytes, requireAtLeastOne: true);
        if (proof.Count != OutboundGateLimits.AuthenticatorProofBytes)
            throw new ArgumentException($"Authenticator proof must be exactly {OutboundGateLimits.AuthenticatorProofBytes} bytes.", nameof(authenticatorProof));
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
        ValidityWindow = validityWindow;
        GrantMaxBytes = grantMaxBytes;
        GrantMaxDurationMilliseconds = grantMaxDurationMilliseconds;
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
    public ServiceMonotonicTimeRange GrantWindow { get; }

    public EphemeralFlowGrant(int version, Guid grantId, Guid ticketId, Guid intentId, GateSubject subject, DestinationBinding destination, long flowGeneration, long policyEpoch, Guid bootInstance, long maximumBytes, ServiceMonotonicTimeRange grantWindow)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(grantId, nameof(grantId));
        OutboundGateLimits.GuidValue(ticketId, nameof(ticketId));
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(destination);
        ArgumentNullException.ThrowIfNull(grantWindow);
        grantWindow.ValidateMaximum(OutboundGateLimits.MaximumGrantDuration, nameof(grantWindow));
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        if (flowGeneration <= 0 || policyEpoch < 0 || maximumBytes is < 1 or > OutboundGateLimits.MaximumGrantBytes)
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
        GrantWindow = grantWindow;
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

public enum GateAffectedScopeKind
{
    Intent,
    Subject,
    OutboundGateSubsystem
}

public sealed record GateAffectedScope
{
    public int Version { get; }
    public GateAffectedScopeKind Kind { get; }
    public Guid? IntentId { get; }
    public GateSubject? Subject { get; }

    public GateAffectedScope(int version, GateAffectedScopeKind kind, Guid? intentId, GateSubject? subject)
    {
        OutboundGateLimits.RequireVersion(version);
        if (!Enum.IsDefined(kind))
            throw new ArgumentOutOfRangeException(nameof(kind));
        OutboundGateLimits.NullableGuid(intentId, nameof(intentId));
        var valid = kind switch
        {
            GateAffectedScopeKind.Intent => intentId is not null && subject is not null,
            GateAffectedScopeKind.Subject => intentId is null && subject is not null,
            GateAffectedScopeKind.OutboundGateSubsystem => intentId is null && subject is null,
            _ => false
        };
        if (!valid)
            throw new ArgumentException("Affected-scope identifiers do not match the selected scope kind.", nameof(kind));
        Version = version;
        Kind = kind;
        IntentId = intentId;
        Subject = subject;
    }
}

public sealed record GateStatus
{
    public int Version { get; }
    public OutboundGateMode Mode { get; }
    public GateRuntimeState State { get; }
    public GateCoverage Coverage { get; }
    public string ReasonCode { get; }
    public GateAffectedScope AffectedScope { get; }
    public DateTimeOffset AuditTimeUtc { get; }
    public ServiceMonotonicTimestamp ServiceObservedAt { get; }
    public long DroppedCount { get; }
    public long OverflowCount { get; }
    public bool TrafficFailedOpen { get; }

    public GateStatus(int version, OutboundGateMode mode, GateRuntimeState state, GateCoverage coverage, string reasonCode, GateAffectedScope affectedScope, DateTimeOffset auditTimeUtc, ServiceMonotonicTimestamp serviceObservedAt, long droppedCount, long overflowCount, bool trafficFailedOpen)
    {
        OutboundGateLimits.RequireVersion(version);
        ArgumentNullException.ThrowIfNull(coverage);
        ArgumentNullException.ThrowIfNull(affectedScope);
        ArgumentNullException.ThrowIfNull(serviceObservedAt);
        if (!Enum.IsDefined(mode) || !Enum.IsDefined(state))
            throw new ArgumentOutOfRangeException(nameof(state));
        if ((state == GateRuntimeState.FailedOpen) != trafficFailedOpen)
            throw new ArgumentException("FailedOpen state and TrafficFailedOpen must agree.", nameof(trafficFailedOpen));
        var validatedReasonCode = OutboundGateLimits.Required(reasonCode, nameof(reasonCode), OutboundGateLimits.MaximumReasonLength);
        OutboundGateLimits.Counter(droppedCount, nameof(droppedCount));
        OutboundGateLimits.Counter(overflowCount, nameof(overflowCount));
        Version = version;
        Mode = mode;
        State = state;
        Coverage = coverage;
        ReasonCode = validatedReasonCode;
        AffectedScope = affectedScope;
        AuditTimeUtc = OutboundGateLimits.Utc(auditTimeUtc, nameof(auditTimeUtc));
        ServiceObservedAt = serviceObservedAt;
        DroppedCount = droppedCount;
        OverflowCount = overflowCount;
        TrafficFailedOpen = trafficFailedOpen;
    }
}

public sealed record CriticalAlert
{
    public int Version { get; }
    public Guid AlertId { get; }
    public string ReasonCode { get; }
    public GateAffectedScope AffectedScope { get; }
    public DateTimeOffset AuditTimeUtc { get; }
    public ServiceMonotonicTimestamp ServiceObservedAt { get; }
    public long DroppedCount { get; }
    public long OverflowCount { get; }
    public bool TrafficFailedOpen { get; }

    public CriticalAlert(int version, Guid alertId, string reasonCode, GateAffectedScope affectedScope, DateTimeOffset auditTimeUtc, ServiceMonotonicTimestamp serviceObservedAt, long droppedCount, long overflowCount, bool trafficFailedOpen)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(alertId, nameof(alertId));
        ArgumentNullException.ThrowIfNull(affectedScope);
        ArgumentNullException.ThrowIfNull(serviceObservedAt);
        var validatedReasonCode = OutboundGateLimits.Required(reasonCode, nameof(reasonCode), OutboundGateLimits.MaximumReasonLength);
        OutboundGateLimits.Counter(droppedCount, nameof(droppedCount));
        OutboundGateLimits.Counter(overflowCount, nameof(overflowCount));
        Version = version;
        AlertId = alertId;
        ReasonCode = validatedReasonCode;
        AffectedScope = affectedScope;
        AuditTimeUtc = OutboundGateLimits.Utc(auditTimeUtc, nameof(auditTimeUtc));
        ServiceObservedAt = serviceObservedAt;
        DroppedCount = droppedCount;
        OverflowCount = overflowCount;
        TrafficFailedOpen = trafficFailedOpen;
    }
}
