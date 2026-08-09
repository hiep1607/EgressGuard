using System.Net;

namespace EgressGuard.Core;

public readonly record struct ProcessIdentity(int ProcessId, DateTimeOffset StartTime);

public sealed record ProcessSnapshot(
    ProcessIdentity Identity,
    string Name,
    string? ExecutablePath,
    int? ParentProcessId,
    ExecutableMetadata? ExecutableMetadata);

public sealed record ExecutableMetadata(
    string Sha256,
    SignatureVerificationStatus SignatureStatus,
    string? Publisher,
    long FileSize,
    DateTimeOffset LastWriteTime);

public enum TransportProtocol
{
    Tcp,
    Udp
}

public enum IpVersion
{
    IPv4,
    IPv6
}

public sealed record NetworkEndpoint(IPAddress Address, int Port);

public sealed record NetworkConnection(
    int ProcessId,
    TransportProtocol Protocol,
    IpVersion IpVersion,
    NetworkEndpoint LocalEndpoint,
    NetworkEndpoint? RemoteEndpoint,
    string? State,
    DateTimeOffset DetectedAt);

public sealed record ObservedConnection(
    NetworkConnection Connection,
    ProcessSnapshot? Process);

public sealed record ExecutableInfo(
    string Path,
    string Sha256,
    SignatureVerificationStatus SignatureStatus,
    string? Publisher,
    long FileSize,
    DateTimeOffset LastWriteTime,
    bool IsInTemp,
    bool IsInAppData);

public enum SignatureVerificationStatus
{
#pragma warning disable CA1720 // Protocol/storage value is deliberately named "Unsigned".
    Unsigned,
#pragma warning restore CA1720
    Valid,
    Invalid,
    Untrusted,
    Expired,
    Revoked,
    Unknown,
    VerificationUnavailable
}

public sealed record DestinationInfo(
    IPAddress Address,
    int Port,
    string? Domain,
    string DomainEvidence);

public sealed record NetworkFlow(
    string Id,
    ProcessIdentity? ProcessIdentity,
    string ProcessName,
    ExecutableInfo? Executable,
    int? ParentProcessId,
    TransportProtocol Protocol,
    IpVersion IpVersion,
    NetworkEndpoint LocalEndpoint,
    DestinationInfo? Destination,
    DateTimeOffset FirstSeen,
    DateTimeOffset LastSeen,
    string? State,
    long? BytesSent,
    long? BytesReceived,
    bool IsBlocked,
    RiskAssessment? Risk);

public enum RiskLevel
{
    Low,
    Medium,
    High,
    Critical
}

public enum PolicyDecision
{
    Allow,
    Ask,
    Block
}

public enum ProtectionMode
{
    Monitor,
    Learning,
    Protect
}

public sealed record RiskReason(
    string Code,
    string Message,
    int Points,
    string Evidence);

public sealed record RiskAssessment(
    int Score,
    RiskLevel Level,
    PolicyDecision Decision,
    IReadOnlyList<RiskReason> Reasons);

public enum FirewallAction
{
    Allow,
    Block
}

public enum RuleSource
{
    User,
    SystemSafety,
    Automatic
}

public sealed record FirewallRule(
    Guid Id,
    string Name,
    FirewallAction Action,
    RuleSource Source,
    string ExecutablePath,
    string? ExecutableSha256,
    string? RemoteAddress,
    int? RemotePort,
    TransportProtocol? Protocol,
    bool Enabled,
    DateTimeOffset CreatedAt,
    DateTimeOffset? LastMatchedAt);

public sealed record SecurityAlert(
    Guid Id,
    string FlowId,
    DateTimeOffset CreatedAt,
    string ProcessName,
    string Destination,
    RiskAssessment Assessment,
    Guid? RelatedRuleId,
    bool IsAcknowledged);
