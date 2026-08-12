using System.Buffers;
using System.Buffers.Binary;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace EgressGuard.Core;

public interface IOneTimeTicketAuthenticator : IDisposable
{
    Guid BootInstance { get; }
    int ProofSizeBytes { get; }
    byte[] CreateProof(ReadOnlySpan<byte> canonicalClaims);
    bool VerifyProof(ReadOnlySpan<byte> canonicalClaims, ReadOnlySpan<byte> presentedProof);
}

public interface IOneTimeTicketAuthenticatorFactory
{
    IOneTimeTicketAuthenticator CreateForBoot(Guid bootInstance);
}

public sealed class HmacSha256BootTicketAuthenticator : IOneTimeTicketAuthenticatorFactory, IOneTimeTicketAuthenticator
{
    private byte[]? _key;

    public HmacSha256BootTicketAuthenticator(Guid bootInstance)
        : this(bootInstance, CreateRandomKey())
    {
    }

    public HmacSha256BootTicketAuthenticator(Guid bootInstance, IReadOnlyList<byte> key)
    {
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        ArgumentNullException.ThrowIfNull(key);
        if (key.Count != 32)
            throw new ArgumentException("The boot authenticator key must be 256 bits.", nameof(key));

        BootInstance = bootInstance;
        _key = key.ToArray();
    }

    public Guid BootInstance { get; }
    public int ProofSizeBytes => OutboundGateLimits.AuthenticatorProofBytes;

    public byte[] CreateProof(ReadOnlySpan<byte> canonicalClaims)
    {
        var key = _key ?? throw new ObjectDisposedException(nameof(HmacSha256BootTicketAuthenticator));
        return HMACSHA256.HashData(key, canonicalClaims);
    }

    public bool VerifyProof(ReadOnlySpan<byte> canonicalClaims, ReadOnlySpan<byte> presentedProof)
    {
        if (presentedProof.Length != ProofSizeBytes)
            return false;
        var expected = CreateProof(canonicalClaims);
        return CryptographicOperations.FixedTimeEquals(expected, presentedProof);
    }

    public IOneTimeTicketAuthenticator CreateForBoot(Guid bootInstance) => new HmacSha256BootTicketAuthenticator(bootInstance);

    public void Dispose()
    {
        if (_key is not null)
        {
            CryptographicOperations.ZeroMemory(_key);
            _key = null;
        }
    }

    private static byte[] CreateRandomKey()
    {
        var key = new byte[32];
        RandomNumberGenerator.Fill(key);
        return key;
    }
}

/// <summary>Deterministic HMAC authenticator intended only for simulation tests.</summary>
public sealed class DeterministicTestTicketAuthenticator : IOneTimeTicketAuthenticator
{
    private readonly HmacSha256BootTicketAuthenticator _inner;

    public DeterministicTestTicketAuthenticator(Guid bootInstance, IReadOnlyList<byte>? key = null)
    {
        var fixtureKey = key?.ToArray() ?? Enumerable.Range(1, 32).Select(value => (byte)value).ToArray();
        _inner = new HmacSha256BootTicketAuthenticator(bootInstance, fixtureKey);
    }

    public Guid BootInstance => _inner.BootInstance;
    public int ProofSizeBytes => _inner.ProofSizeBytes;
    public byte[] CreateProof(ReadOnlySpan<byte> canonicalClaims) => _inner.CreateProof(canonicalClaims);
    public bool VerifyProof(ReadOnlySpan<byte> canonicalClaims, ReadOnlySpan<byte> presentedProof) => _inner.VerifyProof(canonicalClaims, presentedProof);
    public void Dispose() => _inner.Dispose();
}

public sealed record TicketAuthorizationBinding
{
    public int Version { get; }
    public Guid IntentId { get; }
    public GateSubject Subject { get; }
    public FileVersionIdentity File { get; }
    public DestinationBinding Destination { get; }
    public long FlowGeneration { get; }
    public Guid BootInstance { get; }
    public long PolicyEpoch { get; }
    public long GrantMaximumBytes { get; }
    public long GrantMaximumDurationMilliseconds { get; }

    public TicketAuthorizationBinding(int version, Guid intentId, GateSubject subject, FileVersionIdentity file, DestinationBinding destination, long flowGeneration, Guid bootInstance, long policyEpoch, long grantMaximumBytes, long grantMaximumDurationMilliseconds)
    {
        OutboundGateLimits.RequireVersion(version);
        OutboundGateLimits.GuidValue(intentId, nameof(intentId));
        ArgumentNullException.ThrowIfNull(subject);
        ArgumentNullException.ThrowIfNull(file);
        ArgumentNullException.ThrowIfNull(destination);
        OutboundGateLimits.GuidValue(bootInstance, nameof(bootInstance));
        if (flowGeneration <= 0 || policyEpoch < 0 || grantMaximumBytes is < 1 or > OutboundGateLimits.MaximumGrantBytes
            || grantMaximumDurationMilliseconds < 1 || grantMaximumDurationMilliseconds > (long)OutboundGateLimits.MaximumGrantDuration.TotalMilliseconds)
            throw new ArgumentOutOfRangeException(nameof(flowGeneration));

        Version = version;
        IntentId = intentId;
        Subject = subject;
        File = file;
        Destination = destination;
        FlowGeneration = flowGeneration;
        BootInstance = bootInstance;
        PolicyEpoch = policyEpoch;
        GrantMaximumBytes = grantMaximumBytes;
        GrantMaximumDurationMilliseconds = grantMaximumDurationMilliseconds;
    }

    public bool Matches(OneTimeTicket ticket) =>
        ticket is not null
        && Version == ticket.Version
        && IntentId == ticket.IntentId
        && Subject.Matches(ticket.Subject)
        && File == ticket.File
        && Destination == ticket.Destination
        && FlowGeneration == ticket.FlowGeneration
        && BootInstance == ticket.BootInstance
        && PolicyEpoch == ticket.PolicyEpoch
        && GrantMaximumBytes == ticket.GrantMaxBytes
        && GrantMaximumDurationMilliseconds == ticket.GrantMaxDurationMilliseconds;
}

public enum TicketServiceResultKind
{
    Success,
    Rejected,
    FailOpenCritical
}

public sealed record TicketIssueResult(TicketServiceResultKind Kind, string ReasonCode, OneTimeTicket? Ticket, bool CapacityFailure = false);

public sealed record TicketRedemptionResult(TicketServiceResultKind Kind, string ReasonCode, bool TicketConsumed, EphemeralFlowGrant? Grant);

public sealed record TicketPruneResult(int OutstandingRemoved, int TombstonesRemoved);

public sealed record TicketInvalidationResult(int OutstandingInvalidated, int TombstonesRetained);

public sealed record TicketServiceSnapshot(
    int OutstandingGlobal,
    int SubjectsWithOutstandingTickets,
    int ReplayTombstones,
    int ReservedTombstones,
    int OutstandingGlobalCapacity,
    int ReplayTombstoneCapacity,
    int ActiveGrantReservations,
    int ActiveGrantReservationCapacity);

internal interface IEphemeralFlowGrantFactory
{
    bool TryCreate(TicketGrantParameters parameters, out EphemeralFlowGrant? grant);
}

internal sealed record TicketGrantParameters(
    OneTimeTicket Ticket,
    ServiceMonotonicTimestamp Now,
    Guid GrantId);

internal sealed class DefaultEphemeralFlowGrantFactory : IEphemeralFlowGrantFactory
{
    public bool TryCreate(TicketGrantParameters parameters, out EphemeralFlowGrant? grant)
    {
        try
        {
            var deadline = new ServiceMonotonicTimestamp(
                parameters.Now.Version,
                parameters.Now.ClockInstanceId,
                checked(parameters.Now.ElapsedMilliseconds + parameters.Ticket.GrantMaxDurationMilliseconds));
            grant = new EphemeralFlowGrant(
                parameters.Ticket.Version,
                parameters.GrantId,
                parameters.Ticket.TicketId,
                parameters.Ticket.IntentId,
                parameters.Ticket.Subject,
                parameters.Ticket.Destination,
                parameters.Ticket.FlowGeneration,
                parameters.Ticket.PolicyEpoch,
                parameters.Ticket.BootInstance,
                parameters.Ticket.GrantMaxBytes,
                new ServiceMonotonicTimeRange(parameters.Now.Version, parameters.Now, deadline));
            return true;
        }
        catch (Exception exception) when (exception is ArgumentException or OverflowException)
        {
            grant = null;
            return false;
        }
    }
}

public sealed class OneTimeGateTicketService : IDisposable
{
    public const int MaximumOutstandingPerSubject = 8;
    public const int MaximumOutstandingGlobal = 256;
    public const int MaximumReplayTombstonesGlobal = 2_048;
    public const int MaximumActiveGrantsGlobal = 256;

    private readonly object _sync = new();
    private readonly IOutboundGateMonotonicClock _monotonicClock;
    private readonly IOutboundGateAuditClock _auditClock;
    private readonly IOutboundGateNonceProvider _nonceProvider;
    private readonly IEphemeralFlowGrantFactory _grantFactory;
    private IOneTimeTicketAuthenticator _authenticator;
    private long _policyEpoch;
    private bool _disposed;
    private readonly Dictionary<Guid, OutstandingEntry> _outstanding = new();
    private readonly Dictionary<string, Tombstone> _tombstones = new(StringComparer.Ordinal);
    private readonly Dictionary<string, int> _subjectCounts = new(StringComparer.Ordinal);
    private readonly Dictionary<Guid, ServiceMonotonicTimestamp> _activeGrantIds = new();

    public OneTimeGateTicketService(IOutboundGateMonotonicClock monotonicClock, IOutboundGateAuditClock auditClock, IOutboundGateNonceProvider nonceProvider, IOneTimeTicketAuthenticator authenticator, long initialPolicyEpoch)
        : this(monotonicClock, auditClock, nonceProvider, authenticator, initialPolicyEpoch, null)
    {
    }

    internal OneTimeGateTicketService(IOutboundGateMonotonicClock monotonicClock, IOutboundGateAuditClock auditClock, IOutboundGateNonceProvider nonceProvider, IOneTimeTicketAuthenticator authenticator, long initialPolicyEpoch, IEphemeralFlowGrantFactory? grantFactory)
    {
        _monotonicClock = monotonicClock ?? throw new ArgumentNullException(nameof(monotonicClock));
        _auditClock = auditClock ?? throw new ArgumentNullException(nameof(auditClock));
        _nonceProvider = nonceProvider ?? throw new ArgumentNullException(nameof(nonceProvider));
        _authenticator = authenticator ?? throw new ArgumentNullException(nameof(authenticator));
        if (_authenticator.ProofSizeBytes != OutboundGateLimits.AuthenticatorProofBytes)
            throw new ArgumentException("The authenticator must produce a 32-byte proof.", nameof(authenticator));
        ArgumentOutOfRangeException.ThrowIfNegative(initialPolicyEpoch);
        _policyEpoch = initialPolicyEpoch;
        _grantFactory = grantFactory ?? new DefaultEphemeralFlowGrantFactory();
    }

    public long PolicyEpoch => _policyEpoch;
    public Guid BootInstance => _authenticator.BootInstance;

    public TicketServiceSnapshot Snapshot
    {
        get
        {
            lock (_sync)
            {
                return new TicketServiceSnapshot(
                    _outstanding.Count,
                    _subjectCounts.Count,
                    _tombstones.Count,
                    _outstanding.Count,
                    MaximumOutstandingGlobal,
                    MaximumReplayTombstonesGlobal,
                    _activeGrantIds.Count,
                    MaximumActiveGrantsGlobal);
            }
        }
    }

    public TicketIssueResult TryIssue(TicketAuthorizationBinding binding)
    {
        ArgumentNullException.ThrowIfNull(binding);
        lock (_sync)
        {
            EnsureNotDisposed();
            var now = RequireClock();
            PruneExpiredCore(now);
            if (binding.BootInstance != _authenticator.BootInstance || binding.PolicyEpoch != _policyEpoch)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-runtime-invalid", null);

            var subjectKey = SubjectKey(binding.Subject);
            if (_outstanding.Count >= MaximumOutstandingGlobal)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-global-capacity-exhausted", null, true);
            if (_subjectCounts.TryGetValue(subjectKey, out var subjectCount) && subjectCount >= MaximumOutstandingPerSubject)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-subject-capacity-exhausted", null, true);
            if (_tombstones.Count + _outstanding.Count >= MaximumReplayTombstonesGlobal)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-tombstone-capacity-exhausted", null, true);
            if (_activeGrantIds.Count >= MaximumActiveGrantsGlobal)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-active-grant-capacity-exhausted", null, true);

            var ticketId = _nonceProvider.NextNonce();
            var nonce = _nonceProvider.NextNonce();
            if (ticketId == Guid.Empty || nonce == Guid.Empty || ticketId == nonce)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-identifier-unavailable", null);
            if (IdentifierInUse(ticketId) || IdentifierInUse(nonce))
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-identifier-collision", null, true);

            var validityWindow = new ServiceMonotonicTimeRange(
                now.Version,
                now,
                new ServiceMonotonicTimestamp(now.Version, now.ClockInstanceId, checked(now.ElapsedMilliseconds + (long)OutboundGateLimits.MaximumTicketValidity.TotalMilliseconds)));
            var issuedAtUtc = RequireAuditUtc();
            var unsigned = new OneTimeTicket(
                binding.Version,
                ticketId,
                nonce,
                binding.IntentId,
                binding.Subject,
                binding.File,
                binding.Destination,
                binding.FlowGeneration,
                binding.PolicyEpoch,
                binding.BootInstance,
                issuedAtUtc,
                issuedAtUtc.Add(OutboundGateLimits.MaximumTicketValidity),
                validityWindow,
                binding.GrantMaximumBytes,
                binding.GrantMaximumDurationMilliseconds,
                new byte[OutboundGateLimits.AuthenticatorProofBytes]);
            byte[] proof;
            try
            {
                proof = _authenticator.CreateProof(CanonicalTicketEncoding.Encode(unsigned));
            }
            catch (Exception exception) when (exception is CryptographicException or ObjectDisposedException)
            {
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-authenticator-unavailable", null);
            }
            if (proof.Length != OutboundGateLimits.AuthenticatorProofBytes)
                return new TicketIssueResult(TicketServiceResultKind.FailOpenCritical, "ticket-authenticator-unavailable", null);
            var ticket = new OneTimeTicket(
                unsigned.Version,
                unsigned.TicketId,
                unsigned.Nonce,
                unsigned.IntentId,
                unsigned.Subject,
                unsigned.File,
                unsigned.Destination,
                unsigned.FlowGeneration,
                unsigned.PolicyEpoch,
                unsigned.BootInstance,
                unsigned.IssuedAtUtc,
                unsigned.ExpiresAtUtc,
                unsigned.ValidityWindow,
                unsigned.GrantMaxBytes,
                unsigned.GrantMaxDurationMilliseconds,
                proof);

            var entry = new OutstandingEntry(ticket, subjectKey);
            _outstanding.Add(ticket.TicketId, entry);
            _subjectCounts[subjectKey] = subjectCount + 1;
            return new TicketIssueResult(TicketServiceResultKind.Success, "ticket-issued-simulation", ticket);
        }
    }

    public TicketRedemptionResult TryRedeem(OneTimeTicket presentedTicket, TicketAuthorizationBinding currentBinding)
    {
        ArgumentNullException.ThrowIfNull(presentedTicket);
        ArgumentNullException.ThrowIfNull(currentBinding);
        lock (_sync)
        {
            EnsureNotDisposed();
            bool proofValid;
            try
            {
                proofValid = IsCanonicalProofValid(presentedTicket);
            }
            catch (Exception exception) when (exception is CryptographicException or ObjectDisposedException)
            {
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-authenticator-unavailable", false, null);
            }
            if (!proofValid)
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-proof-invalid", false, null);
            if (presentedTicket.BootInstance != _authenticator.BootInstance || currentBinding.BootInstance != _authenticator.BootInstance)
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-boot-instance-mismatch", false, null);
            if (!currentBinding.Matches(presentedTicket))
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-binding-mismatch", false, null);
            if (presentedTicket.PolicyEpoch != _policyEpoch || currentBinding.PolicyEpoch != _policyEpoch)
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-policy-epoch-mismatch", false, null);

            var now = RequireClock();
            PruneExpiredReservationsCore(now);
            if (!SameClock(now, presentedTicket.ValidityWindow.StartedAt))
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-clock-instance-mismatch", false, null);
            if (now.ElapsedMilliseconds < presentedTicket.ValidityWindow.StartedAt.ElapsedMilliseconds)
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-not-yet-valid", false, null);
            if (now.ElapsedMilliseconds >= presentedTicket.ValidityWindow.Deadline.ElapsedMilliseconds)
            {
                if (_outstanding.Remove(presentedTicket.TicketId, out var expired))
                    RemoveSubjectCount(expired.SubjectKey);
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-expired", false, null);
            }

            if (!_outstanding.TryGetValue(presentedTicket.TicketId, out var entry))
            {
                var fingerprint = ReplayFingerprint(presentedTicket);
                return new TicketRedemptionResult(_tombstones.ContainsKey(fingerprint) ? TicketServiceResultKind.Rejected : TicketServiceResultKind.Rejected, _tombstones.ContainsKey(fingerprint) ? "ticket-replay" : "ticket-not-outstanding", false, null);
            }
            if (!TicketEquals(entry.Ticket, presentedTicket))
                return new TicketRedemptionResult(TicketServiceResultKind.Rejected, "ticket-binding-mismatch", false, null);

            _outstanding.Remove(presentedTicket.TicketId);
            RemoveSubjectCount(entry.SubjectKey);
            var tombstoneKey = ReplayFingerprint(presentedTicket);
            if (_tombstones.Count >= MaximumReplayTombstonesGlobal)
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-reservation-invariant-failed", true, null);
            var identifierCollision = _tombstones.Values.Any(tombstone =>
                tombstone.TicketId == presentedTicket.TicketId
                || tombstone.Nonce == presentedTicket.TicketId
                || tombstone.TicketId == presentedTicket.Nonce
                || tombstone.Nonce == presentedTicket.Nonce);
            if (identifierCollision)
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-reservation-invariant-failed", true, null);
            _tombstones[tombstoneKey] = new Tombstone(presentedTicket.TicketId, presentedTicket.Nonce, presentedTicket.ValidityWindow.Deadline);

            if (_activeGrantIds.Count >= MaximumActiveGrantsGlobal)
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-active-grant-capacity-exhausted", true, null);
            var grantId = _nonceProvider.NextNonce();
            if (grantId == Guid.Empty || IdentifierInUse(grantId) || _activeGrantIds.ContainsKey(grantId))
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-grant-identifier-collision", true, null);
            var grantParameters = new TicketGrantParameters(presentedTicket, now, grantId);
            bool grantCreated;
            EphemeralFlowGrant? grant = null;
            try
            {
                grantCreated = grantParameters.GrantId != Guid.Empty && _grantFactory.TryCreate(grantParameters, out grant) && grant is not null;
            }
            catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or OverflowException)
            {
                grantCreated = false;
                grant = null;
            }
            if (!grantCreated)
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-grant-creation-failed", true, null);
            if (grant!.GrantId != grantId || grant.GrantId == presentedTicket.TicketId || grant.GrantId == presentedTicket.Nonce)
                return new TicketRedemptionResult(TicketServiceResultKind.FailOpenCritical, "ticket-grant-creation-failed", true, null);
            _activeGrantIds[grant.GrantId] = grant.GrantWindow.Deadline;
            return new TicketRedemptionResult(TicketServiceResultKind.Success, "ticket-redeemed-simulation", true, grant);
        }
    }

    public bool CancelOutstanding(Guid ticketId)
    {
        lock (_sync)
        {
            EnsureNotDisposed();
            if (!_outstanding.Remove(ticketId, out var entry))
                return false;
            RemoveSubjectCount(entry.SubjectKey);
            return true;
        }
    }

    public TicketPruneResult PruneExpired()
    {
        lock (_sync)
        {
            EnsureNotDisposed();
            var now = RequireClock();
            return PruneExpiredCore(now);
        }
    }

    public TicketInvalidationResult ApplyPolicyEpoch(long newPolicyEpoch)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(newPolicyEpoch);
        lock (_sync)
        {
            EnsureNotDisposed();
            ArgumentOutOfRangeException.ThrowIfLessThan(newPolicyEpoch, _policyEpoch, nameof(newPolicyEpoch));
            if (newPolicyEpoch == _policyEpoch)
                return new TicketInvalidationResult(0, _tombstones.Count);
            _policyEpoch = newPolicyEpoch;
            var invalidated = 0;
            foreach (var entry in _outstanding.Values.Where(entry => entry.Ticket.PolicyEpoch != newPolicyEpoch).ToArray())
            {
                _outstanding.Remove(entry.Ticket.TicketId);
                RemoveSubjectCount(entry.SubjectKey);
                invalidated++;
            }
            _activeGrantIds.Clear();
            return new TicketInvalidationResult(invalidated, _tombstones.Count);
        }
    }

    public TicketInvalidationResult ResetRuntime(Guid newBootInstance, long newPolicyEpoch, IOneTimeTicketAuthenticator newAuthenticator)
    {
        OutboundGateLimits.GuidValue(newBootInstance, nameof(newBootInstance));
        ArgumentNullException.ThrowIfNull(newAuthenticator);
        if (newAuthenticator.BootInstance != newBootInstance)
            throw new ArgumentException("Authenticator boot instance does not match the runtime boot instance.", nameof(newAuthenticator));
        ArgumentOutOfRangeException.ThrowIfNegative(newPolicyEpoch);
        lock (_sync)
        {
            EnsureNotDisposed();
            var invalidated = _outstanding.Count;
            _outstanding.Clear();
            _subjectCounts.Clear();
            _tombstones.Clear();
            _activeGrantIds.Clear();
            _policyEpoch = newPolicyEpoch;
            var old = _authenticator;
            _authenticator = newAuthenticator;
            old.Dispose();
            return new TicketInvalidationResult(invalidated, 0);
        }
    }

    public void Dispose()
    {
        lock (_sync)
        {
            if (_disposed)
                return;
            _disposed = true;
            _outstanding.Clear();
            _subjectCounts.Clear();
            _tombstones.Clear();
            _activeGrantIds.Clear();
            _authenticator.Dispose();
        }
    }

    private TicketPruneResult PruneExpiredCore(ServiceMonotonicTimestamp now)
    {
        var outstandingRemoved = 0;
        foreach (var entry in _outstanding.Values.Where(entry => !SameClock(now, entry.Ticket.ValidityWindow.Deadline) || now.ElapsedMilliseconds >= entry.Ticket.ValidityWindow.Deadline.ElapsedMilliseconds).ToArray())
        {
            _outstanding.Remove(entry.Ticket.TicketId);
            RemoveSubjectCount(entry.SubjectKey);
            outstandingRemoved++;
        }
        var tombstonesRemoved = PruneExpiredReservationsCore(now);
        return new TicketPruneResult(outstandingRemoved, tombstonesRemoved);
    }

    private int PruneExpiredReservationsCore(ServiceMonotonicTimestamp now)
    {
        var tombstonesRemoved = 0;
        foreach (var item in _tombstones.Where(item => SameClock(now, item.Value.SafeUntil) && now.ElapsedMilliseconds >= item.Value.SafeUntil.ElapsedMilliseconds).ToArray())
        {
            _tombstones.Remove(item.Key);
            tombstonesRemoved++;
        }
        foreach (var item in _activeGrantIds.Where(item => SameClock(now, item.Value) && now.ElapsedMilliseconds >= item.Value.ElapsedMilliseconds).ToArray())
            _activeGrantIds.Remove(item.Key);
        return tombstonesRemoved;
    }

    private bool IsCanonicalProofValid(OneTimeTicket ticket)
    {
        if (ticket.AuthenticatorProof.Count != OutboundGateLimits.AuthenticatorProofBytes)
            return false;
        return _authenticator.VerifyProof(CanonicalTicketEncoding.Encode(ticket), ticket.AuthenticatorProof.ToArray());
    }

    private ServiceMonotonicTimestamp RequireClock() => _monotonicClock.Now() ?? throw new InvalidOperationException("Monotonic clock returned null.");

    private DateTimeOffset RequireAuditUtc()
    {
        var value = _auditClock.NowUtc();
        if (value == default)
            throw new InvalidOperationException("Audit clock returned the default timestamp.");
        return value.ToUniversalTime();
    }

    private void RemoveSubjectCount(string key)
    {
        if (!_subjectCounts.TryGetValue(key, out var count))
            return;
        if (count <= 1)
            _subjectCounts.Remove(key);
        else
            _subjectCounts[key] = count - 1;
    }

    private void EnsureNotDisposed()
    {
        if (_disposed)
            ObjectDisposedException.ThrowIf(_disposed, typeof(OneTimeGateTicketService));
    }

    private static bool SameClock(ServiceMonotonicTimestamp left, ServiceMonotonicTimestamp right) =>
        left.Version == right.Version && left.ClockInstanceId == right.ClockInstanceId;

    private bool IdentifierInUse(Guid candidate) =>
        _activeGrantIds.ContainsKey(candidate)
        || _outstanding.Values.Any(entry => entry.Ticket.TicketId == candidate || entry.Ticket.Nonce == candidate)
        || _tombstones.Values.Any(tombstone => tombstone.TicketId == candidate || tombstone.Nonce == candidate);

    private static string SubjectKey(GateSubject subject) => Convert.ToHexString(SHA256.HashData(CanonicalTicketEncoding.EncodeSubject(subject)));

    private static string ReplayFingerprint(OneTimeTicket ticket)
    {
        var writer = new ArrayBufferWriter<byte>();
        CanonicalTicketEncoding.WriteAscii(writer, "EgressGuard/OneTimeGateTicket/replay/v1");
        CanonicalTicketEncoding.WriteGuid(writer, ticket.TicketId);
        CanonicalTicketEncoding.WriteGuid(writer, ticket.Nonce);
        return Convert.ToHexString(SHA256.HashData(writer.WrittenSpan));
    }

    private static bool TicketEquals(OneTimeTicket left, OneTimeTicket right) =>
        left.Version == right.Version
        && left.TicketId == right.TicketId
        && left.Nonce == right.Nonce
        && left.IntentId == right.IntentId
        && left.Subject.Matches(right.Subject)
        && left.File == right.File
        && left.Destination == right.Destination
        && left.FlowGeneration == right.FlowGeneration
        && left.PolicyEpoch == right.PolicyEpoch
        && left.BootInstance == right.BootInstance
        && left.IssuedAtUtc == right.IssuedAtUtc
        && left.ExpiresAtUtc == right.ExpiresAtUtc
        && left.ValidityWindow == right.ValidityWindow
        && left.GrantMaxBytes == right.GrantMaxBytes
        && left.GrantMaxDurationMilliseconds == right.GrantMaxDurationMilliseconds
        && CryptographicOperations.FixedTimeEquals(left.AuthenticatorProof.ToArray(), right.AuthenticatorProof.ToArray());

    private sealed record OutstandingEntry(OneTimeTicket Ticket, string SubjectKey);
    private sealed record Tombstone(Guid TicketId, Guid Nonce, ServiceMonotonicTimestamp SafeUntil);
}

internal static class CanonicalTicketEncoding
{
    private static readonly Encoding Utf8 = new UTF8Encoding(false, true);

    public static byte[] Encode(OneTimeTicket ticket)
    {
        var writer = new ArrayBufferWriter<byte>();
        WriteAscii(writer, "EgressGuard/OneTimeGateTicket/HMAC-SHA256/v1");
        WriteInt32(writer, ticket.Version);
        WriteGuid(writer, ticket.TicketId);
        WriteGuid(writer, ticket.Nonce);
        WriteGuid(writer, ticket.IntentId);
        WriteSubject(writer, ticket.Subject);
        WriteFile(writer, ticket.File);
        WriteDestination(writer, ticket.Destination);
        WriteInt64(writer, ticket.FlowGeneration);
        WriteInt64(writer, ticket.PolicyEpoch);
        WriteGuid(writer, ticket.BootInstance);
        WriteDateTime(writer, ticket.IssuedAtUtc);
        WriteDateTime(writer, ticket.ExpiresAtUtc);
        WriteRange(writer, ticket.ValidityWindow);
        WriteInt64(writer, ticket.GrantMaxBytes);
        WriteInt64(writer, ticket.GrantMaxDurationMilliseconds);
        return writer.WrittenSpan.ToArray();
    }

    public static byte[] EncodeSubject(GateSubject subject)
    {
        var writer = new ArrayBufferWriter<byte>();
        WriteAscii(writer, "EgressGuard/OneTimeGateTicket/subject/v1");
        WriteSubject(writer, subject);
        return writer.WrittenSpan.ToArray();
    }

    public static void WriteAscii(ArrayBufferWriter<byte> writer, string value) => WriteBytes(writer, Encoding.ASCII.GetBytes(value));

    public static void WriteGuid(ArrayBufferWriter<byte> writer, Guid value)
    {
        Span<byte> raw = stackalloc byte[16];
        value.TryWriteBytes(raw);
        Span<byte> output = writer.GetSpan(16);
        BinaryPrimitives.WriteUInt32BigEndian(output[0..4], BinaryPrimitives.ReadUInt32LittleEndian(raw[0..4]));
        BinaryPrimitives.WriteUInt16BigEndian(output[4..6], BinaryPrimitives.ReadUInt16LittleEndian(raw[4..6]));
        BinaryPrimitives.WriteUInt16BigEndian(output[6..8], BinaryPrimitives.ReadUInt16LittleEndian(raw[6..8]));
        raw[8..].CopyTo(output[8..16]);
        writer.Advance(16);
    }

    private static void WriteSubject(ArrayBufferWriter<byte> writer, GateSubject subject)
    {
        WriteInt32(writer, subject.Version);
        WriteProcess(writer, subject.ProcessIdentity);
        WriteString(writer, subject.ApplicationIdentity);
        WriteNullableGuid(writer, subject.ProcessGroupId);
        WriteInt32(writer, subject.GroupMembers.Count);
        foreach (var member in subject.GroupMembers)
            WriteProcess(writer, member);
    }

    private static void WriteProcess(ArrayBufferWriter<byte> writer, ProcessIdentity process)
    {
        WriteInt32(writer, process.ProcessId);
        WriteDateTime(writer, process.StartTime);
    }

    private static void WriteFile(ArrayBufferWriter<byte> writer, FileVersionIdentity file)
    {
        WriteInt32(writer, file.Version);
        WriteString(writer, file.VolumeId);
        WriteString(writer, file.FileId);
        WriteDateTime(writer, file.CreationTimeUtc);
        WriteInt64(writer, file.SizeBytes);
        WriteDateTime(writer, file.LastWriteTimeUtc);
        WriteDateTime(writer, file.ChangeTimeUtc);
        WriteNullableInt64(writer, file.Usn);
        WriteString(writer, file.VersionToken);
    }

    private static void WriteDestination(ArrayBufferWriter<byte> writer, DestinationBinding destination)
    {
        WriteInt32(writer, destination.Version);
        var address = destination.Address.IsIPv4MappedToIPv6 ? destination.Address.MapToIPv4() : destination.Address;
        WriteInt32(writer, (int)destination.IpVersion);
        WriteBytes(writer, address.GetAddressBytes());
        WriteInt32(writer, destination.RemotePort);
        WriteInt32(writer, (int)destination.Protocol);
        WriteInt32(writer, (int)destination.Direction);
        WriteNullableUInt32(writer, destination.NetworkCompartmentId);
        WriteNullableUInt64(writer, destination.InterfaceLuid);
        WriteNullableString(writer, destination.DomainEvidence);
        WriteInt32(writer, (int)destination.DomainProvenance);
        WriteNullableDateTime(writer, destination.DomainObservedAtUtc);
    }

    private static void WriteRange(ArrayBufferWriter<byte> writer, ServiceMonotonicTimeRange range)
    {
        WriteInt32(writer, range.Version);
        WriteTimestamp(writer, range.StartedAt);
        WriteTimestamp(writer, range.Deadline);
    }

    private static void WriteTimestamp(ArrayBufferWriter<byte> writer, ServiceMonotonicTimestamp timestamp)
    {
        WriteInt32(writer, timestamp.Version);
        WriteGuid(writer, timestamp.ClockInstanceId);
        WriteInt64(writer, timestamp.ElapsedMilliseconds);
    }

    private static void WriteDateTime(ArrayBufferWriter<byte> writer, DateTimeOffset value) => WriteInt64(writer, value.UtcDateTime.Ticks);
    private static void WriteNullableDateTime(ArrayBufferWriter<byte> writer, DateTimeOffset? value) { WriteBool(writer, value is not null); if (value is not null) WriteDateTime(writer, value.Value); }
    private static void WriteNullableGuid(ArrayBufferWriter<byte> writer, Guid? value) { WriteBool(writer, value is not null); if (value is not null) WriteGuid(writer, value.Value); }
    private static void WriteNullableInt64(ArrayBufferWriter<byte> writer, long? value) { WriteBool(writer, value is not null); if (value is not null) WriteInt64(writer, value.Value); }
    private static void WriteNullableUInt32(ArrayBufferWriter<byte> writer, uint? value) { WriteBool(writer, value is not null); if (value is not null) WriteUInt32(writer, value.Value); }
    private static void WriteNullableUInt64(ArrayBufferWriter<byte> writer, ulong? value) { WriteBool(writer, value is not null); if (value is not null) WriteUInt64(writer, value.Value); }
    private static void WriteNullableString(ArrayBufferWriter<byte> writer, string? value) { WriteBool(writer, value is not null); if (value is not null) WriteString(writer, value); }
    private static void WriteBool(ArrayBufferWriter<byte> writer, bool value) { var span = writer.GetSpan(1); span[0] = value ? (byte)1 : (byte)0; writer.Advance(1); }
    private static void WriteInt32(ArrayBufferWriter<byte> writer, int value) { var span = writer.GetSpan(4); BinaryPrimitives.WriteInt32BigEndian(span, value); writer.Advance(4); }
    private static void WriteUInt32(ArrayBufferWriter<byte> writer, uint value) { var span = writer.GetSpan(4); BinaryPrimitives.WriteUInt32BigEndian(span, value); writer.Advance(4); }
    private static void WriteUInt64(ArrayBufferWriter<byte> writer, ulong value) { var span = writer.GetSpan(8); BinaryPrimitives.WriteUInt64BigEndian(span, value); writer.Advance(8); }
    private static void WriteInt64(ArrayBufferWriter<byte> writer, long value) { var span = writer.GetSpan(8); BinaryPrimitives.WriteInt64BigEndian(span, value); writer.Advance(8); }

    private static void WriteString(ArrayBufferWriter<byte> writer, string value)
    {
        var bytes = Utf8.GetBytes(value);
        WriteUInt32(writer, checked((uint)bytes.Length));
        WriteBytes(writer, bytes);
    }

    private static void WriteBytes(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> bytes)
    {
        bytes.CopyTo(writer.GetSpan(bytes.Length));
        writer.Advance(bytes.Length);
    }
}
