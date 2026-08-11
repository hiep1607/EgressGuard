using System.Diagnostics;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text.Json;
using Microsoft.Diagnostics.Tracing.Session;

namespace EgressGuard.Windows;

internal sealed record EtwSessionLease(string SessionName, Guid Nonce, int OwnerProcessId, DateTimeOffset OwnerStartTimeUtc);

internal interface IEtwSessionRegistry
{
    bool IsActive(string sessionName);
    void StopExact(string sessionName);
}

internal sealed class TraceEventSessionRegistry : IEtwSessionRegistry
{
    public bool IsActive(string sessionName) =>
        TraceEventSession.GetActiveSessionNames().Contains(sessionName, StringComparer.Ordinal);

    public void StopExact(string sessionName)
    {
        if (!IsActive(sessionName)) return;
        using var session = new TraceEventSession(sessionName);
        session.Stop();
        if (IsActive(sessionName))
        {
            throw new InvalidOperationException("The exact owned ETW session did not stop.");
        }
    }
}

internal sealed class EtwSessionOwnershipManager
{
    internal const string SessionPrefix = "EgressGuard.FileActivity.v2-";
    private const int MarkerVersion = 1;
    private readonly string _directory;
    private readonly string _markerPath;
    private readonly IEtwSessionRegistry _registry;
    private readonly Func<int, DateTimeOffset, bool> _isExactProcessAlive;

    public EtwSessionOwnershipManager(
        string directory,
        IEtwSessionRegistry? registry = null,
        Func<int, DateTimeOffset, bool>? isExactProcessAlive = null)
    {
        _directory = Path.GetFullPath(directory);
        _markerPath = Path.Combine(_directory, "file-activity-session-owner.json");
        _registry = registry ?? new TraceEventSessionRegistry();
        _isExactProcessAlive = isExactProcessAlive ?? IsExactProcessAlive;
    }

    public EtwSessionLease Acquire()
    {
        EnsureProtectedDirectory();
        var existing = ReadMarker();
        string sessionName;
        Guid nonce;
        if (existing is not null)
        {
            ValidateMarker(existing);
            if (_isExactProcessAlive(existing.OwnerProcessId, existing.OwnerStartTimeUtc))
            {
                throw new InvalidOperationException("The EgressGuard ETW session owner is still running.");
            }

            if (_registry.IsActive(existing.SessionName))
            {
                _registry.StopExact(existing.SessionName);
            }

            sessionName = existing.SessionName;
            nonce = existing.Nonce;
        }
        else
        {
            nonce = Guid.NewGuid();
            sessionName = SessionPrefix + nonce.ToString("N");
        }

        using var process = Process.GetCurrentProcess();
        var lease = new EtwSessionLease(sessionName, nonce, Environment.ProcessId, process.StartTime.ToUniversalTime());
        WriteMarker(lease);
        return lease;
    }

    public void Release(EtwSessionLease lease)
    {
        var marker = ReadMarker();
        if (marker is not null
            && marker.Nonce == lease.Nonce
            && marker.OwnerProcessId == lease.OwnerProcessId
            && marker.OwnerStartTimeUtc == lease.OwnerStartTimeUtc
            && string.Equals(marker.SessionName, lease.SessionName, StringComparison.Ordinal))
        {
            File.Delete(_markerPath);
        }
    }

    public bool IsActive(string sessionName) => _registry.IsActive(sessionName);

    public void StopOwnedSession(EtwSessionLease lease)
    {
        var marker = ReadMarker();
        if (marker is null
            || marker.Nonce != lease.Nonce
            || marker.OwnerProcessId != lease.OwnerProcessId
            || marker.OwnerStartTimeUtc != lease.OwnerStartTimeUtc
            || !string.Equals(marker.SessionName, lease.SessionName, StringComparison.Ordinal))
        {
            throw new InvalidOperationException("The exact ETW ownership marker did not match the requested session.");
        }

        _registry.StopExact(lease.SessionName);
        if (_registry.IsActive(lease.SessionName))
        {
            throw new InvalidOperationException("The exact owned ETW session did not stop.");
        }
    }

    private void EnsureProtectedDirectory()
    {
        var directory = Directory.CreateDirectory(_directory);
        using var identity = WindowsIdentity.GetCurrent();
        var owner = identity.User ?? throw new InvalidOperationException("The ETW controller identity has no SID.");
        var security = new DirectorySecurity();
        security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
        AddRule(security, owner);
        AddRule(security, new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null));
        AddRule(security, new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null));
        directory.SetAccessControl(security);
    }

    private static void AddRule(DirectorySecurity security, SecurityIdentifier identity) =>
        security.AddAccessRule(new FileSystemAccessRule(
            identity,
            FileSystemRights.FullControl,
            InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
            PropagationFlags.None,
            AccessControlType.Allow));

    private Marker? ReadMarker()
    {
        if (!File.Exists(_markerPath)) return null;
        try
        {
            return JsonSerializer.Deserialize<Marker>(File.ReadAllText(_markerPath));
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or JsonException)
        {
            throw new InvalidDataException("The EgressGuard ETW ownership marker is unreadable or invalid.", exception);
        }
    }

    private void WriteMarker(EtwSessionLease lease)
    {
        var marker = new Marker(MarkerVersion, lease.SessionName, lease.Nonce, lease.OwnerProcessId, lease.OwnerStartTimeUtc);
        var temporary = _markerPath + "." + Guid.NewGuid().ToString("N") + ".tmp";
        try
        {
            File.WriteAllText(temporary, JsonSerializer.Serialize(marker));
            File.Move(temporary, _markerPath, overwrite: true);
        }
        finally
        {
            if (File.Exists(temporary)) File.Delete(temporary);
        }
    }

    private static void ValidateMarker(Marker marker)
    {
        if (marker.Version != MarkerVersion
            || marker.Nonce == Guid.Empty
            || marker.OwnerProcessId <= 0
            || marker.OwnerStartTimeUtc == default
            || !string.Equals(marker.SessionName, SessionPrefix + marker.Nonce.ToString("N"), StringComparison.Ordinal))
        {
            throw new InvalidDataException("The EgressGuard ETW ownership marker failed exact validation.");
        }
    }

    private static bool IsExactProcessAlive(int processId, DateTimeOffset startTimeUtc)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return !process.HasExited && process.StartTime.ToUniversalTime() == startTimeUtc;
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or System.ComponentModel.Win32Exception)
        {
            return false;
        }
    }

    private sealed record Marker(int Version, string SessionName, Guid Nonce, int OwnerProcessId, DateTimeOffset OwnerStartTimeUtc);
}
