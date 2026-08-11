using System.Security.Cryptography;
using System.Text;

namespace EgressGuard.Core;

public enum FileActivityOperation
{
    OpenCreate,
    Read,
    Write,
    Rename,
    Delete
}

public enum FileSensorState
{
    Disabled,
    Starting,
    Running,
    AccessDenied,
    ProviderUnavailable,
    OverflowDegraded,
    Stopped,
    Failed
}

public enum CorrelationConfidence
{
    Low,
    Medium,
    High
}

public sealed record FileSensorStatus(
    FileSensorState State,
    long DroppedEvents,
    string? Detail,
    DateTimeOffset ChangedAt);

public sealed record FileActivity(
    long Sequence,
    DateTimeOffset TimestampUtc,
    ProcessIdentity ProcessIdentity,
    string ProcessName,
    FileActivityOperation Operation,
    string Path,
    string Extension,
    string Source,
    bool IsValid,
    string? ValidationMessage = null);

public sealed record FileCorrelation(
    Guid Id,
    string FlowId,
    ProcessIdentity ProcessIdentity,
    string ProcessName,
    FileActivityOperation Operation,
    string ProtectedFileIdentifier,
    string DisplayPath,
    string Extension,
    DateTimeOffset ActivityTimestampUtc,
    double TimeDeltaSeconds,
    CorrelationConfidence Confidence,
    string Reason,
    DateTimeOffset CreatedAtUtc);

public interface IFileActivitySensor : IAsyncDisposable
{
    FileSensorStatus Status { get; }
    event EventHandler<FileSensorStatus>? StatusChanged;
    IAsyncEnumerable<FileActivity> ReadAllAsync(CancellationToken cancellationToken);
    Task StartAsync(CancellationToken cancellationToken);
    Task StopAsync(CancellationToken cancellationToken);
}

public sealed record FileActivityProcessInterest(ProcessIdentity Identity, string ProcessName);

/// <summary>
/// A privacy-preserving file event captured before a network flow is known.
/// The path remains in-memory only and is promoted to <see cref="FileActivity"/>
/// only after an exact process identity is supplied by the network sensor.
/// </summary>
public sealed record RawFileActivity(
    long Sequence,
    DateTimeOffset TimestampUtc,
    int ProcessId,
    string ProcessName,
    FileActivityOperation Operation,
    string Path);

public interface IFileActivityInterestSink
{
    IReadOnlyList<FileActivity> UpdateProcessInterests(IEnumerable<FileActivityProcessInterest> processes);
    void ObserveProcessStop(ProcessIdentity identity, DateTimeOffset stoppedAtUtc);
}

public sealed class DisabledFileActivitySensor : IFileActivitySensor
{
    public FileSensorStatus Status { get; } = new(FileSensorState.Disabled, 0, "File correlation is disabled by configuration.", DateTimeOffset.UtcNow);
    public event EventHandler<FileSensorStatus>? StatusChanged { add { } remove { } }
    public IAsyncEnumerable<FileActivity> ReadAllAsync(CancellationToken cancellationToken) => Empty(cancellationToken);
    public Task StartAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public Task StopAsync(CancellationToken cancellationToken) => Task.CompletedTask;
    public ValueTask DisposeAsync() => ValueTask.CompletedTask;

    private static async IAsyncEnumerable<FileActivity> Empty(
        [System.Runtime.CompilerServices.EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await Task.CompletedTask.ConfigureAwait(false);
        cancellationToken.ThrowIfCancellationRequested();
        yield break;
    }
}

public sealed record FileCorrelationOptions(
    TimeSpan BeforeFlow,
    TimeSpan AfterFlow,
    TimeSpan Retention,
    TimeSpan DedupeWindow,
    int MaximumBufferedEvents,
    int MaximumEvidencePerFlow)
{
    public static FileCorrelationOptions Default { get; } = new(
        TimeSpan.FromSeconds(30),
        TimeSpan.FromSeconds(5),
        TimeSpan.FromMinutes(2),
        TimeSpan.FromMilliseconds(750),
        4096,
        20);
}

public sealed class FileCorrelationEngine
{
    private readonly FileCorrelationOptions _options;
    private readonly LinkedList<BufferedFileActivity> _events = [];
    private readonly SortedSet<BufferedFileActivity> _eventsByTimestamp = new(BufferedFileActivityTimestampComparer.Instance);
    private readonly Dictionary<string, DateTimeOffset> _dedupe = new(StringComparer.OrdinalIgnoreCase);
    private readonly string[] _excludedRoots;
    private readonly byte[] _pathSalt;
    private readonly object _sync = new();
    private long _droppedEvents;
    private long _nextOrdinal;
    private long _cleanupNodesInspected;

    public FileCorrelationEngine(
        FileCorrelationOptions? options = null,
        IEnumerable<string>? excludedRoots = null,
        byte[]? pathSalt = null)
    {
        _options = options ?? FileCorrelationOptions.Default;
        if (_options.MaximumBufferedEvents < 1 || _options.MaximumEvidencePerFlow < 1)
        {
            throw new ArgumentOutOfRangeException(nameof(options));
        }

        _excludedRoots = (excludedRoots ?? [])
            .Where(path => !string.IsNullOrWhiteSpace(path))
            .Select(path => EnsureTrailingSeparator(Path.GetFullPath(path)))
            .ToArray();
        _pathSalt = pathSalt is { Length: > 0 } ? [.. pathSalt] : RandomNumberGenerator.GetBytes(32);
    }

    public long DroppedEvents => Interlocked.Read(ref _droppedEvents);
    internal int BufferedEventCount { get { lock (_sync) return _events.Count; } }
    internal int DedupeEntryCount { get { lock (_sync) return _dedupe.Count; } }
    internal int TimestampIndexCount { get { lock (_sync) return _eventsByTimestamp.Count; } }
    internal long CleanupNodesInspected => Interlocked.Read(ref _cleanupNodesInspected);

    public bool Add(FileActivity activity)
    {
        if (!activity.IsValid || string.IsNullOrWhiteSpace(activity.Path) || activity.ProcessIdentity.StartTime == default)
        {
            return false;
        }

        string path;
        try
        {
            path = Path.GetFullPath(activity.Path);
        }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        if (_excludedRoots.Any(root => IsUnderRoot(path, root)))
        {
            return false;
        }

        var normalized = activity with { Path = path, Extension = Path.GetExtension(path).ToLowerInvariant() };
        var key = $"{normalized.ProcessIdentity.ProcessId}|{normalized.ProcessIdentity.StartTime.UtcTicks}|{normalized.Operation}|{path}";
        lock (_sync)
        {
            CleanupCore(normalized.TimestampUtc);
            if (_dedupe.TryGetValue(key, out var previous) && (normalized.TimestampUtc - previous).Duration() <= _options.DedupeWindow)
            {
                return false;
            }

            _dedupe[key] = normalized.TimestampUtc;
            if (_events.Count >= _options.MaximumBufferedEvents)
            {
                RemoveNode(_events.First!);
                Interlocked.Increment(ref _droppedEvents);
            }

            var buffered = new BufferedFileActivity(normalized, key, ++_nextOrdinal);
            buffered.InsertionNode = _events.AddLast(buffered);
            _eventsByTimestamp.Add(buffered);
            return true;
        }
    }

    public IReadOnlyList<FileCorrelation> Correlate(NetworkFlow flow, DateTimeOffset? createdAtUtc = null)
    {
        if (flow.ProcessIdentity is null)
        {
            return [];
        }

        var lower = flow.FirstSeen - _options.BeforeFlow;
        var upper = flow.FirstSeen + _options.AfterFlow;
        var created = createdAtUtc ?? DateTimeOffset.UtcNow;
        lock (_sync)
        {
            CleanupCore(flow.FirstSeen + _options.AfterFlow);
            return _events
                .Select(item => item.Activity)
                .Where(item => item.ProcessIdentity == flow.ProcessIdentity && item.TimestampUtc >= lower && item.TimestampUtc <= upper)
                .OrderBy(item => Math.Abs((item.TimestampUtc - flow.FirstSeen).TotalMilliseconds))
                .ThenBy(item => item.Sequence)
                .Take(_options.MaximumEvidencePerFlow)
                .Select(item => CreateCorrelation(flow, item, created))
                .ToArray();
        }
    }

    public int Cleanup(DateTimeOffset nowUtc)
    {
        lock (_sync)
        {
            return CleanupCore(nowUtc);
        }
    }

    private FileCorrelation CreateCorrelation(NetworkFlow flow, FileActivity activity, DateTimeOffset created)
    {
        var delta = (activity.TimestampUtc - flow.FirstSeen).TotalSeconds;
        var absolute = Math.Abs(delta);
        var confidence = (activity.Operation is FileActivityOperation.Read or FileActivityOperation.OpenCreate) && absolute <= 5
            ? CorrelationConfidence.High
            : absolute <= 15 ? CorrelationConfidence.Medium : CorrelationConfidence.Low;
        var direction = delta < 0 ? "before" : "after";
        var reason = $"Same process identity; file {activity.Operation} {absolute:0.###} seconds {direction} outbound flow first-seen.";
        var hash = Convert.ToHexString(SHA256.HashData(Combine(_pathSalt, Encoding.UTF8.GetBytes(activity.Path.ToUpperInvariant()))));
        var display = $"file-{hash[..12].ToLowerInvariant()}{activity.Extension}";
        return new FileCorrelation(
            DeterministicId(flow.Id, activity), flow.Id, activity.ProcessIdentity, activity.ProcessName,
            activity.Operation, hash, display, activity.Extension, activity.TimestampUtc, delta,
            confidence, reason, created);
    }

    private int CleanupCore(DateTimeOffset nowUtc)
    {
        var cutoff = nowUtc - _options.Retention;
        var removed = 0;
        while (_eventsByTimestamp.Count > 0)
        {
            Interlocked.Increment(ref _cleanupNodesInspected);
            var oldest = _eventsByTimestamp.Min!;
            if (oldest.Activity.TimestampUtc >= cutoff) break;
            RemoveNode(oldest.InsertionNode!);
            removed++;
        }

        return removed;
    }

    private void RemoveNode(LinkedListNode<BufferedFileActivity> node)
    {
        var item = node.Value;
        _events.Remove(node);
        _eventsByTimestamp.Remove(item);
        if (_dedupe.TryGetValue(item.DedupeKey, out var timestamp) && timestamp == item.Activity.TimestampUtc)
        {
            _dedupe.Remove(item.DedupeKey);
        }
    }

    private static Guid DeterministicId(string flowId, FileActivity activity)
    {
        var value = $"{flowId}|{activity.Sequence}|{activity.TimestampUtc.UtcTicks}|{activity.Path}";
        return new Guid(SHA256.HashData(Encoding.UTF8.GetBytes(value)).AsSpan(0, 16));
    }

    private static byte[] Combine(byte[] first, byte[] second)
    {
        var result = new byte[first.Length + second.Length];
        Buffer.BlockCopy(first, 0, result, 0, first.Length);
        Buffer.BlockCopy(second, 0, result, first.Length, second.Length);
        return result;
    }

    private static string EnsureTrailingSeparator(string value) =>
        value.EndsWith(Path.DirectorySeparatorChar) ? value : value + Path.DirectorySeparatorChar;

    private static bool IsUnderRoot(string path, string root) =>
        path.StartsWith(root, StringComparison.OrdinalIgnoreCase)
        || string.Equals(path.TrimEnd(Path.DirectorySeparatorChar), root.TrimEnd(Path.DirectorySeparatorChar), StringComparison.OrdinalIgnoreCase);

    private sealed class BufferedFileActivity(FileActivity activity, string dedupeKey, long ordinal)
    {
        public FileActivity Activity { get; } = activity;
        public string DedupeKey { get; } = dedupeKey;
        public long Ordinal { get; } = ordinal;
        public LinkedListNode<BufferedFileActivity>? InsertionNode { get; set; }
    }

    private sealed class BufferedFileActivityTimestampComparer : IComparer<BufferedFileActivity>
    {
        public static BufferedFileActivityTimestampComparer Instance { get; } = new();

        public int Compare(BufferedFileActivity? left, BufferedFileActivity? right)
        {
            if (ReferenceEquals(left, right)) return 0;
            if (left is null) return -1;
            if (right is null) return 1;
            var timestamp = left.Activity.TimestampUtc.CompareTo(right.Activity.TimestampUtc);
            return timestamp != 0 ? timestamp : left.Ordinal.CompareTo(right.Ordinal);
        }
    }
}
