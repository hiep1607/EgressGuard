using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Channels;
using EgressGuard.Core;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace EgressGuard.Windows;

public sealed class EtwFileActivitySensor : IFileActivitySensor, IFileActivityInterestSink
{
    public const int DefaultCapacity = 4096;
    internal const int DefaultProcessIdentityCapacity = 4096;
    internal static readonly TimeSpan DefaultProcessIdentityTtl = TimeSpan.FromMinutes(1);
    private static readonly TimeSpan DefaultStatusPublishInterval = TimeSpan.FromSeconds(1);
    private readonly Channel<RawFileEvent> _staging;
    private readonly Channel<FileActivity> _output;
    private readonly Channel<byte> _statusSignals;
    private readonly string[] _excludedRoots;
    private readonly IProcessIdentityResolver _processResolver;
    private readonly ProcessIdentityCache _processIdentities;
    private readonly EtwSessionOwnershipManager _ownershipManager;
    private readonly TimeSpan _statusPublishInterval;
    private readonly object _sync = new();
    private TraceEventSession? _session;
    private Task? _traceTask;
    private Task? _projectionTask;
    private Task? _statusPublisherTask;
    private CancellationTokenSource? _lifetime;
    private EtwSessionLease? _sessionLease;
    private long _sequence;
    private long _dropped;
    private FileSensorStatus _status = new(FileSensorState.Stopped, 0, null, DateTimeOffset.UtcNow);

    public EtwFileActivitySensor(IEnumerable<string>? excludedRoots = null, int capacity = DefaultCapacity, string? ownershipDirectory = null)
        : this(
            new RuntimeProcessIdentityResolver(),
            excludedRoots,
            capacity,
            new EtwSessionOwnershipManager(ResolveOwnershipDirectory(excludedRoots, ownershipDirectory)),
            new ProcessIdentityCache(DefaultProcessIdentityCapacity, DefaultProcessIdentityTtl),
            DefaultStatusPublishInterval)
    {
    }

    internal EtwFileActivitySensor(
        IProcessIdentityResolver processResolver,
        IEnumerable<string>? excludedRoots = null,
        int capacity = DefaultCapacity,
        EtwSessionOwnershipManager? ownershipManager = null,
        ProcessIdentityCache? processIdentities = null,
        TimeSpan? statusPublishInterval = null)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        _processResolver = processResolver;
        _processIdentities = processIdentities ?? new ProcessIdentityCache(DefaultProcessIdentityCapacity, DefaultProcessIdentityTtl);
        _ownershipManager = ownershipManager ?? new EtwSessionOwnershipManager(ResolveOwnershipDirectory(excludedRoots, null));
        _statusPublishInterval = statusPublishInterval ?? DefaultStatusPublishInterval;
        if (_statusPublishInterval < TimeSpan.Zero) throw new ArgumentOutOfRangeException(nameof(statusPublishInterval));
        _excludedRoots = (excludedRoots ?? []).Where(value => !string.IsNullOrWhiteSpace(value)).Select(Path.GetFullPath).ToArray();
        _staging = Channel.CreateBounded<RawFileEvent>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = true,
            SingleWriter = true
        });
        _output = Channel.CreateBounded<FileActivity>(new BoundedChannelOptions(capacity)
        {
            FullMode = BoundedChannelFullMode.Wait,
            SingleReader = false,
            SingleWriter = true
        });
        _statusSignals = Channel.CreateBounded<byte>(new BoundedChannelOptions(1)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = false
        });
    }

    public FileSensorStatus Status => Volatile.Read(ref _status) with { DroppedEvents = Interlocked.Read(ref _dropped) };
    public event EventHandler<FileSensorStatus>? StatusChanged;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (_lifetime is not null)
            {
                return Task.CompletedTask;
            }

            EnsureStatusPublisher();
            SetStatus(FileSensorState.Starting, null);
            _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            try
            {
                _sessionLease = _ownershipManager.Acquire();
                _session = new TraceEventSession(_sessionLease.SessionName, null) { StopOnDispose = true };
                _session.EnableKernelProvider(
                    KernelTraceEventParser.Keywords.FileIOInit
                    | KernelTraceEventParser.Keywords.FileIO);
                RegisterCallbacks(_session);
                _projectionTask = ProjectAsync(_lifetime.Token);
                _traceTask = Task.Run(() => ProcessTrace(_session, _lifetime.Token), CancellationToken.None);
                SetStatus(FileSensorState.Running, null);
            }
            catch (UnauthorizedAccessException)
            {
                CleanupFailedStart();
                SetStatus(FileSensorState.AccessDenied, "ETW file provider requires an elevated service token.");
            }
            catch (Exception exception) when (exception is Win32Exception or InvalidOperationException or PlatformNotSupportedException)
            {
                CleanupFailedStart();
                SetStatus(FileSensorState.ProviderUnavailable, $"ETW provider unavailable ({exception.GetType().Name}).");
            }
            catch (Exception exception)
            {
                CleanupFailedStart();
                SetStatus(FileSensorState.Failed, $"ETW sensor failed to start ({exception.GetType().Name}).");
            }
        }

        return Task.CompletedTask;
    }

    public async Task StopAsync(CancellationToken cancellationToken)
    {
        TraceEventSession? session;
        Task? traceTask;
        Task? projectionTask;
        lock (_sync)
        {
            session = _session;
            traceTask = _traceTask;
            projectionTask = _projectionTask;
            _lifetime?.Cancel();
            _staging.Writer.TryComplete();
            session?.Stop();
        }

        var tasks = new[] { traceTask, projectionTask }.Where(task => task is not null).Cast<Task>().ToArray();
        if (tasks.Length > 0)
        {
            await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        }

        lock (_sync)
        {
            _session?.Dispose();
            _session = null;
            if (_sessionLease is not null)
            {
                _ownershipManager.Release(_sessionLease);
                _sessionLease = null;
            }
            _lifetime?.Dispose();
            _lifetime = null;
            _traceTask = null;
            _projectionTask = null;
            _output.Writer.TryComplete();
        }

        SetStatus(FileSensorState.Stopped, null);
        _statusSignals.Writer.TryComplete();
        if (_statusPublisherTask is not null)
        {
            await _statusPublisherTask.WaitAsync(TimeSpan.FromSeconds(5), cancellationToken).ConfigureAwait(false);
        }
    }

    public IAsyncEnumerable<FileActivity> ReadAllAsync(CancellationToken cancellationToken) =>
        _output.Reader.ReadAllAsync(cancellationToken);

    public void UpdateProcessInterests(IEnumerable<FileActivityProcessInterest> processes)
    {
        ArgumentNullException.ThrowIfNull(processes);
        var observedAt = DateTimeOffset.UtcNow;
        foreach (var process in processes)
        {
            _processIdentities.ObserveProcessStart(
                new ResolvedProcessIdentity(process.Identity, process.ProcessName),
                observedAt);
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(5));
            await StopAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or TimeoutException)
        {
            _session?.Dispose();
        }
    }

    private void RegisterCallbacks(TraceEventSession session)
    {
        session.Source.Kernel.FileIORead += data => Stage(data.ProcessID, data.ProcessName, data.FileName, FileActivityOperation.Read, data.TimeStamp);
        session.Source.Kernel.FileIOWrite += data => Stage(data.ProcessID, data.ProcessName, data.FileName, FileActivityOperation.Write, data.TimeStamp);
        session.Source.Kernel.FileIOCreate += data => Stage(data.ProcessID, data.ProcessName, data.FileName, FileActivityOperation.OpenCreate, data.TimeStamp);
        session.Source.Kernel.FileIODelete += data => Stage(data.ProcessID, data.ProcessName, data.FileName, FileActivityOperation.Delete, data.TimeStamp);
        session.Source.Kernel.FileIORename += data => Stage(data.ProcessID, data.ProcessName, data.FileName, FileActivityOperation.Rename, data.TimeStamp);
    }

    private void Stage(int processId, string processName, string? path, FileActivityOperation operation, DateTime timestamp)
    {
        var timestampUtc = new DateTimeOffset(timestamp.ToUniversalTime());
        if (processId <= 0
            || !_processIdentities.TryGet(processId, processName, timestampUtc, DateTimeOffset.UtcNow, out var process)
            || process is null
            || string.IsNullOrWhiteSpace(path)
            || !Path.IsPathFullyQualified(path)
            || IsExcluded(path))
        {
            return;
        }

        var item = new RawFileEvent(process!, path, operation, timestampUtc);
        if (!_staging.Writer.TryWrite(item))
        {
            RecordDrop("Bounded ETW staging buffer overflowed; events were dropped.");
        }
    }

    internal void StageForTest(int processId, string processName, string path, FileActivityOperation operation, DateTime timestamp)
    {
        EnsureStatusPublisher();
        if (!_processIdentities.TryGet(processId, processName, timestamp.ToUniversalTime(), DateTimeOffset.UtcNow, out var known)
            || known is null)
        {
            var resolved = _processResolver.Resolve(processId);
            if (resolved is not null)
            {
                _processIdentities.ObserveProcessStart(
                    new ResolvedProcessIdentity(resolved.Identity, processName),
                    DateTimeOffset.UtcNow);
            }
        }
        Stage(processId, processName, path, operation, timestamp);
    }

    internal FileActivity? ProjectForTest(int processId, string processName, string path, FileActivityOperation operation, DateTimeOffset timestampUtc)
    {
        var resolved = _processIdentities.Resolve(processId, processName, timestampUtc, DateTimeOffset.UtcNow, _processResolver);
        return resolved is null ? null : Resolve(new RawFileEvent(resolved, path, operation, timestampUtc));
    }

    internal int ProcessIdentityCacheCount => _processIdentities.Count;

    internal string? SessionName => _sessionLease?.SessionName;

    private async Task ProjectAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var item in _staging.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                var activity = Resolve(item);
                if (activity is not null && !_output.Writer.TryWrite(activity))
                {
                    RecordDrop("Bounded file activity output overflowed; events were dropped.");
                }
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private FileActivity? Resolve(RawFileEvent item)
    {
        try
        {
            return new FileActivity(
                Interlocked.Increment(ref _sequence), item.TimestampUtc,
                item.Process.Identity,
                item.Process.ProcessName,
                item.Operation, Path.GetFullPath(item.Path), Path.GetExtension(item.Path).ToLowerInvariant(),
                "Windows Kernel File I/O ETW", true);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    private void ProcessTrace(TraceEventSession session, CancellationToken cancellationToken)
    {
        try
        {
            session.Source.Process();
        }
        catch (Exception exception) when (cancellationToken.IsCancellationRequested && exception is (InvalidOperationException or ObjectDisposedException))
        {
        }
        catch (Exception exception)
        {
            SetStatus(FileSensorState.Failed, $"ETW processing failed ({exception.GetType().Name}).");
        }
    }

    private bool IsExcluded(string path) => _excludedRoots.Any(root =>
        path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
        || string.Equals(path, root, StringComparison.OrdinalIgnoreCase));

    private void RecordDrop(string detail)
    {
        Interlocked.Increment(ref _dropped);
        SetStatus(FileSensorState.OverflowDegraded, detail);
        _statusSignals.Writer.TryWrite(0);
    }

    private void CleanupFailedStart()
    {
        _session?.Dispose();
        _session = null;
        if (_sessionLease is not null)
        {
            _ownershipManager.Release(_sessionLease);
            _sessionLease = null;
        }
        _lifetime?.Dispose();
        _lifetime = null;
    }

    private void EnsureStatusPublisher()
    {
        lock (_sync)
        {
            _statusPublisherTask ??= Task.Run(PublishStatusesAsync);
        }
    }

    private async Task PublishStatusesAsync()
    {
        var lastPublished = new FileSensorStatus(FileSensorState.Stopped, -1, null, DateTimeOffset.MinValue);
        var lastPublishedAt = DateTimeOffset.MinValue;
        await foreach (var signal in _statusSignals.Reader.ReadAllAsync().ConfigureAwait(false))
        {
            _ = signal;
            while (_statusSignals.Reader.TryRead(out _)) { }
            var delay = lastPublishedAt == DateTimeOffset.MinValue
                ? TimeSpan.Zero
                : _statusPublishInterval - (DateTimeOffset.UtcNow - lastPublishedAt);
            if (delay > TimeSpan.Zero) await Task.Delay(delay).ConfigureAwait(false);

            var status = Status;
            if (status.State == lastPublished.State
                && status.DroppedEvents == lastPublished.DroppedEvents
                && string.Equals(status.Detail, lastPublished.Detail, StringComparison.Ordinal))
            {
                continue;
            }

            var subscribers = StatusChanged;
            if (subscribers is not null)
            {
                foreach (EventHandler<FileSensorStatus> subscriber in subscribers.GetInvocationList())
                {
                    try
                    {
                        subscriber(this, status);
                    }
                    catch
                    {
                        // Subscriber failures must never affect the ETW callback or sensor lifetime.
                    }
                }
            }

            lastPublished = status;
            lastPublishedAt = DateTimeOffset.UtcNow;
        }
    }

    private void SetStatus(FileSensorState state, string? detail)
    {
        while (true)
        {
            var previous = Volatile.Read(ref _status);
            var changed = previous.State != state || !string.Equals(previous.Detail, detail, StringComparison.Ordinal);
            if (!changed)
            {
                return;
            }

            var status = new FileSensorStatus(state, Interlocked.Read(ref _dropped), detail, DateTimeOffset.UtcNow);
            if (ReferenceEquals(Interlocked.CompareExchange(ref _status, status, previous), previous))
            {
                _statusSignals.Writer.TryWrite(0);
                return;
            }
        }
    }

    private sealed record RawFileEvent(ResolvedProcessIdentity Process, string Path, FileActivityOperation Operation, DateTimeOffset TimestampUtc);

    private static string ResolveOwnershipDirectory(IEnumerable<string>? excludedRoots, string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured)) return Path.GetFullPath(configured);
        var dataRoot = excludedRoots?.FirstOrDefault(value => !string.IsNullOrWhiteSpace(value));
        if (!string.IsNullOrWhiteSpace(dataRoot)) return Path.Combine(Path.GetFullPath(dataRoot), "etw-ownership");
        return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "EgressGuard", "etw-ownership");
    }
}

internal sealed record ResolvedProcessIdentity(ProcessIdentity Identity, string ProcessName);

internal interface IProcessIdentityResolver
{
    ResolvedProcessIdentity? Resolve(int processId);
}

internal sealed class ProcessIdentityCache
{
    private readonly int _capacity;
    private readonly TimeSpan _ttl;
    private readonly Dictionary<int, CacheEntry> _entries = [];
    private readonly LinkedList<int> _lru = [];
    private readonly object _sync = new();

    public ProcessIdentityCache(int capacity, TimeSpan ttl)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(ttl, TimeSpan.Zero);
        _capacity = capacity;
        _ttl = ttl;
    }

    internal int Count { get { lock (_sync) return _entries.Count; } }

    public ResolvedProcessIdentity? Resolve(
        int processId,
        string processName,
        DateTimeOffset eventTimestampUtc,
        DateTimeOffset observedAtUtc,
        IProcessIdentityResolver resolver)
    {
        if (TryGet(processId, processName, eventTimestampUtc, observedAtUtc, out var cached)) return cached;

        var resolved = resolver.Resolve(processId);
        if (resolved is null || eventTimestampUtc < resolved.Identity.StartTime) return null;
        ObserveProcessStart(resolved, observedAtUtc);
        return resolved;
    }

    public bool TryGet(
        int processId,
        string processName,
        DateTimeOffset eventTimestampUtc,
        DateTimeOffset observedAtUtc,
        out ResolvedProcessIdentity? process)
    {
        lock (_sync)
        {
            CleanupExpired(observedAtUtc);
            if (_entries.TryGetValue(processId, out var cached))
            {
                if (!string.IsNullOrWhiteSpace(processName)
                    && !string.Equals(processName, cached.Value.ProcessName, StringComparison.OrdinalIgnoreCase))
                {
                    Remove(cached);
                }
                else
                {
                    Touch(cached, observedAtUtc);
                    process = eventTimestampUtc < cached.Value.Identity.StartTime ? null : cached.Value;
                    return true;
                }
            }
        }

        process = null;
        return false;
    }

    public void ObserveProcessStart(ResolvedProcessIdentity process, DateTimeOffset observedAtUtc)
    {
        lock (_sync)
        {
            CleanupExpired(observedAtUtc);
            if (_entries.TryGetValue(process.Identity.ProcessId, out var existing)) Remove(existing);
            var node = _lru.AddLast(process.Identity.ProcessId);
            _entries[process.Identity.ProcessId] = new CacheEntry(process, observedAtUtc + _ttl, node);
            while (_entries.Count > _capacity)
            {
                Remove(_entries[_lru.First!.Value]);
            }
        }
    }

    public void ObserveProcessStop(int processId, DateTimeOffset stoppedAtUtc)
    {
        lock (_sync)
        {
            if (_entries.TryGetValue(processId, out var existing)
                && existing.Value.Identity.StartTime <= stoppedAtUtc)
            {
                Remove(existing);
            }
        }
    }

    private void CleanupExpired(DateTimeOffset observedAtUtc)
    {
        while (_lru.First is { } node
            && _entries[node.Value].ExpiresAtUtc <= observedAtUtc)
        {
            Remove(_entries[node.Value]);
        }
    }

    private void Touch(CacheEntry entry, DateTimeOffset observedAtUtc)
    {
        entry.ExpiresAtUtc = observedAtUtc + _ttl;
        _lru.Remove(entry.Node);
        _lru.AddLast(entry.Node);
    }

    private void Remove(CacheEntry entry)
    {
        _entries.Remove(entry.Value.Identity.ProcessId);
        _lru.Remove(entry.Node);
    }

    private sealed class CacheEntry(ResolvedProcessIdentity value, DateTimeOffset expiresAtUtc, LinkedListNode<int> node)
    {
        public ResolvedProcessIdentity Value { get; } = value;
        public DateTimeOffset ExpiresAtUtc { get; set; } = expiresAtUtc;
        public LinkedListNode<int> Node { get; } = node;
    }
}

internal sealed class RuntimeProcessIdentityResolver : IProcessIdentityResolver
{
    public ResolvedProcessIdentity? Resolve(int processId)
    {
        try
        {
            using var process = Process.GetProcessById(processId);
            return new ResolvedProcessIdentity(new ProcessIdentity(processId, process.StartTime.ToUniversalTime()), process.ProcessName);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return null;
        }
    }
}
