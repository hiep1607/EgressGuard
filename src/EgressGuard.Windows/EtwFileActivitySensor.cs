using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Channels;
using EgressGuard.Core;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace EgressGuard.Windows;

/// <summary>
/// Observe-only ETW file sensor.  The ETW callback does only cheap validation and
/// writes a bounded raw event.  Process identity resolution and promotion happen
/// after the network snapshot supplies an exact (PID, start time) identity.
/// </summary>
public sealed class EtwFileActivitySensor : IFileActivitySensor, IFileActivityInterestSink
{
    public const int DefaultCapacity = 4096;
    internal const int DefaultProcessIdentityCapacity = 4096;
    internal const int DefaultRecentRawCapacity = 4096;
    internal const int DefaultRecentRawPerProcessCapacity = 256;
    internal static readonly TimeSpan DefaultProcessIdentityTtl = TimeSpan.FromMinutes(1);
    internal static readonly TimeSpan DefaultRecentRawRetention = TimeSpan.FromSeconds(35);
    private static readonly TimeSpan DefaultStatusPublishInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan DefaultRecentRawCleanupInterval = TimeSpan.FromSeconds(1);
    private static readonly TimeSpan DefaultCallbackDedupeWindow = TimeSpan.FromMilliseconds(750);

    private readonly Channel<RawFileActivity> _staging;
    private readonly Channel<FileActivity> _output;
    private readonly Channel<byte> _statusSignals;
    private readonly string[] _excludedRoots;
    private readonly string[] _lowValueSystemRoots;
    private readonly IProcessIdentityResolver _processResolver;
    private readonly ProcessIdentityCache _processIdentities;
    private readonly EtwCallbackAdmissionCache _callbackAdmission;
    private readonly EtwSessionOwnershipManager _ownershipManager;
    private readonly TimeSpan _statusPublishInterval;
    private readonly int _recentRawCapacity;
    private readonly int _recentRawPerProcessCapacity;
    private readonly TimeSpan _recentRawRetention;
    private readonly object _sync = new();
    private readonly object _correlationSync = new();
    private readonly LinkedList<BufferedRawFileActivity> _recentRaw = [];
    private readonly LinkedList<BufferedPromotedFileActivity> _pendingPromoted = [];
    private readonly Dictionary<ProcessIdentity, LinkedList<BufferedPromotedFileActivity>> _pendingPromotedByProcess = [];
    private readonly Dictionary<int, LinkedList<BufferedRawFileActivity>> _recentRawByProcess = [];
    private readonly Dictionary<RawFileActivityKey, BufferedRawFileActivity> _recentRawByKey = new(RawFileActivityKeyComparer.Instance);
    private readonly Dictionary<int, ResolvedProcessIdentity> _processInterests = [];
    private HashSet<int> _interestedProcessIds = [];
    private TraceEventSession? _session;
    private Task? _traceTask;
    private Task? _projectionTask;
    private Task? _statusPublisherTask;
    private Task? _stopTask;
    private CancellationTokenSource? _lifetime;
    private EtwSessionLease? _sessionLease;
    private long _sequence;
    private long _dropped;
    private int _recentRawPeak;
    private int _recentRawPerProcessPeak;
    private long _pendingPromotionNodesVisited;
    private DateTimeOffset _nextRecentRawCleanupUtc = DateTimeOffset.MinValue;
    private FileSensorStatus _status = new(FileSensorState.Stopped, 0, null, DateTimeOffset.UtcNow);

    public EtwFileActivitySensor(IEnumerable<string>? excludedRoots = null, int capacity = DefaultCapacity, string? ownershipDirectory = null)
        : this(
            new RuntimeProcessIdentityResolver(),
            excludedRoots,
            capacity,
            new EtwSessionOwnershipManager(ResolveOwnershipDirectory(excludedRoots, ownershipDirectory)),
            new ProcessIdentityCache(DefaultProcessIdentityCapacity, DefaultProcessIdentityTtl),
            DefaultStatusPublishInterval,
            DefaultRecentRawCapacity,
            DefaultRecentRawPerProcessCapacity,
            DefaultRecentRawRetention,
            callbackAdmission: new EtwCallbackAdmissionCache(DefaultCapacity, DefaultCallbackDedupeWindow))
    {
    }

    internal EtwFileActivitySensor(
        IProcessIdentityResolver processResolver,
        IEnumerable<string>? excludedRoots = null,
        int capacity = DefaultCapacity,
        EtwSessionOwnershipManager? ownershipManager = null,
        ProcessIdentityCache? processIdentities = null,
        TimeSpan? statusPublishInterval = null,
        int recentRawCapacity = DefaultRecentRawCapacity,
        int recentRawPerProcessCapacity = DefaultRecentRawPerProcessCapacity,
        TimeSpan? recentRawRetention = null,
        IEnumerable<string>? lowValueSystemRoots = null,
        EtwCallbackAdmissionCache? callbackAdmission = null)
    {
        ArgumentNullException.ThrowIfNull(processResolver);
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(recentRawCapacity, 1);
        ArgumentOutOfRangeException.ThrowIfLessThan(recentRawPerProcessCapacity, 1);
        _processResolver = processResolver;
        _processIdentities = processIdentities ?? new ProcessIdentityCache(DefaultProcessIdentityCapacity, DefaultProcessIdentityTtl);
        _callbackAdmission = callbackAdmission ?? new EtwCallbackAdmissionCache(DefaultCapacity, DefaultCallbackDedupeWindow);
        _ownershipManager = ownershipManager ?? new EtwSessionOwnershipManager(ResolveOwnershipDirectory(excludedRoots, null));
        _statusPublishInterval = statusPublishInterval ?? DefaultStatusPublishInterval;
        _recentRawCapacity = recentRawCapacity;
        _recentRawPerProcessCapacity = recentRawPerProcessCapacity;
        _recentRawRetention = recentRawRetention ?? DefaultRecentRawRetention;
        if (_statusPublishInterval < TimeSpan.Zero || _recentRawRetention <= TimeSpan.Zero)
        {
            throw new ArgumentOutOfRangeException(nameof(statusPublishInterval));
        }

        _excludedRoots = (excludedRoots ?? [])
            .Where(value => !string.IsNullOrWhiteSpace(value))
            .Select(Path.GetFullPath)
            .ToArray();
        _lowValueSystemRoots = NormalizeRoots(lowValueSystemRoots ?? GetDefaultLowValueSystemRoots());
        _staging = Channel.CreateBounded<RawFileActivity>(new BoundedChannelOptions(capacity)
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
    internal int ProcessIdentityCacheCount => _processIdentities.Count;
    internal int RecentRawEventCount { get { lock (_correlationSync) return _recentRaw.Count; } }
    internal int RecentRawDedupeCount { get { lock (_correlationSync) return _recentRawByKey.Count; } }
    internal int RecentRawPeak => Volatile.Read(ref _recentRawPeak);
    internal int RecentRawPerProcessPeak => Volatile.Read(ref _recentRawPerProcessPeak);
    internal int PendingPromotedCount { get { lock (_correlationSync) return _pendingPromoted.Count; } }
    internal int PendingPromotedIdentityCount { get { lock (_correlationSync) return _pendingPromotedByProcess.Count; } }
    internal long PendingPromotionNodesVisited => Interlocked.Read(ref _pendingPromotionNodesVisited);
    internal int StagedEventCount => _staging.Reader.Count;
    internal int CallbackAdmissionCount => _callbackAdmission.Count;
    internal string? SessionName => _sessionLease?.SessionName;

    public Task StartAsync(CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        lock (_sync)
        {
            if (_lifetime is not null) return Task.CompletedTask;
            if (_stopTask is not null) throw new InvalidOperationException("An ETW sensor instance cannot be restarted after StopAsync.");

            EnsureStatusPublisher();
            SetStatus(FileSensorState.Starting, null);
            _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            try
            {
                _sessionLease = _ownershipManager.Acquire();
                _session = new TraceEventSession(_sessionLease.SessionName, null) { StopOnDispose = true };
                _session.EnableKernelProvider(KernelTraceEventParser.Keywords.FileIOInit | KernelTraceEventParser.Keywords.FileIO);
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

    public Task StopAsync(CancellationToken cancellationToken)
    {
        Task stopTask;
        Task? publisherTask = null;
        lock (_sync)
        {
            if (_lifetime is null)
            {
                if (_stopTask is null) SetStatus(FileSensorState.Stopped, null);
                _statusSignals.Writer.TryComplete();
                publisherTask = _statusPublisherTask;
                return publisherTask is null
                    ? Task.CompletedTask
                    : publisherTask.WaitAsync(TimeSpan.FromSeconds(8), cancellationToken);
            }

            stopTask = _stopTask ??= StopCoreAsync();
        }

        return stopTask.WaitAsync(TimeSpan.FromSeconds(10), cancellationToken);
    }

    public IAsyncEnumerable<FileActivity> ReadAllAsync(CancellationToken cancellationToken) =>
        _output.Reader.ReadAllAsync(cancellationToken);

    /// <summary>
    /// Installs exact network identities and synchronously promotes buffered
    /// pre-flow raw events.  The returned activities are consumed immediately by
    /// FlowCoordinator so correlation cannot race the asynchronous ETW pump.
    /// </summary>
    public IReadOnlyList<FileActivity> UpdateProcessInterests(IEnumerable<FileActivityProcessInterest> processes)
    {
        ArgumentNullException.ThrowIfNull(processes);
        var currentProcesses = processes as FileActivityProcessInterest[] ?? processes.ToArray();
        var observedAt = DateTimeOffset.UtcNow;
        var promoted = new List<FileActivity>();
        lock (_correlationSync)
        {
            CleanupRecentRaw(observedAt, force: true);
            foreach (var process in currentProcesses)
            {
                var resolved = new ResolvedProcessIdentity(process.Identity, process.ProcessName);
                _processIdentities.ObserveProcessStart(resolved, observedAt);
                _processInterests[process.Identity.ProcessId] = resolved;
                PromoteForInterest(resolved, observedAt, promoted);
                DrainPendingPromoted(resolved.Identity, promoted);
            }

            // Publish an immutable snapshot for the ETW callback. Unknown
            // processes only need pre-flow reads; once a network identity is
            // known, the callback may admit the remaining operations too.
            Volatile.Write(
                ref _interestedProcessIds,
                currentProcesses.Select(process => process.Identity.ProcessId).ToHashSet());
        }

        return promoted;
    }

    public void ObserveProcessStop(ProcessIdentity identity, DateTimeOffset stoppedAtUtc)
    {
        _processIdentities.ObserveProcessStop(identity, stoppedAtUtc);
        lock (_correlationSync)
        {
            if (_processInterests.TryGetValue(identity.ProcessId, out var current) && current.Identity == identity)
            {
                _processInterests.Remove(identity.ProcessId);
                Volatile.Write(ref _interestedProcessIds, _processInterests.Keys.ToHashSet());
            }
        }
    }

    public async ValueTask DisposeAsync()
    {
        try
        {
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
            await StopAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (Exception exception) when (exception is OperationCanceledException or TimeoutException)
        {
            // Preserve the exact marker on a timeout; a subsequent start can
            // reclaim only that exact verified orphan.
            lock (_sync) _session?.Dispose();
        }
    }

    private async Task StopCoreAsync()
    {
        TraceEventSession? session;
        Task? traceTask;
        Task? projectionTask;
        CancellationTokenSource? lifetime;
        EtwSessionLease? lease;
        lock (_sync)
        {
            session = _session;
            traceTask = _traceTask;
            projectionTask = _projectionTask;
            lifetime = _lifetime;
            lease = _sessionLease;
            lifetime?.Cancel();
            _staging.Writer.TryComplete();
        }

        Exception? failure = null;
        try
        {
            session?.Stop();
            var tasks = new[] { traceTask, projectionTask }.Where(task => task is not null).Cast<Task>().ToArray();
            if (tasks.Length > 0)
            {
                await Task.WhenAll(tasks).WaitAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
            }
        }
        catch (Exception exception)
        {
            failure = exception;
        }

        try { session?.Dispose(); } catch (Exception exception) { failure ??= exception; }

        var sessionStopped = lease is null || !_ownershipManager.IsActive(lease.SessionName);
        if (!sessionStopped)
        {
            try
            {
                _ownershipManager.StopOwnedSession(lease!);
                sessionStopped = !_ownershipManager.IsActive(lease!.SessionName);
            }
            catch (Exception exception)
            {
                failure ??= exception;
            }
        }

        lock (_sync)
        {
            _session = null;
            _traceTask = null;
            _projectionTask = null;
            _lifetime = null;
            lifetime?.Dispose();
            if (sessionStopped && lease is not null)
            {
                _ownershipManager.Release(lease);
                _sessionLease = null;
            }
            _output.Writer.TryComplete(failure);
        }

        if (failure is not null || !sessionStopped)
        {
            SetStatus(FileSensorState.Failed, failure?.Message ?? "Exact owned ETW session remained active after bounded stop.");
            throw failure ?? new InvalidOperationException("Exact owned ETW session remained active after bounded stop.");
        }

        SetStatus(FileSensorState.Stopped, null);
        _statusSignals.Writer.TryComplete();
        if (_statusPublisherTask is not null)
        {
            await _statusPublisherTask.WaitAsync(TimeSpan.FromSeconds(8)).ConfigureAwait(false);
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
            || string.IsNullOrWhiteSpace(path)
            || !Path.IsPathFullyQualified(path)
            || IsExcluded(path)
            || IsLowValueSystemPathCore(path, _lowValueSystemRoots))
        {
            return;
        }

        // Kernel FileIOCreate/Write/Rename/Delete are extremely noisy during
        // provider startup and do not establish that an as-yet unknown process
        // read data before opening a network flow. Retain pre-flow Read events;
        // after FlowCoordinator publishes an exact process interest, preserve
        // every supported operation for that process.
        if (operation != FileActivityOperation.Read
            && !Volatile.Read(ref _interestedProcessIds).Contains(processId))
        {
            return;
        }

        if (!_callbackAdmission.ShouldAdmit(
                new RawFileActivityKey(processId, operation, path),
                DateTimeOffset.UtcNow))
        {
            return;
        }

        var item = new RawFileActivity(
            Interlocked.Increment(ref _sequence), timestampUtc, processId,
            processName ?? string.Empty, operation, path);
        if (!_staging.Writer.TryWrite(item))
        {
            RecordDrop("Bounded ETW staging buffer overflowed; events were dropped.");
        }
    }

    internal void StageForTest(int processId, string processName, string path, FileActivityOperation operation, DateTime timestamp)
    {
        EnsureStatusPublisher();
        Stage(processId, processName, path, operation, timestamp);
    }

    internal FileActivity? ProjectForTest(int processId, string processName, string path, FileActivityOperation operation, DateTimeOffset timestampUtc)
    {
        var resolved = _processIdentities.Resolve(processId, processName, timestampUtc, DateTimeOffset.UtcNow, _processResolver);
        return resolved is null ? null : Resolve(new RawFileActivity(Interlocked.Increment(ref _sequence), timestampUtc, processId, processName, operation, path), resolved);
    }

    internal IReadOnlyList<FileActivity> PromoteRawForTest(IEnumerable<RawFileActivity> events, IEnumerable<FileActivityProcessInterest> interests)
    {
        foreach (var item in events) BufferRaw(item);
        return UpdateProcessInterests(interests);
    }

    private async Task ProjectAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var item in _staging.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                BufferRaw(item);
            }
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
        }
    }

    private void BufferRaw(RawFileActivity item)
    {
        var promoted = default(FileActivity?);
        lock (_correlationSync)
        {
            var now = DateTimeOffset.UtcNow;
            CleanupRecentRaw(now, force: false);
            if (_processInterests.TryGetValue(item.ProcessId, out var interest))
            {
                if (item.TimestampUtc >= interest.Identity.StartTime && item.TimestampUtc <= now.AddSeconds(5))
                {
                    promoted = Resolve(item, interest);
                }
                else if (item.TimestampUtc < interest.Identity.StartTime)
                {
                    return;
                }
            }

            if (promoted is null)
            {
                AddRecentRaw(item);
                return;
            }
        }

        if (promoted is not null)
        {
            lock (_correlationSync)
            {
                AddPendingPromoted(promoted);
            }
        }
        PublishOutput(promoted);
    }

    private void DrainPendingPromoted(ProcessIdentity identity, List<FileActivity> promoted)
    {
        if (!_pendingPromotedByProcess.TryGetValue(identity, out var processEvents)) return;
        var node = processEvents.First;
        while (node is not null)
        {
            var next = node.Next;
            Interlocked.Increment(ref _pendingPromotionNodesVisited);
            promoted.Add(node.Value.Activity);
            RemovePendingPromoted(node.Value);
            node = next;
        }
    }

    private void AddPendingPromoted(FileActivity activity)
    {
        if (!_pendingPromotedByProcess.TryGetValue(activity.ProcessIdentity, out var processEvents))
        {
            processEvents = [];
            _pendingPromotedByProcess[activity.ProcessIdentity] = processEvents;
        }

        var buffered = new BufferedPromotedFileActivity(activity);
        buffered.GlobalNode = _pendingPromoted.AddLast(buffered);
        buffered.ProcessNode = processEvents.AddLast(buffered);
        while (_pendingPromoted.Count > _recentRawCapacity)
        {
            RemovePendingPromoted(_pendingPromoted.First!.Value);
            RecordDrop("Promoted file activity handoff reached its hard bound; events were dropped.");
        }
    }

    private void RemovePendingPromoted(BufferedPromotedFileActivity buffered)
    {
        if (buffered.GlobalNode is { List: not null }) _pendingPromoted.Remove(buffered.GlobalNode);
        if (_pendingPromotedByProcess.TryGetValue(buffered.Activity.ProcessIdentity, out var processEvents)
            && buffered.ProcessNode is { List: not null })
        {
            processEvents.Remove(buffered.ProcessNode);
            if (processEvents.Count == 0) _pendingPromotedByProcess.Remove(buffered.Activity.ProcessIdentity);
        }
    }

    private void PromoteForInterest(ResolvedProcessIdentity interest, DateTimeOffset observedAt, List<FileActivity> promoted)
    {
        if (!_recentRawByProcess.TryGetValue(interest.Identity.ProcessId, out var processEvents)) return;
        var node = processEvents.First;
        while (node is not null)
        {
            var next = node.Next;
            var buffered = node.Value;
            var item = buffered.Activity;
            RemoveRecentRaw(buffered);
            if (item.TimestampUtc >= interest.Identity.StartTime
                && item.TimestampUtc <= observedAt.AddSeconds(5))
            {
                var activity = Resolve(item, interest);
                if (activity is not null) promoted.Add(activity);
            }

            node = next;
        }
    }

    private void AddRecentRaw(RawFileActivity item)
    {
        var key = new RawFileActivityKey(item.ProcessId, item.Operation, item.Path);
        if (_recentRawByKey.TryGetValue(key, out var duplicate))
        {
            // Kernel FileIORead is emitted per I/O chunk. One newest event for
            // the same PID/path/operation preserves the useful pre-flow signal
            // without allowing a single file read to exhaust the per-PID cap.
            RemoveRecentRaw(duplicate);
        }

        if (_recentRawByProcess.TryGetValue(item.ProcessId, out var existingProcessEvents)
            && existingProcessEvents.Count >= _recentRawPerProcessCapacity)
        {
            RemoveRecentRaw(existingProcessEvents.First!.Value);
            RecordDrop($"Per-process recent ETW buffer for PID {item.ProcessId} reached its hard bound; events were dropped.");
        }

        if (_recentRaw.Count >= _recentRawCapacity)
        {
            RemoveRecentRaw(_recentRaw.First!.Value);
            RecordDrop("Global recent ETW buffer reached its hard bound; events were dropped.");
        }

        if (!_recentRawByProcess.TryGetValue(item.ProcessId, out var processEvents))
        {
            processEvents = [];
            _recentRawByProcess[item.ProcessId] = processEvents;
        }

        var buffered = new BufferedRawFileActivity(item);
        buffered.GlobalNode = _recentRaw.AddLast(buffered);
        buffered.ProcessNode = processEvents.AddLast(buffered);
        _recentRawByKey[key] = buffered;
        _recentRawPeak = Math.Max(_recentRawPeak, _recentRaw.Count);
        _recentRawPerProcessPeak = Math.Max(_recentRawPerProcessPeak, processEvents.Count);
    }

    private void CleanupRecentRaw(DateTimeOffset now, bool force)
    {
        if (!force && now < _nextRecentRawCleanupUtc) return;
        var cutoff = now - _recentRawRetention;
        var node = _recentRaw.First;
        while (node is not null)
        {
            var next = node.Next;
            if (node.Value.Activity.TimestampUtc < cutoff) RemoveRecentRaw(node.Value);
            node = next;
        }
        _nextRecentRawCleanupUtc = now + DefaultRecentRawCleanupInterval;
    }

    private void RemoveRecentRaw(BufferedRawFileActivity buffered)
    {
        var processId = buffered.Activity.ProcessId;
        var key = new RawFileActivityKey(processId, buffered.Activity.Operation, buffered.Activity.Path);
        if (buffered.GlobalNode is { List: not null }) _recentRaw.Remove(buffered.GlobalNode);
        if (_recentRawByProcess.TryGetValue(processId, out var processEvents)
            && buffered.ProcessNode is { List: not null })
        {
            processEvents.Remove(buffered.ProcessNode);
            if (processEvents.Count == 0) _recentRawByProcess.Remove(processId);
        }

        if (_recentRawByKey.TryGetValue(key, out var current) && ReferenceEquals(current, buffered))
        {
            _recentRawByKey.Remove(key);
        }
    }

    private static FileActivity? Resolve(RawFileActivity item, ResolvedProcessIdentity process)
    {
        try
        {
            return new FileActivity(
                item.Sequence, item.TimestampUtc, process.Identity, process.ProcessName,
                item.Operation, Path.GetFullPath(item.Path), Path.GetExtension(item.Path).ToLowerInvariant(),
                "Windows Kernel File I/O ETW", true);
        }
        catch (Exception exception) when (exception is ArgumentException or InvalidOperationException or Win32Exception or NotSupportedException)
        {
            return null;
        }
    }

    private void PublishOutput(FileActivity? activity)
    {
        if (activity is not null && !_output.Writer.TryWrite(activity))
        {
            RecordDrop("Bounded file activity output overflowed; events were dropped.");
        }
    }

    private void ProcessTrace(TraceEventSession session, CancellationToken cancellationToken)
    {
        try { session.Source.Process(); }
        catch (Exception exception) when (cancellationToken.IsCancellationRequested && exception is InvalidOperationException or ObjectDisposedException) { }
        catch (Exception exception) { SetStatus(FileSensorState.Failed, $"ETW processing failed ({exception.GetType().Name})."); }
    }

    private bool IsExcluded(string path) => _excludedRoots.Any(root =>
        path.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
        || string.Equals(path, root, StringComparison.OrdinalIgnoreCase));

    // Kernel FileIO includes a very high-volume stream from the OS and shared
    // installation trees.  These paths cannot provide useful user-file
    // evidence and are rejected with cheap ordinal checks before entering the
    // bounded raw buffer.  User profile, temp and application data files remain
    // eligible, including the synthetic pre-flow fixture.
    internal static bool IsLowValueSystemPath(string path, IEnumerable<string> systemRoots)
    {
        ArgumentNullException.ThrowIfNull(systemRoots);
        return IsLowValueSystemPathCore(path, NormalizeRoots(systemRoots));
    }

    private static bool IsLowValueSystemPathCore(string path, IReadOnlyList<string> normalizedSystemRoots)
    {
        string normalizedPath;
        try { normalizedPath = Path.GetFullPath(path); }
        catch (Exception exception) when (exception is ArgumentException or NotSupportedException or PathTooLongException)
        {
            return false;
        }

        return normalizedSystemRoots.Any(root => IsUnderNormalizedDirectoryRoot(normalizedPath, root));
    }

    private static string[] GetDefaultLowValueSystemRoots() => NormalizeRoots([
        Environment.GetFolderPath(Environment.SpecialFolder.Windows),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
        Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86)
    ]);

    private static string[] NormalizeRoots(IEnumerable<string> roots) => roots
        .Where(root => !string.IsNullOrWhiteSpace(root))
        .Select(Path.GetFullPath)
        .Select(Path.TrimEndingDirectorySeparator)
        .Distinct(StringComparer.OrdinalIgnoreCase)
        .ToArray();

    private static bool IsUnderNormalizedDirectoryRoot(string path, string normalizedRoot)
    {
        return string.Equals(path, normalizedRoot, StringComparison.OrdinalIgnoreCase)
            || path.StartsWith(normalizedRoot + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase)
            || (Path.AltDirectorySeparatorChar != Path.DirectorySeparatorChar
                && path.StartsWith(normalizedRoot + Path.AltDirectorySeparatorChar, StringComparison.OrdinalIgnoreCase));
    }

    private void RecordDrop(string detail)
    {
        Interlocked.Increment(ref _dropped);
        SetStatus(FileSensorState.OverflowDegraded, detail);
        _statusSignals.Writer.TryWrite(0);
    }

    private void CleanupFailedStart()
    {
        try { _session?.Stop(); } catch { }
        try { _session?.Dispose(); } catch { }
        if (_sessionLease is { } lease)
        {
            try
            {
                if (_ownershipManager.IsActive(lease.SessionName)) _ownershipManager.StopOwnedSession(lease);
                if (!_ownershipManager.IsActive(lease.SessionName)) _ownershipManager.Release(lease);
            }
            catch { }
        }

        _session = null;
        _sessionLease = null;
        _lifetime?.Dispose();
        _lifetime = null;
    }

    private void EnsureStatusPublisher()
    {
        lock (_sync) _statusPublisherTask ??= Task.Run(PublishStatusesAsync);
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
            if (status.State == lastPublished.State && status.DroppedEvents == lastPublished.DroppedEvents && string.Equals(status.Detail, lastPublished.Detail, StringComparison.Ordinal)) continue;
            var subscribers = StatusChanged;
            if (subscribers is not null)
            {
                foreach (EventHandler<FileSensorStatus> subscriber in subscribers.GetInvocationList())
                {
                    try { subscriber(this, status); } catch { }
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
            if (previous.State == state && string.Equals(previous.Detail, detail, StringComparison.Ordinal)) return;
            var status = new FileSensorStatus(state, Interlocked.Read(ref _dropped), detail, DateTimeOffset.UtcNow);
            if (ReferenceEquals(Interlocked.CompareExchange(ref _status, status, previous), previous))
            {
                _statusSignals.Writer.TryWrite(0);
                return;
            }
        }
    }

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

    public ResolvedProcessIdentity? Resolve(int processId, string processName, DateTimeOffset eventTimestampUtc, DateTimeOffset observedAtUtc, IProcessIdentityResolver resolver)
    {
        if (TryGet(processId, processName, eventTimestampUtc, observedAtUtc, out var cached)) return cached;
        var resolved = resolver.Resolve(processId);
        if (resolved is null || eventTimestampUtc < resolved.Identity.StartTime) return null;
        ObserveProcessStart(resolved, observedAtUtc);
        return resolved;
    }

    public bool TryGet(int processId, string processName, DateTimeOffset eventTimestampUtc, DateTimeOffset observedAtUtc, out ResolvedProcessIdentity? process)
    {
        lock (_sync)
        {
            CleanupExpired(observedAtUtc);
            if (_entries.TryGetValue(processId, out var cached))
            {
                if (!string.IsNullOrWhiteSpace(processName) && !string.Equals(processName, cached.Value.ProcessName, StringComparison.OrdinalIgnoreCase))
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
            while (_entries.Count > _capacity) Remove(_entries[_lru.First!.Value]);
        }
    }

    public void ObserveProcessStop(ProcessIdentity identity, DateTimeOffset stoppedAtUtc)
    {
        lock (_sync)
        {
            if (_entries.TryGetValue(identity.ProcessId, out var existing)
                && existing.Value.Identity == identity
                && existing.Value.Identity.StartTime <= stoppedAtUtc)
            {
                Remove(existing);
            }
        }
    }

    // Compatibility for legacy callers that only know a PID.  Without the
    // generation start time it is unsafe to remove anything: a delayed stop
    // for an older process could otherwise delete a newer PID generation.
    public void ObserveProcessStop(int processId, DateTimeOffset stoppedAtUtc)
    {
        _ = _capacity;
        _ = processId;
        _ = stoppedAtUtc;
    }

    private void CleanupExpired(DateTimeOffset observedAtUtc)
    {
        while (_lru.First is { } node && _entries[node.Value].ExpiresAtUtc <= observedAtUtc) Remove(_entries[node.Value]);
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

internal sealed class BufferedRawFileActivity(RawFileActivity activity)
{
    public RawFileActivity Activity { get; } = activity;
    public LinkedListNode<BufferedRawFileActivity>? GlobalNode { get; set; }
    public LinkedListNode<BufferedRawFileActivity>? ProcessNode { get; set; }
}

internal readonly record struct RawFileActivityKey(int ProcessId, FileActivityOperation Operation, string Path);

internal sealed class RawFileActivityKeyComparer : IEqualityComparer<RawFileActivityKey>
{
    public static RawFileActivityKeyComparer Instance { get; } = new();

    public bool Equals(RawFileActivityKey x, RawFileActivityKey y) =>
        x.ProcessId == y.ProcessId
        && x.Operation == y.Operation
        && string.Equals(x.Path, y.Path, StringComparison.OrdinalIgnoreCase);

    public int GetHashCode(RawFileActivityKey obj) => HashCode.Combine(
        obj.ProcessId,
        obj.Operation,
        StringComparer.OrdinalIgnoreCase.GetHashCode(obj.Path));
}

/// <summary>
/// Single-ETW-callback-thread coalescing cache. It prevents per-chunk events for
/// one file operation from filling the staging channel before the projector can
/// apply its longer-lived raw-history dedupe. Both its index and eviction queue
/// have the same hard bound.
/// </summary>
internal sealed class EtwCallbackAdmissionCache
{
    private readonly int _capacity;
    private readonly TimeSpan _window;
    private readonly Dictionary<RawFileActivityKey, DateTimeOffset> _entries = new(RawFileActivityKeyComparer.Instance);
    private readonly Queue<(RawFileActivityKey Key, DateTimeOffset ObservedAt)> _order = [];

    public EtwCallbackAdmissionCache(int capacity, TimeSpan window)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
        ArgumentOutOfRangeException.ThrowIfLessThanOrEqual(window, TimeSpan.Zero);
        _capacity = capacity;
        _window = window;
    }

    public int Count => _entries.Count;

    public bool ShouldAdmit(RawFileActivityKey key, DateTimeOffset observedAt)
    {
        Cleanup(observedAt);
        if (_entries.TryGetValue(key, out var previous) && observedAt - previous <= _window)
        {
            return false;
        }

        _entries[key] = observedAt;
        _order.Enqueue((key, observedAt));
        while (_order.Count > _capacity)
        {
            RemoveOldest();
        }

        return true;
    }

    private void Cleanup(DateTimeOffset observedAt)
    {
        while (_order.TryPeek(out var oldest) && observedAt - oldest.ObservedAt > _window)
        {
            RemoveOldest();
        }
    }

    private void RemoveOldest()
    {
        var oldest = _order.Dequeue();
        if (_entries.TryGetValue(oldest.Key, out var current) && current == oldest.ObservedAt)
        {
            _entries.Remove(oldest.Key);
        }
    }
}

internal sealed class BufferedPromotedFileActivity(FileActivity activity)
{
    public FileActivity Activity { get; } = activity;
    public LinkedListNode<BufferedPromotedFileActivity>? GlobalNode { get; set; }
    public LinkedListNode<BufferedPromotedFileActivity>? ProcessNode { get; set; }
}
