using System.ComponentModel;
using System.Diagnostics;
using System.Threading.Channels;
using EgressGuard.Core;
using Microsoft.Diagnostics.Tracing.Parsers;
using Microsoft.Diagnostics.Tracing.Session;

namespace EgressGuard.Windows;

public sealed class EtwFileActivitySensor : IFileActivitySensor
{
    public const int DefaultCapacity = 4096;
    private readonly Channel<RawFileEvent> _staging;
    private readonly Channel<FileActivity> _output;
    private readonly string[] _excludedRoots;
    private readonly object _sync = new();
    private TraceEventSession? _session;
    private Task? _traceTask;
    private Task? _projectionTask;
    private CancellationTokenSource? _lifetime;
    private long _sequence;
    private long _dropped;
    private FileSensorStatus _status = new(FileSensorState.Stopped, 0, null, DateTimeOffset.UtcNow);

    public EtwFileActivitySensor(IEnumerable<string>? excludedRoots = null, int capacity = DefaultCapacity)
    {
        ArgumentOutOfRangeException.ThrowIfLessThan(capacity, 1);
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
    }

    public FileSensorStatus Status => Volatile.Read(ref _status);
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

            SetStatus(FileSensorState.Starting, null);
            _lifetime = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
            try
            {
                var sessionName = $"EgressGuard.FileActivity.v1-{Environment.ProcessId}";
                _session = new TraceEventSession(sessionName, null) { StopOnDispose = true };
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
            _lifetime?.Dispose();
            _lifetime = null;
            _traceTask = null;
            _projectionTask = null;
            _output.Writer.TryComplete();
        }

        SetStatus(FileSensorState.Stopped, null);
    }

    public IAsyncEnumerable<FileActivity> ReadAllAsync(CancellationToken cancellationToken) =>
        _output.Reader.ReadAllAsync(cancellationToken);

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
        if (processId <= 0 || string.IsNullOrWhiteSpace(path) || !Path.IsPathFullyQualified(path) || IsExcluded(path))
        {
            return;
        }

        var item = new RawFileEvent(processId, processName, path, operation, timestamp.ToUniversalTime());
        if (!_staging.Writer.TryWrite(item))
        {
            Interlocked.Increment(ref _dropped);
            SetStatus(FileSensorState.OverflowDegraded, "Bounded ETW staging buffer overflowed; events were dropped.", notifyAsynchronously: true);
        }
    }

    internal void StageForTest(int processId, string processName, string path, FileActivityOperation operation, DateTime timestamp) =>
        Stage(processId, processName, path, operation, timestamp);

    private async Task ProjectAsync(CancellationToken cancellationToken)
    {
        try
        {
            await foreach (var item in _staging.Reader.ReadAllAsync(cancellationToken).ConfigureAwait(false))
            {
                var activity = Resolve(item);
                if (activity is not null && !_output.Writer.TryWrite(activity))
                {
                    Interlocked.Increment(ref _dropped);
                    SetStatus(FileSensorState.OverflowDegraded, "Bounded file activity output overflowed; events were dropped.");
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
            using var process = Process.GetProcessById(item.ProcessId);
            var start = process.StartTime.ToUniversalTime();
            return new FileActivity(
                Interlocked.Increment(ref _sequence), item.TimestampUtc,
                new ProcessIdentity(item.ProcessId, start),
                string.IsNullOrWhiteSpace(item.ProcessName) ? process.ProcessName : item.ProcessName,
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

    private void CleanupFailedStart()
    {
        _session?.Dispose();
        _session = null;
        _lifetime?.Dispose();
        _lifetime = null;
    }

    private void SetStatus(FileSensorState state, string? detail, bool notifyAsynchronously = false)
    {
        var status = new FileSensorStatus(state, Interlocked.Read(ref _dropped), detail, DateTimeOffset.UtcNow);
        Volatile.Write(ref _status, status);
        if (notifyAsynchronously)
        {
            _ = Task.Run(() => StatusChanged?.Invoke(this, status));
        }
        else
        {
            StatusChanged?.Invoke(this, status);
        }
    }

    private sealed record RawFileEvent(int ProcessId, string ProcessName, string Path, FileActivityOperation Operation, DateTimeOffset TimestampUtc);
}
