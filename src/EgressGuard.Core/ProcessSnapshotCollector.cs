using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

namespace EgressGuard.Core;

public sealed class ProcessSnapshotCollector
{
    private readonly IExecutableMetadataProvider _metadataProvider;

    public ProcessSnapshotCollector(IExecutableMetadataProvider? metadataProvider = null)
    {
        _metadataProvider = metadataProvider ?? new ExecutableMetadataProvider();
    }

    public IReadOnlyDictionary<int, ProcessSnapshot> Capture()
    {
        var parentProcessIds = CaptureParentProcessIds();
        var snapshots = new Dictionary<int, ProcessSnapshot>();

        foreach (var process in Process.GetProcesses())
        {
            using (process)
            {
                TryAddSnapshot(process, parentProcessIds, snapshots);
            }
        }

        return snapshots;
    }

    private void TryAddSnapshot(
        Process process,
        Dictionary<int, int> parentProcessIds,
        IDictionary<int, ProcessSnapshot> snapshots)
    {
        try
        {
            var startTime = new DateTimeOffset(process.StartTime);
            var name = TryRead(() => process.ProcessName) ?? $"pid-{process.Id}";
            var executablePath = TryRead(() => process.MainModule?.FileName);
            parentProcessIds.TryGetValue(process.Id, out var parentProcessId);
            var metadata = executablePath is null ? null : _metadataProvider.GetMetadata(executablePath);

            snapshots[process.Id] = new ProcessSnapshot(
                new ProcessIdentity(process.Id, startTime),
                name,
                executablePath,
                parentProcessId == 0 ? null : parentProcessId,
                metadata);
        }
        catch (Exception exception) when (IsExpectedProcessRace(exception))
        {
            // A process can exit or become inaccessible between enumeration and inspection.
        }
    }

    private static T? TryRead<T>(Func<T?> read) where T : class
    {
        try
        {
            return read();
        }
        catch (Exception exception) when (IsExpectedProcessRace(exception))
        {
            return null;
        }
    }

    private static bool IsExpectedProcessRace(Exception exception) =>
        exception is InvalidOperationException
            or Win32Exception
            or NotSupportedException
            or UnauthorizedAccessException;

    private static Dictionary<int, int> CaptureParentProcessIds()
    {
        var parents = new Dictionary<int, int>();
        using var snapshot = NativeMethods.CreateToolhelp32Snapshot(NativeMethods.Th32csSnapProcess, 0);
        if (snapshot.IsInvalid)
        {
            return parents;
        }

        var entry = new NativeMethods.ProcessEntry32
        {
            Size = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32>()
        };

        if (!NativeMethods.Process32First(snapshot, ref entry))
        {
            return parents;
        }

        do
        {
            parents[checked((int)entry.ProcessId)] = checked((int)entry.ParentProcessId);
            entry.Size = (uint)Marshal.SizeOf<NativeMethods.ProcessEntry32>();
        }
        while (NativeMethods.Process32Next(snapshot, ref entry));

        return parents;
    }
}
