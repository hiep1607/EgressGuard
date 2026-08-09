using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace EgressGuard.Core;

internal static class NativeMethods
{
    internal const uint Th32csSnapProcess = 0x00000002;
    internal const int ErrorInsufficientBuffer = 122;
    internal const int AfInet = 2;
    internal const int AfInet6 = 23;
    internal const int TcpTableOwnerPidAll = 5;
    internal const int UdpTableOwnerPid = 1;

    [DllImport("kernel32.dll", SetLastError = true)]
    internal static extern SafeSnapshotHandle CreateToolhelp32Snapshot(uint flags, uint processId);

    [DllImport("kernel32.dll", EntryPoint = "Process32FirstW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32First(SafeSnapshotHandle snapshot, ref ProcessEntry32 entry);

    [DllImport("kernel32.dll", EntryPoint = "Process32NextW", SetLastError = true, CharSet = CharSet.Unicode)]
    [return: MarshalAs(UnmanagedType.Bool)]
    internal static extern bool Process32Next(SafeSnapshotHandle snapshot, ref ProcessEntry32 entry);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedTcpTable(
        IntPtr table,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    internal static extern uint GetExtendedUdpTable(
        IntPtr table,
        ref int size,
        [MarshalAs(UnmanagedType.Bool)] bool order,
        int addressFamily,
        int tableClass,
        uint reserved);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ProcessEntry32
    {
        internal uint Size;
        internal uint Usage;
        internal uint ProcessId;
        internal UIntPtr DefaultHeapId;
        internal uint ModuleId;
        internal uint Threads;
        internal uint ParentProcessId;
        internal int BasePriority;
        internal uint Flags;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string ExecutableFile;
    }

    internal sealed class SafeSnapshotHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        internal SafeSnapshotHandle() : base(ownsHandle: true)
        {
        }

        protected override bool ReleaseHandle() => CloseHandle(handle);
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CloseHandle(IntPtr handle);
}
