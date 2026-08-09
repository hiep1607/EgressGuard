using System.ComponentModel;
using System.Net;
using System.Runtime.InteropServices;

namespace EgressGuard.Core;

public sealed class NativeNetworkTableReader
{
    public static IReadOnlyList<NetworkConnection> Capture()
    {
        var detectedAt = DateTimeOffset.Now;
        var connections = new List<NetworkConnection>();
        connections.AddRange(ReadTcpIPv4(detectedAt));
        connections.AddRange(ReadTcpIPv6(detectedAt));
        connections.AddRange(ReadUdpIPv4(detectedAt));
        connections.AddRange(ReadUdpIPv6(detectedAt));
        return connections;
    }

    private static IEnumerable<NetworkConnection> ReadTcpIPv4(DateTimeOffset detectedAt) =>
        ReadTable<NativeTcpRowV4>(
            isTcp: true,
            NativeMethods.AfInet,
            NativeMethods.TcpTableOwnerPidAll,
            row => new NetworkConnection(
                checked((int)row.ProcessId),
                TransportProtocol.Tcp,
                IpVersion.IPv4,
                new NetworkEndpoint(NetworkValueConverter.DecodeIPv4(row.LocalAddress), NetworkValueConverter.DecodePort(row.LocalPort)),
                new NetworkEndpoint(NetworkValueConverter.DecodeIPv4(row.RemoteAddress), NetworkValueConverter.DecodePort(row.RemotePort)),
                TcpStateName(row.State),
                detectedAt));

    private static IEnumerable<NetworkConnection> ReadTcpIPv6(DateTimeOffset detectedAt) =>
        ReadTable<NativeTcpRowV6>(
            isTcp: true,
            NativeMethods.AfInet6,
            NativeMethods.TcpTableOwnerPidAll,
            row => new NetworkConnection(
                checked((int)row.ProcessId),
                TransportProtocol.Tcp,
                IpVersion.IPv6,
                new NetworkEndpoint(new IPAddress(row.LocalAddress, row.LocalScopeId), NetworkValueConverter.DecodePort(row.LocalPort)),
                new NetworkEndpoint(new IPAddress(row.RemoteAddress, row.RemoteScopeId), NetworkValueConverter.DecodePort(row.RemotePort)),
                TcpStateName(row.State),
                detectedAt));

    private static IEnumerable<NetworkConnection> ReadUdpIPv4(DateTimeOffset detectedAt) =>
        ReadTable<NativeUdpRowV4>(
            isTcp: false,
            NativeMethods.AfInet,
            NativeMethods.UdpTableOwnerPid,
            row => new NetworkConnection(
                checked((int)row.ProcessId),
                TransportProtocol.Udp,
                IpVersion.IPv4,
                new NetworkEndpoint(NetworkValueConverter.DecodeIPv4(row.LocalAddress), NetworkValueConverter.DecodePort(row.LocalPort)),
                RemoteEndpoint: null,
                State: null,
                detectedAt));

    private static IEnumerable<NetworkConnection> ReadUdpIPv6(DateTimeOffset detectedAt) =>
        ReadTable<NativeUdpRowV6>(
            isTcp: false,
            NativeMethods.AfInet6,
            NativeMethods.UdpTableOwnerPid,
            row => new NetworkConnection(
                checked((int)row.ProcessId),
                TransportProtocol.Udp,
                IpVersion.IPv6,
                new NetworkEndpoint(new IPAddress(row.LocalAddress, row.LocalScopeId), NetworkValueConverter.DecodePort(row.LocalPort)),
                RemoteEndpoint: null,
                State: null,
                detectedAt));

    private static IReadOnlyList<NetworkConnection> ReadTable<TRow>(
        bool isTcp,
        int addressFamily,
        int tableClass,
        Func<TRow, NetworkConnection> map) where TRow : struct
    {
        var size = 0;
        var firstResult = CallNative(isTcp, IntPtr.Zero, ref size, addressFamily, tableClass);
        if (firstResult != NativeMethods.ErrorInsufficientBuffer && firstResult != 0)
        {
            throw new Win32Exception(checked((int)firstResult));
        }

        if (size < sizeof(int))
        {
            return Array.Empty<NetworkConnection>();
        }

        var buffer = Marshal.AllocHGlobal(size);
        try
        {
            var result = CallNative(isTcp, buffer, ref size, addressFamily, tableClass);
            if (result != 0)
            {
                throw new Win32Exception(checked((int)result));
            }

            return ParseRows(buffer, size, map);
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    private static List<NetworkConnection> ParseRows<TRow>(
        IntPtr buffer,
        int bufferSize,
        Func<TRow, NetworkConnection> map) where TRow : struct
    {
        var count = Marshal.ReadInt32(buffer);
        var rowSize = Marshal.SizeOf<TRow>();
        var maximumRows = (bufferSize - sizeof(int)) / rowSize;
        if (count < 0 || count > maximumRows)
        {
            throw new InvalidDataException("The Windows network table returned an invalid row count.");
        }

        var result = new List<NetworkConnection>(count);
        var rowPointer = IntPtr.Add(buffer, sizeof(int));
        for (var index = 0; index < count; index++)
        {
            var nativeRow = Marshal.PtrToStructure<TRow>(rowPointer);
            result.Add(map(nativeRow));
            rowPointer = IntPtr.Add(rowPointer, rowSize);
        }

        return result;
    }

    private static uint CallNative(bool isTcp, IntPtr buffer, ref int size, int addressFamily, int tableClass) =>
        isTcp
            ? NativeMethods.GetExtendedTcpTable(buffer, ref size, order: true, addressFamily, tableClass, 0)
            : NativeMethods.GetExtendedUdpTable(buffer, ref size, order: true, addressFamily, tableClass, 0);

    private static string TcpStateName(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN-SENT",
        4 => "SYN-RECEIVED",
        5 => "ESTABLISHED",
        6 => "FIN-WAIT-1",
        7 => "FIN-WAIT-2",
        8 => "CLOSE-WAIT",
        9 => "CLOSING",
        10 => "LAST-ACK",
        11 => "TIME-WAIT",
        12 => "DELETE-TCB",
        _ => $"UNKNOWN-{state}"
    };

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeTcpRowV4
    {
        internal readonly uint State;
        internal readonly uint LocalAddress;
        internal readonly uint LocalPort;
        internal readonly uint RemoteAddress;
        internal readonly uint RemotePort;
        internal readonly uint ProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeTcpRowV6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] LocalAddress;
        internal uint LocalScopeId;
        internal uint LocalPort;

        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] RemoteAddress;
        internal uint RemoteScopeId;
        internal uint RemotePort;
        internal uint State;
        internal uint ProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private readonly struct NativeUdpRowV4
    {
        internal readonly uint LocalAddress;
        internal readonly uint LocalPort;
        internal readonly uint ProcessId;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct NativeUdpRowV6
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        internal byte[] LocalAddress;
        internal uint LocalScopeId;
        internal uint LocalPort;
        internal uint ProcessId;
    }
}
