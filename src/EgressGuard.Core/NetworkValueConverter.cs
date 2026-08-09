using System.Net;

namespace EgressGuard.Core;

public static class NetworkValueConverter
{
    public static int DecodePort(uint nativePort) =>
        (ushort)IPAddress.NetworkToHostOrder(unchecked((short)nativePort));

    public static IPAddress DecodeIPv4(uint nativeAddress) =>
        new(BitConverter.GetBytes(nativeAddress));

    public static string FormatEndpoint(NetworkEndpoint? endpoint)
    {
        if (endpoint is null)
        {
            return "*:*";
        }

        return endpoint.Address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6
            ? $"[{endpoint.Address}]:{endpoint.Port}"
            : $"{endpoint.Address}:{endpoint.Port}";
    }
}
