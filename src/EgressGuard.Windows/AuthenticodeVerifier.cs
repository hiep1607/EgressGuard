using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
namespace EgressGuard.Core;

public static class AuthenticodeVerifier
{
    private static readonly Guid GenericVerifyV2 = new("00AAC56B-CD44-11D0-8CC2-00C04FC295EE");

    public static SignatureVerificationStatus Verify(string filePath)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(filePath);
        if (!File.Exists(filePath))
        {
            return SignatureVerificationStatus.VerificationUnavailable;
        }

        var fileInfo = new WinTrustFileInfo(filePath);
        var fileInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustFileInfo>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPointer, fDeleteOld: false);
            var trustData = new WinTrustData(fileInfoPointer);
            var status = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref trustData);
            trustData.StateAction = WinTrustDataStateAction.Close;
            _ = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref trustData);
            var mapped = MapStatus(status);
            return mapped == SignatureVerificationStatus.Unsigned ? VerifyCatalog(filePath) : mapped;
        }
        catch (Exception exception) when (exception is ExternalException or UnauthorizedAccessException or IOException)
        {
            return SignatureVerificationStatus.VerificationUnavailable;
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustFileInfo>(fileInfoPointer);
            Marshal.FreeHGlobal(fileInfoPointer);
        }
    }

    public static SignatureVerificationStatus MapStatus(int status) => unchecked((uint)status) switch
    {
        0x00000000 => SignatureVerificationStatus.Valid,
        0x800B0100 => SignatureVerificationStatus.Unsigned, // TRUST_E_NOSIGNATURE
        0x80096010 or 0x80096004 => SignatureVerificationStatus.Invalid, // bad digest/signature
        0x800B0101 => SignatureVerificationStatus.Expired,
        0x800B010C => SignatureVerificationStatus.Revoked,
        0x800B0111 or 0x800B0004 or 0x800B0109 or 0x800B010A => SignatureVerificationStatus.Untrusted,
        0x80092013 or 0x800B010E => SignatureVerificationStatus.VerificationUnavailable,
        0x800B0001 or 0x800B0003 => SignatureVerificationStatus.Unknown,
        _ => SignatureVerificationStatus.Unknown
    };

    private static SignatureVerificationStatus VerifyCatalog(string filePath)
    {
        if (!CryptCATAdminAcquireContext2(out var catalogAdmin, IntPtr.Zero, "SHA256", IntPtr.Zero, 0))
        {
            return SignatureVerificationStatus.VerificationUnavailable;
        }

        try
        {
            using SafeFileHandle fileHandle = File.OpenHandle(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite | FileShare.Delete);
            uint hashLength = 0;
            _ = CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, fileHandle, ref hashLength, null, 0);
            if (hashLength == 0)
            {
                return SignatureVerificationStatus.VerificationUnavailable;
            }

            var hash = new byte[hashLength];
            if (!CryptCATAdminCalcHashFromFileHandle2(catalogAdmin, fileHandle, ref hashLength, hash, 0))
            {
                return SignatureVerificationStatus.VerificationUnavailable;
            }

            var previousCatalog = IntPtr.Zero;
            var catalogContext = CryptCATAdminEnumCatalogFromHash(catalogAdmin, hash, hashLength, 0, ref previousCatalog);
            if (catalogContext == IntPtr.Zero)
            {
                return SignatureVerificationStatus.Unsigned;
            }

            try
            {
                var catalogDetails = new CatalogInfo { StructSize = (uint)Marshal.SizeOf<CatalogInfo>() };
                if (!CryptCATCatalogInfoFromContext(catalogContext, ref catalogDetails, 0))
                {
                    return SignatureVerificationStatus.VerificationUnavailable;
                }

                return VerifyCatalogMember(filePath, fileHandle, catalogAdmin, catalogContext, catalogDetails.CatalogFilePath, hash);
            }
            finally
            {
                _ = CryptCATAdminReleaseCatalogContext(catalogAdmin, catalogContext, 0);
            }
        }
        finally
        {
            _ = CryptCATAdminReleaseContext(catalogAdmin, 0);
        }
    }

    private static SignatureVerificationStatus VerifyCatalogMember(
        string filePath,
        SafeFileHandle fileHandle,
        IntPtr catalogAdmin,
        IntPtr catalogContext,
        string catalogPath,
        byte[] hash)
    {
        var hashPointer = Marshal.AllocHGlobal(hash.Length);
        var catalogInfoPointer = Marshal.AllocHGlobal(Marshal.SizeOf<WinTrustCatalogInfo>());
        try
        {
            Marshal.Copy(hash, 0, hashPointer, hash.Length);
            var catalogInfo = new WinTrustCatalogInfo(
                catalogPath,
                Convert.ToHexString(hash),
                filePath,
                fileHandle.DangerousGetHandle(),
                hashPointer,
                (uint)hash.Length,
                catalogContext,
                catalogAdmin);
            Marshal.StructureToPtr(catalogInfo, catalogInfoPointer, fDeleteOld: false);
            var trustData = new WinTrustData(catalogInfoPointer, unionChoice: 2);
            var status = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref trustData);
            trustData.StateAction = WinTrustDataStateAction.Close;
            _ = WinVerifyTrust(IntPtr.Zero, GenericVerifyV2, ref trustData);
            return MapStatus(status);
        }
        finally
        {
            Marshal.DestroyStructure<WinTrustCatalogInfo>(catalogInfoPointer);
            Marshal.FreeHGlobal(catalogInfoPointer);
            Marshal.FreeHGlobal(hashPointer);
        }
    }

    [DllImport("wintrust.dll", ExactSpelling = true, PreserveSig = true, SetLastError = false)]
    private static extern int WinVerifyTrust(
        IntPtr windowHandle,
        [MarshalAs(UnmanagedType.LPStruct)] Guid actionId,
        ref WinTrustData trustData);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminAcquireContext2(out IntPtr catalogAdmin, IntPtr subsystem, string hashAlgorithm, IntPtr strongHashPolicy, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminCalcHashFromFileHandle2(IntPtr catalogAdmin, SafeFileHandle fileHandle, ref uint hashLength, byte[]? hash, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    private static extern IntPtr CryptCATAdminEnumCatalogFromHash(IntPtr catalogAdmin, byte[] hash, uint hashLength, uint flags, ref IntPtr previousCatalog);

    [DllImport("wintrust.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATCatalogInfoFromContext(IntPtr catalogContext, ref CatalogInfo catalogInfo, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseCatalogContext(IntPtr catalogAdmin, IntPtr catalogContext, uint flags);

    [DllImport("wintrust.dll", SetLastError = true)]
    [return: MarshalAs(UnmanagedType.Bool)]
    private static extern bool CryptCATAdminReleaseContext(IntPtr catalogAdmin, uint flags);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustFileInfo
    {
        internal WinTrustFileInfo(string filePath)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustFileInfo>();
            FilePath = filePath;
        }

        internal uint StructSize;

        [MarshalAs(UnmanagedType.LPWStr)]
        internal string FilePath;

        internal IntPtr FileHandle;
        internal IntPtr KnownSubject;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct WinTrustData
    {
        internal WinTrustData(IntPtr unionInfo, uint unionChoice = 1)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustData>();
            PolicyCallbackData = IntPtr.Zero;
            SipClientData = IntPtr.Zero;
            UiChoice = 2; // WTD_UI_NONE
            RevocationChecks = 0; // Avoid network revocation checks in the sensor path.
            UnionChoice = unionChoice;
            FileInfo = unionInfo;
            StateAction = WinTrustDataStateAction.Verify;
            StateData = IntPtr.Zero;
            UrlReference = IntPtr.Zero;
            ProviderFlags = 0x00001000; // WTD_CACHE_ONLY_URL_RETRIEVAL
            UiContext = 0;
        }

        internal uint StructSize;
        internal IntPtr PolicyCallbackData;
        internal IntPtr SipClientData;
        internal uint UiChoice;
        internal uint RevocationChecks;
        internal uint UnionChoice;
        internal IntPtr FileInfo;
        internal WinTrustDataStateAction StateAction;
        internal IntPtr StateData;
        internal IntPtr UrlReference;
        internal uint ProviderFlags;
        internal uint UiContext;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct CatalogInfo
    {
        internal uint StructSize;

        [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
        internal string CatalogFilePath;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private sealed class WinTrustCatalogInfo
    {
        internal WinTrustCatalogInfo(string catalogPath, string memberTag, string memberPath, IntPtr memberFile, IntPtr hash, uint hashLength, IntPtr catalogContext, IntPtr catalogAdmin)
        {
            StructSize = (uint)Marshal.SizeOf<WinTrustCatalogInfo>();
            CatalogFilePath = catalogPath;
            MemberTag = memberTag;
            MemberFilePath = memberPath;
            MemberFile = memberFile;
            CalculatedFileHash = hash;
            CalculatedFileHashLength = hashLength;
            CatalogContext = catalogContext;
            CatalogAdmin = catalogAdmin;
        }

        internal uint StructSize;
        internal uint CatalogVersion;
        [MarshalAs(UnmanagedType.LPWStr)] internal string CatalogFilePath;
        [MarshalAs(UnmanagedType.LPWStr)] internal string MemberTag;
        [MarshalAs(UnmanagedType.LPWStr)] internal string MemberFilePath;
        internal IntPtr MemberFile;
        internal IntPtr CalculatedFileHash;
        internal uint CalculatedFileHashLength;
        internal IntPtr CatalogContext;
        internal IntPtr CatalogAdmin;
    }

    private enum WinTrustDataStateAction : uint
    {
        Verify = 1,
        Close = 2
    }
}
