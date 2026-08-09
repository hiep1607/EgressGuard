using System.Collections.Concurrent;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace EgressGuard.Core;

public interface IExecutableMetadataProvider
{
    ExecutableMetadata? GetMetadata(string executablePath);
}

public sealed class ExecutableMetadataProvider : IExecutableMetadataProvider
{
    private readonly ConcurrentDictionary<CacheKey, ExecutableMetadata> _cache = new();

    public ExecutableMetadata? GetMetadata(string executablePath)
    {
        try
        {
            var file = new FileInfo(executablePath);
            if (!file.Exists)
            {
                return null;
            }

            var key = new CacheKey(file.FullName, file.Length, file.LastWriteTimeUtc);
            return _cache.GetOrAdd(key, static cacheKey => CreateMetadata(cacheKey));
        }
        catch (Exception exception) when (exception is UnauthorizedAccessException or IOException or NotSupportedException)
        {
            return null;
        }
    }

    private static ExecutableMetadata CreateMetadata(CacheKey key)
    {
        using var stream = new FileStream(
            key.Path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete);
        var hash = Convert.ToHexString(SHA256.HashData(stream));
        var signatureStatus = AuthenticodeVerifier.Verify(key.Path);
        var publisher = ReadPublisherMetadata(key.Path);
        return new ExecutableMetadata(
            hash,
            signatureStatus,
            publisher,
            key.FileSize,
            new DateTimeOffset(key.LastWriteTimeUtc, TimeSpan.Zero));
    }

    private static string? ReadPublisherMetadata(string path)
    {
        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            return certificate.Subject;
        }
        catch (Exception exception) when (exception is CryptographicException or InvalidOperationException)
        {
            return null;
        }
    }

    private readonly record struct CacheKey(string Path, long FileSize, DateTime LastWriteTimeUtc);
}
