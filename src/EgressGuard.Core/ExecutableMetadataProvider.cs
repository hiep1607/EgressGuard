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
        var signature = InspectEmbeddedSignature(key.Path);
        return new ExecutableMetadata(
            hash,
            signature.IsPresent,
            signature.Publisher,
            key.FileSize,
            new DateTimeOffset(key.LastWriteTimeUtc, TimeSpan.Zero));
    }

    private static (bool IsPresent, string? Publisher) InspectEmbeddedSignature(string path)
    {
        try
        {
            using var certificate = X509Certificate.CreateFromSignedFile(path);
            return (true, certificate.Subject);
        }
        catch (CryptographicException)
        {
            return (false, null);
        }
    }

    private readonly record struct CacheKey(string Path, long FileSize, DateTime LastWriteTimeUtc);
}
