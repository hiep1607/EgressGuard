using System.Globalization;
using System.IO;
using System.Text;
using EgressGuard.Core;

namespace EgressGuard.UI;

internal static class FileActivityHistoryCsvExporter
{
    public const int MaximumRows = 5_000;
    private static readonly UTF8Encoding Utf8WithBom = new(encoderShouldEmitUTF8Identifier: true);

    public static async Task WriteAsync(
        string path,
        IReadOnlyList<FileCorrelationHistoryItem> items,
        CancellationToken cancellationToken)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(path);
        ArgumentNullException.ThrowIfNull(items);
        if (items.Count > MaximumRows)
            throw new ArgumentOutOfRangeException(nameof(items));
        await using var stream = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 16 * 1024, useAsync: true);
        await using var writer = new StreamWriter(stream, Utf8WithBom, 16 * 1024, leaveOpen: false);
        await writer.WriteLineAsync("Time,Process,Activity,File,Extension,Relevance,Time distance,Reason,Connection code".AsMemory(), cancellationToken).ConfigureAwait(false);
        foreach (var item in items)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var fields = new[]
            {
                item.ActivityTimestampUtc.ToLocalTime().ToString("G", CultureInfo.CurrentCulture),
                item.ProcessName,
                OperationLabel(item.Operation),
                item.DisplayPath,
                item.Extension,
                item.Confidence.ToString(),
                FormatTimeDistance(item.TimeDeltaSeconds),
                item.Reason,
                item.FlowId
            };
            await writer.WriteLineAsync(string.Join(',', fields.Select(Escape)).AsMemory(), cancellationToken).ConfigureAwait(false);
        }

        await writer.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    internal static string Escape(string? value)
    {
        var safe = NeutralizeFormula(value ?? string.Empty);
        return safe.IndexOfAny([',', '"', '\r', '\n']) >= 0
            ? $"\"{safe.Replace("\"", "\"\"", StringComparison.Ordinal)}\""
            : safe;
    }

    internal static string NeutralizeFormula(string value) => value.Length > 0 && value[0] is '=' or '+' or '-' or '@' or '\t' or '\r' or '\n'
        ? "'" + value
        : value;

    private static string OperationLabel(FileActivityOperation operation) => operation switch
    {
        FileActivityOperation.OpenCreate => "Open / create",
        FileActivityOperation.Read => "Read",
        FileActivityOperation.Write => "Write",
        FileActivityOperation.Rename => "Rename",
        FileActivityOperation.Delete => "Delete",
        _ => "Unknown"
    };

    private static string FormatTimeDistance(double seconds)
    {
        var absolute = Math.Abs(seconds);
        return absolute < 0.0005
            ? "At connection time"
            : $"{absolute:0.###} s {(seconds < 0 ? "before" : "after")} connection";
    }
}
