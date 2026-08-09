using System.Buffers.Binary;
using System.Text.Json;

namespace EgressGuard.Protocol;

public static class MessageFraming
{
    public static async Task WriteAsync(Stream stream, MessageEnvelope message, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        ArgumentNullException.ThrowIfNull(message);
        var payload = JsonSerializer.SerializeToUtf8Bytes(message, JsonDefaults.Options);
        if (payload.Length > ProtocolConstants.MaximumMessageBytes)
        {
            throw new InvalidDataException($"Message exceeds {ProtocolConstants.MaximumMessageBytes} bytes.");
        }

        var header = new byte[sizeof(int)];
        BinaryPrimitives.WriteInt32LittleEndian(header, payload.Length);
        await stream.WriteAsync(header, cancellationToken).ConfigureAwait(false);
        await stream.WriteAsync(payload, cancellationToken).ConfigureAwait(false);
        await stream.FlushAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task<MessageEnvelope?> ReadAsync(Stream stream, CancellationToken cancellationToken)
    {
        ArgumentNullException.ThrowIfNull(stream);
        var header = new byte[sizeof(int)];
        var headerBytes = await ReadAtMostAsync(stream, header, cancellationToken).ConfigureAwait(false);
        if (headerBytes == 0)
        {
            return null;
        }

        if (headerBytes != header.Length)
        {
            throw new EndOfStreamException("Message length header was truncated.");
        }

        var length = BinaryPrimitives.ReadInt32LittleEndian(header);
        if (length is <= 0 or > ProtocolConstants.MaximumMessageBytes)
        {
            throw new InvalidDataException($"Invalid message length: {length}.");
        }

        var payload = new byte[length];
        var read = await ReadAtMostAsync(stream, payload, cancellationToken).ConfigureAwait(false);
        if (read != length)
        {
            throw new EndOfStreamException("Message payload was truncated.");
        }

        var envelope = JsonSerializer.Deserialize<MessageEnvelope>(payload, JsonDefaults.Options)
            ?? throw new InvalidDataException("Message JSON was empty.");
        if (envelope.Version != ProtocolConstants.Version || string.IsNullOrWhiteSpace(envelope.Type))
        {
            throw new InvalidDataException("Unsupported protocol version or missing message type.");
        }

        return envelope;
    }

    private static async Task<int> ReadAtMostAsync(Stream stream, Memory<byte> buffer, CancellationToken cancellationToken)
    {
        var total = 0;
        while (total < buffer.Length)
        {
            var count = await stream.ReadAsync(buffer[total..], cancellationToken).ConfigureAwait(false);
            if (count == 0)
            {
                break;
            }

            total += count;
        }

        return total;
    }
}
