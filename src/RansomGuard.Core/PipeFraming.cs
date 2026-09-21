using System.Buffers.Binary;
using System.Text.Json;
namespace RansomGuard.Core;

// Length-prefixed JSON: multiple frames read together never discard the next frame.
public static class PipeFraming
{
    public const int MaxFrameBytes = 1024 * 1024;
    public static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web)
    { PropertyNameCaseInsensitive = true, MaxDepth = 20 };
    public static async Task WriteAsync<T>(Stream stream, T value, CancellationToken token)
    {
        byte[] body = JsonSerializer.SerializeToUtf8Bytes(value, Json);
        if (body.Length is <= 0 or > MaxFrameBytes) throw new IOException("Frame size rejected.");
        byte[] prefix = new byte[4];
        BinaryPrimitives.WriteInt32LittleEndian(prefix, body.Length);
        await stream.WriteAsync(prefix, token).ConfigureAwait(false);
        await stream.WriteAsync(body, token).ConfigureAwait(false);
        await stream.FlushAsync(token).ConfigureAwait(false);
    }
    public static async Task<T> ReadAsync<T>(Stream stream, CancellationToken token, int limit = MaxFrameBytes)
    {
        byte[] prefix = new byte[4];
        await stream.ReadExactlyAsync(prefix, token).ConfigureAwait(false);
        int count = BinaryPrimitives.ReadInt32LittleEndian(prefix);
        if (count <= 0 || count > Math.Min(limit, MaxFrameBytes)) throw new IOException("Frame size rejected before allocation.");
        byte[] body = new byte[count];
        await stream.ReadExactlyAsync(body, token).ConfigureAwait(false);
        return JsonSerializer.Deserialize<T>(body, Json) ?? throw new IOException("Null JSON frame.");
    }
}
