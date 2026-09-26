using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Windows is required.");
    return 2;
}

if (args.Length != 5 || args[0] is not ("--malicious" or "--malicious-exit" or "--benign"))
{
    Console.Error.WriteLine("Usage: --malicious|--malicious-exit|--benign TARGET HEARTBEAT READY RESULT");
    return 3;
}

var mode = args[0][2..];
var target = Path.GetFullPath(args[1]);
var heartbeat = Path.GetFullPath(args[2]);
var ready = Path.GetFullPath(args[3]);
var result = Path.GetFullPath(args[4]);

foreach (var path in new[] { heartbeat, ready, result })
{
    var parent = Path.GetDirectoryName(path);
    if (string.IsNullOrWhiteSpace(parent))
        throw new IOException("Output path has no parent: " + path);
    Directory.CreateDirectory(parent);
    if (File.Exists(path))
        File.Delete(path);
}

if (!File.Exists(target))
    throw new FileNotFoundException("Fixture target does not exist.", target);

using var current = Process.GetCurrentProcess();
var creationFileTimeUtc = current.StartTime.ToUniversalTime().ToFileTimeUtc();
var startedUtc = DateTime.UtcNow;
WriteJsonDurable(ready, new
{
    schema = 1,
    mode,
    pid = Environment.ProcessId,
    creationFileTimeUtc,
    startedUtc,
    target
});

var timer = Stopwatch.StartNew();
var lastTickMs = timer.Elapsed.TotalMilliseconds;
double maxGapMs = 0;
var heartbeatCount = 0;
var protectedWrites = 0;

if (mode is "malicious" or "malicious-exit")
{
    var payload = RandomNumberGenerator.GetBytes(4096);
    using var stream = new FileStream(target, FileMode.Open, FileAccess.Write,
        FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.WriteThrough);
    stream.Position = 0;
    stream.SetLength(payload.Length);
    stream.Write(payload);
    stream.Flush(true);
    protectedWrites = 1;
    if (mode == "malicious-exit")
        return 0;
}
else
{
    var payload = Encoding.UTF8.GetBytes(new string('B', 4096));
    using var stream = new FileStream(target, FileMode.Open, FileAccess.Write,
        FileShare.ReadWrite | FileShare.Delete, 4096, FileOptions.WriteThrough);
    for (var i = 0; i < 200; i++)
    {
        stream.Position = 0;
        stream.Write(payload);
        stream.Flush();
        protectedWrites++;
    }
    stream.Flush(true);
}

var heartbeatDuration = mode == "malicious"
    ? TimeSpan.FromSeconds(8)
    : TimeSpan.FromSeconds(4);
var deadline = timer.Elapsed + heartbeatDuration;

while (timer.Elapsed < deadline)
{
    var nowMs = timer.Elapsed.TotalMilliseconds;
    if (heartbeatCount != 0)
        maxGapMs = Math.Max(maxGapMs, nowMs - lastTickMs);
    lastTickMs = nowMs;
    heartbeatCount++;

    File.WriteAllText(
        heartbeat,
        $"{heartbeatCount}|{DateTime.UtcNow:O}",
        new UTF8Encoding(false));

    Thread.Sleep(50);
}

var completedUtc = DateTime.UtcNow;
var sha256 = Convert.ToHexString(SHA256.HashData(File.ReadAllBytes(target)));
WriteJsonDurable(result, new
{
    schema = 1,
    mode,
    pid = Environment.ProcessId,
    creationFileTimeUtc,
    startedUtc,
    completedUtc,
    elapsedMs = timer.Elapsed.TotalMilliseconds,
    maxHeartbeatGapMs = maxGapMs,
    heartbeatCount,
    protectedWrites,
    target,
    targetSha256 = sha256
});

return 0;

static void WriteJsonDurable(string path, object value)
{
    var temp = path + "." + Guid.NewGuid().ToString("N") + ".tmp";
    try
    {
        using (var stream = new FileStream(
                   temp,
                   FileMode.CreateNew,
                   FileAccess.Write,
                   FileShare.None,
                   4096,
                   FileOptions.WriteThrough))
        {
            JsonSerializer.Serialize(stream, value, new JsonSerializerOptions { WriteIndented = true });
            stream.Flush(true);
        }
        File.Move(temp, path, overwrite: true);
    }
    finally
    {
        if (File.Exists(temp))
            File.Delete(temp);
    }
}
