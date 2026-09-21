using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;

namespace RansomGuard.Service;

// Query-only identity verification. No injection, privilege enabling, suspension, or process-tree operations.
internal sealed class ScopedRuleVerifier : IDisposable
{
    private ProcessHandle? _process;
    private FileStream? _image;
    public ScopedProcessEvidence Evidence { get; private set; }
    private ScopedRuleVerifier(ScopedProcessEvidence evidence) => Evidence = evidence;
    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool OpenProcessToken(ProcessHandle process, uint access, out SafeAccessTokenHandle token);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string file, uint access, uint share, IntPtr security, uint mode, uint flags, IntPtr template);

    public static string UserSid(ProcessHandle process)
    {
        if (!OpenProcessToken(process, 0x0008, out var token)) throw new Win32Exception(Marshal.GetLastWin32Error());
        using (token)
        using (var identity = new WindowsIdentity(token.DangerousGetHandle()))
            return identity.User?.Value ?? throw new IOException("Process user SID unavailable.");
    }
    public static void CheckDirectory(string path)
    {
        if (!ScopedTrustPolicy.ExactLocalPath(path)) throw new IOException("Noncanonical local directory rejected.");
        FileSafety.NoReparse(path);
        if (!Directory.Exists(path)) throw new IOException("Required directory is missing.");
        using var handle = CreateFileW(path, 0, 7, IntPtr.Zero, 3, 0x02200000, IntPtr.Zero);
        if (handle.IsInvalid || !WinPaths.Equal(Native.FinalFilePath(handle), path)) throw new IOException("Directory resolution not verified.");
        FileSafety.NoReparse(path);
    }
    public static void CheckScopes(IEnumerable<string> roots, string stateRoot)
    {
        var forbidden = new[] { Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), stateRoot };
        foreach (string root in roots)
        {
            CheckDirectory(root);
            if (!ScopedTrustPolicy.NarrowRoot(root) || forbidden.Where(p => !string.IsNullOrWhiteSpace(p)).Any(p =>
                WinPaths.Equal(root, p) || WinPaths.Under(root, p) || WinPaths.Under(p, root)))
                throw new IOException("Scope overlaps system, program, or security-state directories.");
        }
    }
    private static void CheckEvidencePaths(RiskSignal risk)
    {
        foreach (var e in risk.Evidence)
        {
            if (!ScopedTrustPolicy.ExactLocalPath(e.Path)) throw new IOException("Event path is not explicit/canonical.");
            FileSafety.NoReparse(e.Path);
            string parent = Path.GetDirectoryName(e.Path) ?? throw new IOException("Missing event parent.");
            CheckDirectory(parent);
            if (File.Exists(e.Path))
            {
                using var handle = CreateFileW(e.Path, 0, 7, IntPtr.Zero, 3, 0x00200000, IntPtr.Zero);
                if (handle.IsInvalid || !WinPaths.Equal(Native.FinalFilePath(handle), e.Path)) throw new IOException("Event file path changed.");
            }
            else if (e.Kind == FileKind.Write) throw new IOException("Written file is no longer available for contextual checking.");
            if (e.Kind == FileKind.Rename)
            {
                if (e.DestinationPath is not string target) throw new IOException("ETW did not supply a verified rename destination.");
                FileSafety.NoReparse(target);
                CheckDirectory(Path.GetDirectoryName(target) ?? throw new IOException("Rename target missing."));
            }
        }
    }
    public static async Task<ScopedRuleVerifier> OpenAsync(RiskSignal risk, ImageEvidence diagnosticImage,
        IReadOnlyCollection<string> roots, string stateRoot, Func<string, string> disposition, CancellationToken token)
    {
        var result = new ScopedRuleVerifier(new(risk.Process, null, diagnosticImage, false, false, DateTime.UtcNow, "NotChecked"));
        try
        {
            if (risk.Process.Pid <= 4 || risk.Process.CreationFileTimeUtc <= 0) throw new IOException("Invalid process generation.");
            result._process = Native.OpenProcess(Native.Query | Native.Synchronize, false, risk.Process.Pid);
            if (Native.Identity(result._process, risk.Process.Pid) != risk.Process) throw new IOException("Process exited or PID reused.");
            if (!Native.IsProcessCritical(result._process, out var critical) || critical) throw new IOException("Critical/unknown process excluded from review preferences.");
            string path = Native.ImagePath(result._process) ?? throw new IOException("Live process image unavailable.");
            if (!WinPaths.Equal(path, risk.ImagePath)) throw new IOException("Live image differs from event image.");
            string sid = UserSid(result._process);
            FileSafety.NoReparse(path);
            result._image = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 128 * 1024, FileOptions.Asynchronous | FileOptions.SequentialScan);
            if (result._image.Length <= 0 || result._image.Length > 128L * 1024 * 1024) throw new IOException("Executable exceeds strict hashing budget (128 MiB).");
            if (!WinPaths.Equal(path, Native.FinalFilePath(result._image.SafeFileHandle))) throw new IOException("Executable path redirection.");
            using var deadline = CancellationTokenSource.CreateLinkedTokenSource(token);
            deadline.CancelAfter(TimeSpan.FromSeconds(5));
            string hash = Convert.ToHexString(await SHA256.HashDataAsync(result._image, deadline.Token));
            result._image.Position = 0;
            var signature = Authenticode.Check(result._image, path);
            var evidence = new ImageEvidence(path, hash, result._image.Length, "Hashed", signature,
                disposition(hash), DateTime.UtcNow, null);
            CheckScopes(roots, stateRoot);
            CheckEvidencePaths(risk);
            if (Native.Identity(result._process, risk.Process.Pid) != risk.Process || UserSid(result._process) != sid)
                throw new IOException("Process changed during verification.");
            // File-sharing lock and SAME process handle remain held until policy evaluation finishes.
            result.Evidence = new(risk.Process, sid, evidence, true, true, DateTime.UtcNow, null);
        }
        catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or Win32Exception or CryptographicException or OperationCanceledException or ArgumentException or System.Security.SecurityException)
        {
            result.Dispose();
            result.Evidence = new(risk.Process, null, diagnosticImage, false, false, DateTime.UtcNow, ex.GetType().Name + ": " + ex.Message);
        }
        return result;
    }
    public void Dispose() { _image?.Dispose(); _image = null; _process?.Dispose(); _process = null; }
}
