using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal sealed class ProcessStateChangeHandle : SafeHandleZeroOrMinusOneIsInvalid
{
    internal ProcessStateChangeHandle(IntPtr existing) : base(true)
    {
        SetHandle(existing);
    }

    protected override bool ReleaseHandle() => Native.CloseHandle(handle);
}

internal sealed class WindowsProcessStateChangeLease : IDisposable
{
    private const uint ProcessSetInformation = 0x0200;
    private const uint ProcessStateAllAccess = 0x001F0001;
    private const int ProcessStateChangeSuspend = 0;
    private const int ProcessStateChangeResume = 1;

    private readonly ProcessHandle _processHandle;
    private readonly ProcessStateChangeHandle _stateChangeHandle;
    private bool _suspended;
    private bool _disposed;

    internal ProcessKey Process { get; }
    internal string? ImagePath { get; }
    internal string? ImageSha256 { get; }
    internal FileIdentityEvidence? ImageFileIdentity { get; }
    internal bool CriticalStateKnown { get; }
    internal bool IsCritical { get; }
    internal bool IsSuspended => _suspended;

    private WindowsProcessStateChangeLease(
        ProcessHandle processHandle,
        ProcessStateChangeHandle stateChangeHandle,
        ProcessKey process,
        string? imagePath,
        string? imageSha256,
        FileIdentityEvidence? imageFileIdentity,
        bool criticalStateKnown,
        bool isCritical)
    {
        _processHandle = processHandle;
        _stateChangeHandle = stateChangeHandle;
        Process = process;
        ImagePath = imagePath;
        ImageSha256 = imageSha256;
        ImageFileIdentity = imageFileIdentity;
        CriticalStateKnown = criticalStateKnown;
        IsCritical = isCritical;
    }

    internal static bool IsSupported()
    {
        if (!OperatingSystem.IsWindows())
            return false;
        if (!NativeLibrary.TryLoad("ntdll.dll", out var library))
            return false;

        try
        {
            return NativeLibrary.TryGetExport(library, "NtCreateProcessStateChange", out _) &&
                   NativeLibrary.TryGetExport(library, "NtChangeProcessState", out _);
        }
        finally
        {
            NativeLibrary.Free(library);
        }
    }

    internal static WindowsProcessStateChangeLease Open(
        ProcessKey expectedProcess,
        Func<string?, (string? Sha256, FileIdentityEvidence? FileIdentity)> freshImageIdentity)
    {
        ArgumentNullException.ThrowIfNull(freshImageIdentity);

        if (!IsSupported())
            throw new PlatformNotSupportedException(
                "Windows process state-change API is unavailable; crash-safe production containment is not supported.");

        if (expectedProcess.Pid <= 4 || expectedProcess.CreationFileTimeUtc <= 0)
            throw new InvalidOperationException("BoundProcessInvalid");

        var process = Native.OpenProcess(
            Native.Query | Native.Synchronize | Native.SuspendResume | ProcessSetInformation,
            false,
            expectedProcess.Pid);
        if (process.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            process.Dispose();
            throw new Win32Exception(error, "OpenProcess state-change lease failed.");
        }

        try
        {
            var live = Native.Identity(process, expectedProcess.Pid);
            if (live is null || live.Value != expectedProcess)
                throw new InvalidOperationException("ProcessIdentityChanged");

            var path = Native.ImagePath(process);
            var imageIdentity = freshImageIdentity(path);
            var imageSha256 = imageIdentity.Sha256;
            var imageFileIdentity = imageIdentity.FileIdentity;
            var criticalKnown = Native.IsProcessCritical(process, out var critical);

            var createStatus = NtCreateProcessStateChange(
                out var rawStateChange,
                ProcessStateAllAccess,
                IntPtr.Zero,
                process,
                0);
            if (createStatus < 0 || rawStateChange == IntPtr.Zero)
            {
                if (rawStateChange != IntPtr.Zero)
                    _ = Native.CloseHandle(rawStateChange);
                throw NtStatusFailure("NtCreateProcessStateChange", createStatus);
            }

            return new(
                process,
                new ProcessStateChangeHandle(rawStateChange),
                expectedProcess,
                path,
                imageSha256,
                imageFileIdentity,
                criticalKnown,
                critical);
        }
        catch
        {
            process.Dispose();
            throw;
        }
    }

    internal void Suspend()
    {
        ThrowIfDisposed();
        if (_suspended)
            return;

        EnsureProcessIdentity();

        var status = NtChangeProcessState(
            _stateChangeHandle,
            _processHandle,
            ProcessStateChangeSuspend,
            IntPtr.Zero,
            UIntPtr.Zero,
            0);
        if (status < 0)
            throw NtStatusFailure("NtChangeProcessState(Suspend)", status);

        _suspended = true;
    }

    internal void Resume()
    {
        ThrowIfDisposed();
        if (!_suspended)
            return;

        EnsureProcessIdentity();

        var status = NtChangeProcessState(
            _stateChangeHandle,
            _processHandle,
            ProcessStateChangeResume,
            IntPtr.Zero,
            UIntPtr.Zero,
            0);
        if (status < 0)
            throw NtStatusFailure("NtChangeProcessState(Resume)", status);

        _suspended = false;
    }

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;

        // The state-change handle is deliberately released before the process
        // handle. Windows owns rollback of any still-active state change when
        // the final state-change object reference is destroyed.
        _stateChangeHandle.Dispose();
        _processHandle.Dispose();
        _suspended = false;
    }

    private void EnsureProcessIdentity()
    {
        var live = Native.Identity(_processHandle, Process.Pid);
        if (live is null || live.Value != Process)
            throw new IOException("Containment target process identity changed.");
    }

    private void ThrowIfDisposed()
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(WindowsProcessStateChangeLease));
    }

    private static IOException NtStatusFailure(string operation, int status) =>
        new($"{operation} failed with NTSTATUS 0x{unchecked((uint)status):X8}.");

    [DllImport("ntdll.dll")]
    private static extern int NtCreateProcessStateChange(
        out IntPtr processStateChangeHandle,
        uint desiredAccess,
        IntPtr objectAttributes,
        ProcessHandle processHandle,
        uint reserved);

    [DllImport("ntdll.dll")]
    private static extern int NtChangeProcessState(
        ProcessStateChangeHandle processStateChangeHandle,
        ProcessHandle processHandle,
        int stateChangeType,
        IntPtr extendedInformation,
        UIntPtr extendedInformationLength,
        uint reserved);
}
