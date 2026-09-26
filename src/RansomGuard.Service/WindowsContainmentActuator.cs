using System.ComponentModel;
using System.Runtime.InteropServices;
using RansomGuard.Core;

namespace RansomGuard.Service;

internal sealed class WindowsContainmentActuationPlatform : IContainmentProcessActuationPlatform
{
    private readonly Func<string?, string?> _freshImageSha256;

    internal WindowsContainmentActuationPlatform(Func<string?, string?> freshImageSha256)
    {
        _freshImageSha256 = freshImageSha256 ?? throw new ArgumentNullException(nameof(freshImageSha256));
    }

    public IContainmentProcessActuationLease Open(ProcessKey expectedProcess)
    {
        if (expectedProcess.Pid <= 4 || expectedProcess.CreationFileTimeUtc <= 0)
            throw new InvalidOperationException("BoundProcessInvalid");

        var handle = Native.OpenProcess(Native.Query | Native.Synchronize, false, expectedProcess.Pid);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, "OpenProcess query lease failed.");
        }

        try
        {
            var live = Native.Identity(handle, expectedProcess.Pid);
            if (live is null || live.Value != expectedProcess)
                throw new InvalidOperationException("ProcessIdentityChanged");

            var path = Native.ImagePath(handle);
            var imageSha256 = _freshImageSha256(path);
            var criticalKnown = Native.IsProcessCritical(handle, out var critical);

            return new WindowsContainmentProcessActuationLease(
                handle,
                expectedProcess,
                path,
                imageSha256,
                criticalKnown,
                critical);
        }
        catch
        {
            handle.Dispose();
            throw;
        }
    }
}

internal sealed class WindowsContainmentProcessActuationLease : IContainmentProcessActuationLease
{
    private const int ErrorNoMoreFiles = 18;
    private const int ErrorInvalidParameter = 87;

    private readonly ProcessHandle _processHandle;
    private bool _disposed;

    public ProcessKey Process { get; }
    public string? ImagePath { get; }
    public string? ImageSha256 { get; }
    public bool CriticalStateKnown { get; }
    public bool IsCritical { get; }

    public WindowsContainmentProcessActuationLease(
        ProcessHandle processHandle,
        ProcessKey process,
        string? imagePath,
        string? imageSha256,
        bool criticalStateKnown,
        bool isCritical)
    {
        _processHandle = processHandle ?? throw new ArgumentNullException(nameof(processHandle));
        if (_processHandle.IsInvalid)
            throw new ArgumentException("Process handle is invalid.", nameof(processHandle));

        Process = process;
        ImagePath = imagePath;
        ImageSha256 = imageSha256;
        CriticalStateKnown = criticalStateKnown;
        IsCritical = isCritical;
    }

    public IReadOnlyList<ContainmentActuationThreadKey> EnumerateThreads(
        int maxThreads,
        CancellationToken cancellationToken)
    {
        ThrowIfDisposed();
        if (maxThreads is < 1 or > 1024)
            throw new ArgumentOutOfRangeException(nameof(maxThreads));
        EnsureProcessIdentity();

        using var snapshot = Native.CreateToolhelp32Snapshot(Native.SnapThread, 0);
        if (snapshot.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "CreateToolhelp32Snapshot(THREAD) failed.");

        var entry = new ThreadEntry32 { Size = (uint)Marshal.SizeOf<ThreadEntry32>() };
        var result = new List<ContainmentActuationThreadKey>();
        var have = Native.Thread32First(snapshot, ref entry);
        if (!have)
        {
            var error = Marshal.GetLastWin32Error();
            if (error != ErrorNoMoreFiles)
                throw new Win32Exception(error, "Thread32First failed.");
            return result;
        }

        while (true)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (entry.OwnerProcessId == (uint)Process.Pid)
            {
                var thread = TryReadThreadIdentity(entry.ThreadId, out var diagnostic);
                if (thread is not null)
                {
                    result.Add(thread.Value);
                    if (result.Count > maxThreads)
                        throw new IOException("Containment thread enumeration exceeded the qualified bound.");
                }
                else if (!string.Equals(diagnostic, "ThreadExited", StringComparison.Ordinal))
                {
                    throw new IOException("Unable to verify target thread identity: " + diagnostic);
                }
            }

            entry.Size = (uint)Marshal.SizeOf<ThreadEntry32>();
            if (!Native.Thread32Next(snapshot, ref entry))
            {
                var error = Marshal.GetLastWin32Error();
                if (error != ErrorNoMoreFiles)
                    throw new Win32Exception(error, "Thread32Next failed.");
                break;
            }
        }

        EnsureProcessIdentity();
        return result
            .Distinct()
            .OrderBy(x => x.ThreadId)
            .ThenBy(x => x.CreationFileTimeUtc)
            .ToArray();
    }

    public bool TrySuspendThread(
        ContainmentActuationThreadKey thread,
        out string diagnostic)
    {
        ThrowIfDisposed();
        if (!TryOpenExactThread(thread, Native.ThreadSuspendResume | Native.ThreadQueryLimitedInformation, out var handle, out diagnostic))
            return false;

        using (handle)
        {
            var previous = Native.SuspendThread(handle);
            if (previous == uint.MaxValue)
            {
                diagnostic = "SuspendThread:" + Marshal.GetLastWin32Error();
                return false;
            }

            if (!MatchesExactThread(handle, thread))
            {
                _ = Native.ResumeThread(handle);
                diagnostic = "ThreadIdentityChangedAfterSuspend";
                return false;
            }

            diagnostic = "";
            return true;
        }
    }

    public bool TryResumeThread(
        ContainmentActuationThreadKey thread,
        out string diagnostic)
    {
        ThrowIfDisposed();
        if (!TryOpenExactThread(thread, Native.ThreadSuspendResume | Native.ThreadQueryLimitedInformation, out var handle, out diagnostic))
            return false;

        using (handle)
        {
            var previous = Native.ResumeThread(handle);
            if (previous == uint.MaxValue)
            {
                diagnostic = "ResumeThread:" + Marshal.GetLastWin32Error();
                return false;
            }
            if (previous == 0)
            {
                diagnostic = "OwnedSuspendIncrementMissing";
                return false;
            }

            diagnostic = "";
            return true;
        }
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        _processHandle.Dispose();
    }

    private ContainmentActuationThreadKey? TryReadThreadIdentity(
        uint threadId,
        out string diagnostic)
    {
        if (!TryOpenThread(threadId, Native.ThreadQueryLimitedInformation, out var handle, out diagnostic))
            return null;

        using (handle)
        {
            if (Native.GetProcessIdOfThread(handle) != (uint)Process.Pid)
            {
                diagnostic = "ThreadOwnerChanged";
                return null;
            }
            if (!Native.GetThreadTimes(handle, out var created, out _, out _, out _))
            {
                diagnostic = "GetThreadTimes:" + Marshal.GetLastWin32Error();
                return null;
            }
            if (created <= 0)
            {
                diagnostic = "ThreadCreationTimeInvalid";
                return null;
            }

            diagnostic = "";
            return new ContainmentActuationThreadKey(threadId, created);
        }
    }

    private bool TryOpenExactThread(
        ContainmentActuationThreadKey thread,
        uint rights,
        out ThreadHandle handle,
        out string diagnostic)
    {
        handle = Native.OpenThread(rights, false, thread.ThreadId);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            diagnostic = error == ErrorInvalidParameter
                ? "ThreadExited"
                : "OpenThread:" + error;
            return false;
        }

        if (!MatchesExactThread(handle, thread))
        {
            handle.Dispose();
            diagnostic = "ThreadIdentityChanged";
            return false;
        }

        diagnostic = "";
        return true;
    }

    private bool TryOpenThread(
        uint threadId,
        uint rights,
        out ThreadHandle handle,
        out string diagnostic)
    {
        handle = Native.OpenThread(rights, false, threadId);
        if (!handle.IsInvalid)
        {
            diagnostic = "";
            return true;
        }

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        diagnostic = error == ErrorInvalidParameter
            ? "ThreadExited"
            : "OpenThread:" + error;
        return false;
    }

    private bool MatchesExactThread(
        ThreadHandle handle,
        ContainmentActuationThreadKey expected)
    {
        if (handle.IsInvalid)
            return false;
        if (Native.GetProcessIdOfThread(handle) != (uint)Process.Pid)
            return false;
        if (!Native.GetThreadTimes(handle, out var created, out _, out _, out _))
            return false;
        return created == expected.CreationFileTimeUtc;
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
            throw new ObjectDisposedException(nameof(WindowsContainmentProcessActuationLease));
    }
}
