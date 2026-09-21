using System.Collections.Concurrent;
using System.ComponentModel;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using RansomGuard.Rollback;

sealed record PendingCreate(
    ulong Sequence,
    string OriginalPath,
    CreateDisposition Disposition,
    CreateTargetState PreTargetState,
    CreatePreservationAction PreservationAction,
    RollbackFileIdentity? PreIdentity);

sealed class CreateReconciliationTracker
{
    private const int MaxPending = 4096;
    private readonly ConcurrentDictionary<ulong, PendingCreate> _pending = new();

    public void Register(PendingCreate pending)
    {
        if (pending.Sequence == 0) throw new ArgumentOutOfRangeException(nameof(pending));
        if (_pending.Count >= MaxPending)
            throw new InvalidOperationException("Too many pending CREATE reconciliations.");
        if (!_pending.TryAdd(pending.Sequence, pending))
            throw new InvalidOperationException("Duplicate pending CREATE sequence.");
    }

    public bool TryGet(ulong sequence, out PendingCreate pending) =>
        _pending.TryGetValue(sequence, out pending!);

    public void Remove(ulong sequence) => _pending.TryRemove(sequence, out _);
}

static class FileIdentityReader
{
    private const uint FileReadAttributes = 0x00000080;
    private const uint ShareReadWriteDelete = 0x00000001 | 0x00000002 | 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileFlagBackupSemantics = 0x02000000;
    private const int FileIdInfo = 0x12;
    private const int FileIdInfoSize = 24;

    public static RollbackFileIdentity Read(string path)
    {
        using var handle = CreateFile(
            path,
            FileReadAttributes,
            ShareReadWriteDelete,
            IntPtr.Zero,
            OpenExisting,
            FileFlagBackupSemantics,
            IntPtr.Zero);

        if (handle.IsInvalid)
            throw new Win32Exception(Marshal.GetLastWin32Error(), "Cannot open target for FILE_ID_INFO: " + path);

        var buffer = Marshal.AllocHGlobal(FileIdInfoSize);
        try
        {
            if (!GetFileInformationByHandleEx(handle, FileIdInfo, buffer, FileIdInfoSize))
                throw new Win32Exception(Marshal.GetLastWin32Error(), "GetFileInformationByHandleEx(FileIdInfo) failed: " + path);

            var volume = unchecked((ulong)Marshal.ReadInt64(buffer, 0));
            var id = new byte[16];
            Marshal.Copy(IntPtr.Add(buffer, 8), id, 0, id.Length);
            if (id.All(b => b == 0))
                throw new InvalidDataException("Filesystem returned a zero 128-bit file ID: " + path);

            return new RollbackFileIdentity(volume, Convert.ToHexString(id));
        }
        finally
        {
            Marshal.FreeHGlobal(buffer);
        }
    }

    public static bool Same(RollbackFileIdentity left, RollbackFileIdentity right) =>
        left.VolumeSerialNumber == right.VolumeSerialNumber &&
        left.FileId128Hex.Equals(right.FileId128Hex, StringComparison.OrdinalIgnoreCase);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFile(
        string lpFileName,
        uint dwDesiredAccess,
        uint dwShareMode,
        IntPtr lpSecurityAttributes,
        uint dwCreationDisposition,
        uint dwFlagsAndAttributes,
        IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetFileInformationByHandleEx(
        SafeFileHandle hFile,
        int fileInformationClass,
        IntPtr lpFileInformation,
        int dwBufferSize);
}
