using Microsoft.Win32.SafeHandles;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.InteropServices;

internal static class Program
{
    private const uint GenericRead = 0x80000000;
    private const uint GenericWrite = 0x40000000;
    private const uint ShareRead = 0x00000001;
    private const uint ShareWrite = 0x00000002;
    private const uint ShareDelete = 0x00000004;
    private const uint OpenExisting = 3;
    private const uint FileAttributeNormal = 0x00000080;
    private const uint FileFlagWriteThrough = 0x80000000;

    private const uint FsctlSetSparse = 0x000900C4;
    private const uint FsctlFileLevelTrim = 0x00098208;
    private const uint FsctlOffloadRead = 0x00094264;
    private const uint FsctlOffloadWrite = 0x00098268;
    private const uint FsctlDuplicateExtentsToFile = 0x00098344;
    private const uint FsctlDuplicateExtentsToFileEx = 0x000983E8;

    private static int Main(string[] args)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.Error.WriteLine("RansomGuard FSCTL qualification probe is Windows-only.");
            return 2;
        }

        if (args.Length == 0)
        {
            Console.Error.WriteLine("Use: set-sparse | file-trim | duplicate-extents | duplicate-extents-ex | offload-copy");
            return 2;
        }

        try
        {
            var command = args[0].ToLowerInvariant();
            var options = Parse(args.Skip(1).ToArray());
            switch (command)
            {
                case "set-sparse":
                    SetSparse(Require(options, "--file"), Require(options, "--result"));
                    break;
                case "file-trim":
                    FileTrim(
                        Require(options, "--file"),
                        RequireInt64(options, "--offset"),
                        RequireInt64(options, "--length"),
                        Require(options, "--result"));
                    break;
                case "duplicate-extents":
                    DuplicateExtents(
                        Require(options, "--source"),
                        Require(options, "--target"),
                        RequireInt64(options, "--length"),
                        Require(options, "--result"),
                        false);
                    break;
                case "duplicate-extents-ex":
                    DuplicateExtents(
                        Require(options, "--source"),
                        Require(options, "--target"),
                        RequireInt64(options, "--length"),
                        Require(options, "--result"),
                        true);
                    break;
                case "offload-copy":
                    OffloadCopy(
                        Require(options, "--source"),
                        Require(options, "--target"),
                        RequireInt64(options, "--length"),
                        Require(options, "--result"));
                    break;
                default:
                    throw new ArgumentException($"Unknown command '{args[0]}'.");
            }

            return 0;
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine("FSCTL QUALIFICATION PROBE ERROR");
            Console.Error.WriteLine(ex.ToString());
            return 20;
        }
    }

    private static Dictionary<string, string> Parse(string[] args)
    {
        var result = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i < args.Length; i += 2)
        {
            if (i + 1 >= args.Length || !args[i].StartsWith("--", StringComparison.Ordinal))
                throw new ArgumentException("Options must be supplied as --name value pairs.");
            result[args[i]] = args[i + 1];
        }
        return result;
    }

    private static string Require(Dictionary<string, string> options, string name)
    {
        if (!options.TryGetValue(name, out var value) || string.IsNullOrWhiteSpace(value))
            throw new ArgumentException($"Required option '{name}' is missing.");
        return value;
    }

    private static long RequireInt64(Dictionary<string, string> options, string name)
    {
        var value = Require(options, name);
        if (!long.TryParse(value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var parsed) || parsed < 0)
            throw new ArgumentException($"Option '{name}' must be a non-negative Int64.");
        return parsed;
    }

    private static SafeFileHandle OpenFile(string path, uint access)
    {
        var handle = Native.CreateFileW(
            path,
            access,
            ShareRead | ShareWrite | ShareDelete,
            IntPtr.Zero,
            OpenExisting,
            FileAttributeNormal | FileFlagWriteThrough,
            IntPtr.Zero);
        if (!handle.IsInvalid)
            return handle;

        var error = Marshal.GetLastWin32Error();
        handle.Dispose();
        throw new Win32Exception(error, $"CreateFileW failed for '{path}'.");
    }

    private static void SetSparse(string filePath, string resultPath)
    {
        try
        {
            using var file = OpenFile(filePath, GenericRead | GenericWrite);
            var input = Marshal.AllocHGlobal(1);
            try
            {
                Marshal.WriteByte(input, 1);
                if (!Native.DeviceIoControl(file, FsctlSetSparse, input, 1, IntPtr.Zero, 0, out _, IntPtr.Zero))
                {
                    WriteResult(resultPath, "win32-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return;
                }
            }
            finally
            {
                Marshal.FreeHGlobal(input);
            }

            _ = Native.FlushFileBuffers(file);
            WriteResult(resultPath, "allowed");
        }
        catch (Win32Exception ex)
        {
            WriteResult(resultPath, "open-error:" + ex.NativeErrorCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void FileTrim(string filePath, long offset, long length, string resultPath)
    {
        try
        {
            using var file = OpenFile(filePath, GenericRead | GenericWrite);
            var inputValue = new FileLevelTrimInput
            {
                Key = 0,
                NumRanges = 1,
                Offset = checked((ulong)offset),
                Length = checked((ulong)length)
            };
            var inputSize = Marshal.SizeOf<FileLevelTrimInput>();
            var input = Marshal.AllocHGlobal(inputSize);
            var output = Marshal.AllocHGlobal(sizeof(uint));
            try
            {
                Marshal.StructureToPtr(inputValue, input, false);
                Marshal.WriteInt32(output, 0);
                if (!Native.DeviceIoControl(
                        file,
                        FsctlFileLevelTrim,
                        input,
                        checked((uint)inputSize),
                        output,
                        sizeof(uint),
                        out _,
                        IntPtr.Zero))
                {
                    WriteResult(resultPath, "win32-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return;
                }

                var processed = unchecked((uint)Marshal.ReadInt32(output));
                WriteResult(resultPath, "allowed:" + processed.ToString(CultureInfo.InvariantCulture));
            }
            finally
            {
                Marshal.FreeHGlobal(output);
                Marshal.FreeHGlobal(input);
            }
        }
        catch (Win32Exception ex)
        {
            WriteResult(resultPath, "open-error:" + ex.NativeErrorCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void DuplicateExtents(string sourcePath, string targetPath, long length, string resultPath, bool extended)
    {
        try
        {
            using var source = OpenFile(sourcePath, GenericRead);
            using var target = OpenFile(targetPath, GenericRead | GenericWrite);
            if (extended)
            {
                var data = new DuplicateExtentsDataEx
                {
                    StructureSize = UIntPtr.Zero,
                    FileHandle = source.DangerousGetHandle(),
                    SourceFileOffset = 0,
                    TargetFileOffset = 0,
                    ByteCount = length,
                    Flags = 0
                };
                var size = Marshal.SizeOf<DuplicateExtentsDataEx>();
                data.StructureSize = checked((UIntPtr)(uint)size);
                if (!InvokeStructIoctl(target, FsctlDuplicateExtentsToFileEx, data, size))
                {
                    WriteResult(resultPath, "win32-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return;
                }
            }
            else
            {
                var data = new DuplicateExtentsData
                {
                    FileHandle = source.DangerousGetHandle(),
                    SourceFileOffset = 0,
                    TargetFileOffset = 0,
                    ByteCount = length
                };
                var size = Marshal.SizeOf<DuplicateExtentsData>();
                if (!InvokeStructIoctl(target, FsctlDuplicateExtentsToFile, data, size))
                {
                    WriteResult(resultPath, "win32-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                    return;
                }
            }

            if (!Native.FlushFileBuffers(target))
            {
                WriteResult(resultPath, "flush-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                return;
            }

            WriteResult(resultPath, "allowed");
        }
        catch (Win32Exception ex)
        {
            WriteResult(resultPath, "open-error:" + ex.NativeErrorCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static void OffloadCopy(string sourcePath, string targetPath, long length, string resultPath)
    {
        try
        {
            using var source = OpenFile(sourcePath, GenericRead);
            using var target = OpenFile(targetPath, GenericRead | GenericWrite);

            var readInput = new OffloadReadInput
            {
                Size = checked((uint)Marshal.SizeOf<OffloadReadInput>()),
                Flags = 0,
                TokenTimeToLive = 0,
                Reserved = 0,
                FileOffset = 0,
                CopyLength = checked((ulong)length)
            };
            var readOutput = new OffloadReadOutput
            {
                Size = checked((uint)Marshal.SizeOf<OffloadReadOutput>()),
                Flags = 0,
                TransferLength = 0,
                Token = new byte[512]
            };

            if (!InvokeStructIoctl(source, FsctlOffloadRead, readInput, ref readOutput))
            {
                WriteResult(resultPath, "read-win32-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                return;
            }
            if (readOutput.TransferLength == 0)
            {
                WriteResult(resultPath, "read-zero-transfer");
                return;
            }

            var copyLength = Math.Min(checked((ulong)length), readOutput.TransferLength);
            var writeInput = new OffloadWriteInput
            {
                Size = checked((uint)Marshal.SizeOf<OffloadWriteInput>()),
                Flags = 0,
                FileOffset = 0,
                CopyLength = copyLength,
                TransferOffset = 0,
                Token = readOutput.Token
            };
            var writeOutput = new OffloadWriteOutput
            {
                Size = checked((uint)Marshal.SizeOf<OffloadWriteOutput>()),
                Flags = 0,
                LengthWritten = 0
            };

            if (!InvokeStructIoctl(target, FsctlOffloadWrite, writeInput, ref writeOutput))
            {
                WriteResult(resultPath, "write-win32-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                return;
            }
            if (!Native.FlushFileBuffers(target))
            {
                WriteResult(resultPath, "flush-error:" + Marshal.GetLastWin32Error().ToString(CultureInfo.InvariantCulture));
                return;
            }

            WriteResult(
                resultPath,
                "allowed:" +
                writeOutput.LengthWritten.ToString(CultureInfo.InvariantCulture) +
                ":" +
                readOutput.TransferLength.ToString(CultureInfo.InvariantCulture));
        }
        catch (Win32Exception ex)
        {
            WriteResult(resultPath, "open-error:" + ex.NativeErrorCode.ToString(CultureInfo.InvariantCulture));
        }
    }

    private static bool InvokeStructIoctl<T>(SafeFileHandle file, uint code, T inputValue, int inputSize)
        where T : struct
    {
        var input = Marshal.AllocHGlobal(inputSize);
        try
        {
            Marshal.StructureToPtr(inputValue, input, false);
            return Native.DeviceIoControl(
                file,
                code,
                input,
                checked((uint)inputSize),
                IntPtr.Zero,
                0,
                out _,
                IntPtr.Zero);
        }
        finally
        {
            Marshal.FreeHGlobal(input);
        }
    }

    private static bool InvokeStructIoctl<TIn, TOut>(SafeFileHandle file, uint code, TIn inputValue, ref TOut outputValue)
        where TIn : struct
        where TOut : struct
    {
        var inputSize = Marshal.SizeOf<TIn>();
        var outputSize = Marshal.SizeOf<TOut>();
        var input = Marshal.AllocHGlobal(inputSize);
        var output = Marshal.AllocHGlobal(outputSize);
        try
        {
            Marshal.StructureToPtr(inputValue, input, false);
            Marshal.StructureToPtr(outputValue, output, false);
            var ok = Native.DeviceIoControl(
                file,
                code,
                input,
                checked((uint)inputSize),
                output,
                checked((uint)outputSize),
                out _,
                IntPtr.Zero);
            if (ok)
                outputValue = Marshal.PtrToStructure<TOut>(output);
            return ok;
        }
        finally
        {
            Marshal.DestroyStructure<TOut>(output);
            Marshal.DestroyStructure<TIn>(input);
            Marshal.FreeHGlobal(output);
            Marshal.FreeHGlobal(input);
        }
    }

    private static void WriteResult(string path, string value)
    {
        var full = Path.GetFullPath(path);
        var parent = Path.GetDirectoryName(full);
        if (!string.IsNullOrWhiteSpace(parent))
            Directory.CreateDirectory(parent);
        File.WriteAllText(full, value);
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct FileLevelTrimInput
    {
        public uint Key;
        public uint NumRanges;
        public ulong Offset;
        public ulong Length;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DuplicateExtentsData
    {
        public IntPtr FileHandle;
        public long SourceFileOffset;
        public long TargetFileOffset;
        public long ByteCount;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct DuplicateExtentsDataEx
    {
        public UIntPtr StructureSize;
        public IntPtr FileHandle;
        public long SourceFileOffset;
        public long TargetFileOffset;
        public long ByteCount;
        public uint Flags;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OffloadReadInput
    {
        public uint Size;
        public uint Flags;
        public uint TokenTimeToLive;
        public uint Reserved;
        public ulong FileOffset;
        public ulong CopyLength;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OffloadReadOutput
    {
        public uint Size;
        public uint Flags;
        public ulong TransferLength;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] Token;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OffloadWriteInput
    {
        public uint Size;
        public uint Flags;
        public ulong FileOffset;
        public ulong CopyLength;
        public ulong TransferOffset;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 512)]
        public byte[] Token;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct OffloadWriteOutput
    {
        public uint Size;
        public uint Flags;
        public ulong LengthWritten;
    }

    private static class Native
    {
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern SafeFileHandle CreateFileW(
            string lpFileName,
            uint dwDesiredAccess,
            uint dwShareMode,
            IntPtr lpSecurityAttributes,
            uint dwCreationDisposition,
            uint dwFlagsAndAttributes,
            IntPtr hTemplateFile);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool DeviceIoControl(
            SafeFileHandle hDevice,
            uint dwIoControlCode,
            IntPtr lpInBuffer,
            uint nInBufferSize,
            IntPtr lpOutBuffer,
            uint nOutBufferSize,
            out uint lpBytesReturned,
            IntPtr lpOverlapped);

        [DllImport("kernel32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        public static extern bool FlushFileBuffers(SafeFileHandle hFile);
    }
}
