using Microsoft.Win32.SafeHandles;
using RansomGuard.Rollback;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Text;

const string PortName = @"\RansomGuardMinifilterPort";
var options = Options.Parse(args);
if (options.PrepareOnly)
{
    LabRootPolicy.Prepare(options.Root);
    Console.WriteLine($"Prepared LAB root: {options.Root}");
    Console.WriteLine("No driver connection was made.");
    return;
}

LabRootPolicy.Validate(options.Root);
if (PathPolicy.Under(options.StoreRoot, options.Root))
    throw new InvalidOperationException("Rollback store must be outside the protected LAB root.");
Directory.CreateDirectory(options.StoreRoot);
var repository = new RollbackRepository(options.StoreRoot);
repository.VerifyAll(); // Refuse to start a new gate session on top of ambiguous/crash-damaged rollback state.
var sessionId = options.SessionId ?? $"gate-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
var store = repository.CreateSession(sessionId);
var writeStore = new RangeRollbackStore(Path.Combine(store.Root, "write-cow"));
var createStore = new CreateRollbackStore(Path.Combine(store.Root, "create-state"));
var createOperationStore = new CreateOperationStore(Path.Combine(store.Root, "create-state"));
var identityStore = new FileIdentityStore(Path.Combine(store.Root, "identity-state"));
var renameStore = new RenameRollbackStore(Path.Combine(store.Root, "rename-state"));
var ntRoot = DevicePathResolver.ToNtRoot(options.Root);

Console.WriteLine("RansomGuard LAB pre-write gate v0.7.7.0");
Console.WriteLine("LAB ONLY: use only inside a disposable test directory on a test machine/VM.");
Console.WriteLine($"Protected LAB root : {options.Root}");
Console.WriteLine($"Kernel NT root     : {ntRoot}");
Console.WriteLine($"Rollback session   : {sessionId}");
Console.WriteLine($"Rollback store     : {store.Root}");
Console.WriteLine("CREATE/write/rename/delete/truncate in this root are gated by durable preservation semantics.");
Console.WriteLine($"Bounded gate workers : {options.GateWorkers}");
Console.WriteLine("Press Ctrl+C to disconnect. The driver then stops gating because no client is connected.");

var context = new RgConnectContext
{
    ProtocolVersion = 8,
    ClientMode = (uint)RgClientMode.LabGate,
    ClientProcessId = (ulong)Environment.ProcessId,
    GateRootLengthBytes = checked((uint)(ntRoot.Length * 2)),
    GateRoot = ntRoot
};

using var port = Native.Connect(PortName, context);
using var cts = new CancellationTokenSource();
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Native.Cancel(port); };

var headerSize = Marshal.SizeOf<FilterMessageHeader>();
var eventSize = Marshal.SizeOf<RgEvent>();
var replyHeaderSize = Marshal.SizeOf<FilterReplyHeader>();
var gateReplySize = Marshal.SizeOf<RgGateReply>();
if (headerSize != 16 || eventSize != 2168 || replyHeaderSize != 16 || gateReplySize != 24)
    throw new InvalidOperationException($"Unexpected protocol sizes: message={headerSize}, event={eventSize}, replyHeader={replyHeaderSize}, gateReply={gateReplySize}");

var resolver = new DevicePathResolver();
using var workerSlots = new SemaphoreSlim(options.GateWorkers, options.GateWorkers);
var activeWorkers = new List<Task>();
var replySync = new object();
var buffer = Marshal.AllocHGlobal(checked(headerSize + eventSize));

async Task ProcessMessageAsync(FilterMessageHeader header, RgEvent ev)
{
    try
    {
        if ((RgEventType)ev.EventType == RgEventType.CreateResult)
        {
            var completion = await CreateReconciliation.HandleAsync(
                ev, resolver, options.Root, createOperationStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.CreateResult,-20} request={ev.RelatedSequence,-7} {completion.State,-34} status=0x{completion.CompletionStatus:X8} {completion.FinalPath}");
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.RenameResult)
        {
            var completion = await RenameReconciliation.HandleAsync(
                ev, resolver, options.Root, renameStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.RenameResult,-20} request={ev.RelatedSequence,-7} {completion.State,-24} status=0x{completion.CompletionStatus:X8} {completion.FinalDestinationPath}");
            return;
        }

        var reply = await GateDecision.EvaluateAsync(
            ev, resolver, options.Root, store, writeStore, createStore, createOperationStore,
            identityStore, renameStore, cts.Token).ConfigureAwait(false);

        lock (replySync)
        {
            Native.Reply(port, header.MessageId, reply);
        }

        var path = resolver.Resolve(ev.Path) ?? ev.Path ?? "<unresolved>";
        Console.WriteLine(
            $"{DateTime.Now:HH:mm:ss.fff} {((RgEventType)ev.EventType),-20} pid={ev.ProcessId,-7} {reply.Decision,-18} {path}");
    }
    catch (OperationCanceledException) when (cts.IsCancellationRequested)
    {
        // Shutdown cancels outstanding preservation work. GateDecision itself returns Deny for
        // ordinary blocking requests; reconciliation events are simply left pending for restart.
    }
    catch (Exception ex)
    {
        Console.Error.WriteLine($"Gate worker failed: {ex.GetType().Name}: {ex.Message}");
    }
    finally
    {
        workerSlots.Release();
    }
}

try
{
    while (!cts.IsCancellationRequested)
    {
        var hr = Native.FilterGetMessage(port, buffer, (uint)(headerSize + eventSize), IntPtr.Zero);
        if (hr != 0)
        {
            if (cts.IsCancellationRequested) break;
            throw new InvalidOperationException($"FilterGetMessage failed HRESULT=0x{hr:X8}");
        }

        var header = Marshal.PtrToStructure<FilterMessageHeader>(buffer);
        var ev = Marshal.PtrToStructure<RgEvent>(IntPtr.Add(buffer, headerSize));

        await workerSlots.WaitAsync(cts.Token).ConfigureAwait(false);
        activeWorkers.RemoveAll(static task => task.IsCompleted);
        activeWorkers.Add(Task.Run(() => ProcessMessageAsync(header, ev)));
    }
}
catch (OperationCanceledException) when (cts.IsCancellationRequested)
{
}
finally
{
    Marshal.FreeHGlobal(buffer);
    if (activeWorkers.Count != 0)
        await Task.WhenAll(activeWorkers).ConfigureAwait(false);
}

static class CreateReconciliation
{
    public static async Task<CreateOperationCompletion> HandleAsync(
        RgEvent ev,
        DevicePathResolver resolver,
        string root,
        CreateOperationStore operationStore,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != 8 || ev.RelatedSequence == 0)
            throw new InvalidDataException("Invalid CREATE completion correlation.");

        if (!NtSuccess(ev.CompletionStatus))
        {
            return await operationStore.RecordCompletionAsync(
                    ev.RelatedSequence,
                    CreateCompletionState.Failed,
                    ev.CompletionStatus,
                    ev.CompletionInformation,
                    null,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        string? finalPath = null;
        if (ev.PathStatus == (uint)RgPathStatus.Resolved)
        {
            var resolved = resolver.Resolve(ev.Path);
            if (!string.IsNullOrWhiteSpace(resolved) && PathPolicy.Under(resolved, root))
                finalPath = resolved;
        }

        DurableFileIdentity? finalIdentity = null;
        if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
            (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
        {
            finalIdentity = new DurableFileIdentity(
                ev.VolumeSerialNumber.ToString("X16"),
                ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
        }

        var state = (finalPath is not null, finalIdentity is not null) switch
        {
            (true, true) => CreateCompletionState.Succeeded,
            (false, true) => CreateCompletionState.SucceededNameUnresolved,
            (true, false) => CreateCompletionState.SucceededIdentityUnresolved,
            _ => CreateCompletionState.SucceededNameAndIdentityUnresolved
        };

        return await operationStore.RecordCompletionAsync(
                ev.RelatedSequence,
                state,
                ev.CompletionStatus,
                ev.CompletionInformation,
                finalPath,
                finalIdentity,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;
}

static class RenameReconciliation
{
    public static async Task<RenameRollbackCompletion> HandleAsync(
        RgEvent ev,
        DevicePathResolver resolver,
        string root,
        RenameRollbackStore renameStore,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != 8 || ev.RelatedSequence == 0)
            throw new InvalidDataException("Invalid rename completion correlation.");

        if (!NtSuccess(ev.CompletionStatus))
        {
            return await renameStore.RecordCompletionAsync(
                    ev.RelatedSequence,
                    RenameCompletionState.Failed,
                    ev.CompletionStatus,
                    ev.CompletionInformation,
                    null,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        string? finalPath = null;
        if (ev.DestinationPathStatus == (uint)RgPathStatus.Resolved)
        {
            var resolved = resolver.Resolve(ev.DestinationPath);
            if (!string.IsNullOrWhiteSpace(resolved) && PathPolicy.Under(resolved, root))
                finalPath = resolved;
        }

        DurableFileIdentity? finalIdentity = null;
        if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
            (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
        {
            finalIdentity = new DurableFileIdentity(
                ev.VolumeSerialNumber.ToString("X16"),
                ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
        }

        var state = (finalPath is not null, finalIdentity is not null) switch
        {
            (true, true) => RenameCompletionState.Succeeded,
            (false, true) => RenameCompletionState.SucceededNameUnresolved,
            (true, false) => RenameCompletionState.SucceededIdentityUnresolved,
            _ => RenameCompletionState.SucceededNameAndIdentityUnresolved
        };

        return await renameStore.RecordCompletionAsync(
                ev.RelatedSequence,
                state,
                ev.CompletionStatus,
                ev.CompletionInformation,
                finalPath,
                finalIdentity,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;
}

static class GateDecision
{
    public static async Task<RgGateReply> EvaluateAsync(RgEvent ev, DevicePathResolver resolver, string root,
        RollbackStore store, RangeRollbackStore writeStore, CreateRollbackStore createStore,
        CreateOperationStore createOperationStore, FileIdentityStore identityStore,
        RenameRollbackStore renameStore, CancellationToken cancellationToken)
    {
        try
        {
            // Never preserve or authorize against a truncated path. The kernel only sends a truncated
            // gate event when its known prefix is already inside the explicit LAB root, so deny it here.
            if (ev.ProtocolVersion != 8 || ev.PathStatus != (uint)RgPathStatus.Resolved)
                return Deny(ev.Sequence, 1);

            var path = resolver.Resolve(ev.Path);
            if (string.IsNullOrWhiteSpace(path) || !PathPolicy.Under(path, root))
                return Deny(ev.Sequence, 2);

            var eventType = (RgEventType)ev.EventType;
            if (eventType == RgEventType.Create)
                return await EvaluateCreateAsync(ev, path, store, createStore, createOperationStore, identityStore, cancellationToken).ConfigureAwait(false);

            var state = PathProbe.Get(path);
            if (state != CreateTargetState.File)
                return Deny(ev.Sequence, 3);

            var sourceOriginallyAbsent = createStore.WasOriginallyAbsent(path);
            var identityBaseline = await identityStore.CaptureOrVerifyAsync(path, cancellationToken)
                .ConfigureAwait(false);

            if (eventType == RgEventType.Rename)
                return await EvaluateRenameAsync(ev, resolver, root, path, store, createStore,
                    identityStore, renameStore, identityBaseline, sourceOriginallyAbsent, cancellationToken).ConfigureAwait(false);

            // Once a path is known to have been absent at incident start, later non-rename mutations must not
            // manufacture a pre-image from data that was created during the incident.
            if (sourceOriginallyAbsent)
                return Allow(ev.Sequence, RgGateDecision.BaselineCommitted);

            if (eventType == RgEventType.Write)
            {
                if (ev.ByteOffset < 0)
                    return Deny(ev.Sequence, 6);
                await writeStore.CaptureWritePreimageAsync(path, ev.ByteOffset, ev.Length,
                        identityBaseline.Identity, cancellationToken)
                    .ConfigureAwait(false);
            }
            else
            {
                var mutation = eventType switch
                {
                    RgEventType.DeleteDisposition => RollbackMutationKind.Delete,
                    RgEventType.Truncate => RollbackMutationKind.Write,
                    _ => throw new InvalidOperationException("Unsupported gate event type.")
                };
                _ = await store.CapturePreimageAsync(path, mutation, identityBaseline.Identity, cancellationToken)
                    .ConfigureAwait(false);
            }

            return Allow(ev.Sequence, RgGateDecision.SnapshotCommitted);
        }
        catch (OperationCanceledException) when (cancellationToken.IsCancellationRequested)
        {
            return Deny(ev.Sequence, 4);
        }
        catch (Exception ex)
        {
            Console.Error.WriteLine($"Gate capture failed: {ex.GetType().Name}: {ex.Message}");
            return Deny(ev.Sequence, 5);
        }
    }

    private static async Task<RgGateReply> EvaluateRenameAsync(
        RgEvent ev,
        DevicePathResolver resolver,
        string root,
        string sourcePath,
        RollbackStore store,
        CreateRollbackStore createStore,
        FileIdentityStore identityStore,
        RenameRollbackStore renameStore,
        FileIdentityBaseline sourceIdentity,
        bool sourceOriginallyAbsent,
        CancellationToken cancellationToken)
    {
        if (ev.DestinationPathStatus != (uint)RgPathStatus.Resolved)
            return Deny(ev.Sequence, 9);

        var destinationPath = resolver.Resolve(ev.DestinationPath);
        if (string.IsNullOrWhiteSpace(destinationPath) || !PathPolicy.Under(destinationPath, root))
            return Deny(ev.Sequence, 10);

        // Preserve the source only when it existed before the incident. Incident-created source bytes
        // must not become a false pre-incident pre-image.
        if (!sourceOriginallyAbsent)
        {
            _ = await store.CapturePreimageAsync(sourcePath, RollbackMutationKind.Rename,
                    sourceIdentity.Identity, cancellationToken)
                .ConfigureAwait(false);
        }

        RenameDestinationState destinationState;
        DurableFileIdentity? destinationIdentity = null;

        if (sourcePath.Equals(destinationPath, StringComparison.OrdinalIgnoreCase))
        {
            destinationState = RenameDestinationState.SameAsSource;
            destinationIdentity = sourceIdentity.Identity;
        }
        else
        {
            var destinationProbe = PathProbe.Get(destinationPath);
            switch (destinationProbe)
            {
                case CreateTargetState.Missing:
                    // Record pre-incident absence so recovery can distinguish a rename-created name
                    // from a destination that existed before the incident.
                    if (!createStore.WasOriginallyAbsent(destinationPath))
                        _ = await createStore.CaptureAbsentAsync(destinationPath, cancellationToken)
                            .ConfigureAwait(false);
                    destinationState = RenameDestinationState.OriginallyAbsent;
                    break;

                case CreateTargetState.File:
                    var destinationBaseline = await identityStore.CaptureOrVerifyAsync(destinationPath, cancellationToken)
                        .ConfigureAwait(false);
                    destinationIdentity = destinationBaseline.Identity;
                    if (destinationIdentity.Equals(sourceIdentity.Identity))
                    {
                        // Hard-link/self-alias replacement semantics are not yet modeled safely.
                        return Deny(ev.Sequence, 11);
                    }

                    _ = await store.CapturePreimageAsync(destinationPath, RollbackMutationKind.RenameDestination,
                            destinationIdentity, cancellationToken)
                        .ConfigureAwait(false);
                    destinationState = RenameDestinationState.ExistingFile;
                    break;

                default:
                    // Directory topology replacement/rename is outside the current recovery model.
                    return Deny(ev.Sequence, 12);
            }
        }

        _ = await renameStore.CaptureIntentAsync(
                ev.Sequence,
                sourcePath,
                destinationPath,
                sourceIdentity.Identity,
                sourceOriginallyAbsent,
                destinationState,
                destinationIdentity,
                ev.Flags,
                ev.FileInformationClass,
                cancellationToken)
            .ConfigureAwait(false);

        return Allow(ev.Sequence, RgGateDecision.SnapshotCommitted);
    }

    private static async Task<RgGateReply> EvaluateCreateAsync(RgEvent ev, string path,
        RollbackStore store, CreateRollbackStore createStore, CreateOperationStore createOperationStore,
        FileIdentityStore identityStore, CancellationToken cancellationToken)
    {
        var rawDisposition = (ev.Flags >> 24) & 0xFF;
        if (!CreateGatePolicy.TryParseDisposition(rawDisposition, out var disposition))
            return Deny(ev.Sequence, 7);

        var createOptions = ev.Flags & 0x00FFFFFF;
        var observedState = PathProbe.Get(path);
        CreatePreservationAction action;
        string preservationRecordSha256 = string.Empty;
        DurableFileIdentity? originalIdentity = null;

        if (createStore.TryGetBaseline(path, out var committedAbsent) && committedAbsent is not null)
        {
            // The path was absent before this incident. Even if it exists now, never manufacture a
            // pre-incident pre-image from bytes created during the incident.
            action = CreatePreservationAction.RecordOriginallyAbsent;
            preservationRecordSha256 = committedAbsent.RecordSha256;
        }
        else
        {
            action = CreateGatePolicy.Decide(disposition, observedState, createOptions);
            switch (action)
            {
                case CreatePreservationAction.CaptureExistingPreimage:
                    var identityBaseline = await identityStore.CaptureOrVerifyAsync(path, cancellationToken)
                        .ConfigureAwait(false);
                    originalIdentity = identityBaseline.Identity;
                    var capture = await store.CapturePreimageAsync(
                            path,
                            RollbackMutationKind.Create,
                            identityBaseline.Identity,
                            cancellationToken)
                        .ConfigureAwait(false);
                    preservationRecordSha256 = capture.RecordSha256;
                    break;

                case CreatePreservationAction.RecordOriginallyAbsent:
                    var absent = await createStore.CaptureAbsentAsync(path, cancellationToken)
                        .ConfigureAwait(false);
                    preservationRecordSha256 = absent.RecordSha256;
                    break;

                case CreatePreservationAction.DenyUnsupported:
                    // Directory delete-on-close/topology rollback is not modeled yet.
                    return Deny(ev.Sequence, 8);

                case CreatePreservationAction.NoPreservationRequired:
                    break;

                default:
                    throw new InvalidOperationException("Unknown CREATE preservation action.");
            }
        }

        _ = await createOperationStore.RecordIntentAsync(
                ev.Sequence,
                path,
                disposition,
                createOptions,
                ev.Length,
                observedState,
                action,
                preservationRecordSha256,
                originalIdentity,
                cancellationToken)
            .ConfigureAwait(false);

        return action switch
        {
            CreatePreservationAction.CaptureExistingPreimage => Allow(ev.Sequence, RgGateDecision.SnapshotCommitted),
            CreatePreservationAction.RecordOriginallyAbsent => Allow(ev.Sequence, RgGateDecision.BaselineCommitted),
            _ => Allow(ev.Sequence, RgGateDecision.NoPreservationRequired)
        };
    }

    private static RgGateReply Allow(ulong sequence, RgGateDecision decision) => new()
    {
        ProtocolVersion = 8,
        Decision = decision,
        RequestSequence = sequence,
        ErrorCode = 0
    };

    private static RgGateReply Deny(ulong sequence, uint errorCode) => new()
    {
        ProtocolVersion = 8,
        Decision = RgGateDecision.Deny,
        RequestSequence = sequence,
        ErrorCode = errorCode
    };
}

static class PathProbe
{
    public static CreateTargetState Get(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            return (attributes & FileAttributes.Directory) != 0 ? CreateTargetState.Directory : CreateTargetState.File;
        }
        catch (FileNotFoundException) { return CreateTargetState.Missing; }
        catch (DirectoryNotFoundException) { return CreateTargetState.Missing; }
    }
}

sealed record Options(string Root, string StoreRoot, string? SessionId, bool PrepareOnly, int GateWorkers)
{
    public const int DefaultGateWorkers = 4;
    public const int MaxGateWorkers = 8;

    public static Options Parse(string[] args)
    {
        string? root = null;
        string? store = null;
        string? session = null;
        var prepare = false;
        var gateWorkers = DefaultGateWorkers;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--root" when i + 1 < args.Length: root = Path.GetFullPath(args[++i]).TrimEnd('\\'); break;
                case "--store" when i + 1 < args.Length: store = Path.GetFullPath(args[++i]); break;
                case "--session" when i + 1 < args.Length: session = args[++i]; break;
                case "--gate-workers" when i + 1 < args.Length:
                    if (!int.TryParse(args[++i], out gateWorkers) || gateWorkers < 1 || gateWorkers > MaxGateWorkers)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            $"--gate-workers must be between 1 and {MaxGateWorkers}.");
                    break;
                case "--prepare-root": prepare = true; break;
                default: throw new ArgumentException($"Unknown/incomplete argument: {args[i]}");
            }
        }
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Pass --root <disposable-test-directory>.");
        store ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RansomGuardV072", "GateRollback");
        return new Options(root, store, session, prepare, gateWorkers);
    }
}

static class LabRootPolicy
{
    private const string MarkerName = ".ransomguard-gate-lab-root";
    private const string MarkerText = "RANSOMGUARD-LAB-GATE-V1";

    public static void Prepare(string root)
    {
        ValidateShape(root, requireMarker: false);
        Directory.CreateDirectory(root);
        File.WriteAllText(Path.Combine(root, MarkerName), MarkerText, Encoding.ASCII);
    }

    public static void Validate(string root) => ValidateShape(root, requireMarker: true);

    private static void ValidateShape(string root, bool requireMarker)
    {
        var full = Path.GetFullPath(root).TrimEnd('\\');
        var drive = Path.GetPathRoot(full)?.TrimEnd('\\');
        if (string.IsNullOrWhiteSpace(drive) || full.Equals(drive, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("LAB gate root cannot be an entire drive.");
        if (!Directory.Exists(full) && requireMarker) throw new DirectoryNotFoundException(full);
        if (Directory.Exists(full) && (File.GetAttributes(full) & FileAttributes.ReparsePoint) != 0)
            throw new InvalidOperationException("LAB gate root cannot be a reparse point.");

        foreach (var systemPath in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        }.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            if (PathPolicy.Under(full, systemPath))
                throw new InvalidOperationException("LAB gate root must not be inside Windows, Program Files, or ProgramData.");
        }

        if (requireMarker)
        {
            var marker = Path.Combine(full, MarkerName);
            if (!File.Exists(marker) || File.ReadAllText(marker, Encoding.ASCII).Trim() != MarkerText)
                throw new InvalidOperationException($"LAB marker missing. Run once with --prepare-root --root \"{full}\".");
        }
    }
}

static class PathPolicy
{
    public static bool Under(string? path, string root)
    {
        if (string.IsNullOrWhiteSpace(path)) return false;
        var p = Path.GetFullPath(path).TrimEnd('\\');
        var r = Path.GetFullPath(root).TrimEnd('\\');
        return p.Equals(r, StringComparison.OrdinalIgnoreCase) || p.StartsWith(r + "\\", StringComparison.OrdinalIgnoreCase);
    }
}

sealed class DevicePathResolver
{
    private readonly (string Device, string Drive)[] _map;

    public DevicePathResolver()
    {
        var list = new List<(string, string)>();
        foreach (var d in DriveInfo.GetDrives())
        {
            var drive = d.Name.TrimEnd('\\');
            if (drive.Length != 2 || drive[1] != ':') continue;
            var sb = new StringBuilder(1024);
            if (Native.QueryDosDevice(drive, sb, sb.Capacity) != 0)
                list.Add((sb.ToString().Split('\0')[0], drive));
        }
        _map = list.OrderByDescending(x => x.Item1.Length).ToArray();
    }

    public string? Resolve(string? ntPath)
    {
        if (string.IsNullOrWhiteSpace(ntPath)) return null;
        var p = ntPath;
        if (p.StartsWith(@"\??\", StringComparison.Ordinal)) p = p[4..];
        if (p.Length >= 3 && char.IsAsciiLetter(p[0]) && p[1] == ':' && p[2] == '\\') return p;
        foreach (var (device, drive) in _map)
            if (p.StartsWith(device, StringComparison.OrdinalIgnoreCase)) return drive + p[device.Length..];
        return null;
    }

    public static string ToNtRoot(string dosRoot)
    {
        var full = Path.GetFullPath(dosRoot).TrimEnd('\\');
        var drive = Path.GetPathRoot(full)?.TrimEnd('\\') ?? throw new InvalidOperationException("No drive root.");
        if (drive.Length != 2 || drive[1] != ':') throw new InvalidOperationException("LAB gate supports local drive paths only.");
        var sb = new StringBuilder(1024);
        if (Native.QueryDosDevice(drive, sb, sb.Capacity) == 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "QueryDosDevice failed.");
        var device = sb.ToString().Split('\0')[0];
        return device + full[drive.Length..];
    }
}

enum RgClientMode : uint { Audit = 1, LabGate = 2 }
enum RgEventType : uint { Invalid = 0, Write = 1, Rename = 2, DeleteDisposition = 3, Truncate = 4, Create = 5, RenameResult = 6, CreateResult = 7 }
enum RgPathStatus : uint { Unknown = 0, Resolved = 1, QueryFailed = 2, Truncated = 3 }
enum RgIdentityStatus : uint { Unknown = 0, Resolved = 1, QueryFailed = 2 }
enum RgGateDecision : uint { Invalid = 0, SnapshotCommitted = 1, Deny = 2, BaselineCommitted = 3, NoPreservationRequired = 4 }

[StructLayout(LayoutKind.Sequential)]
struct FilterMessageHeader { public uint ReplyLength; public ulong MessageId; }

[StructLayout(LayoutKind.Sequential)]
struct FilterReplyHeader { public int Status; public ulong MessageId; }

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
struct RgConnectContext
{
    public uint ProtocolVersion, ClientMode;
    public ulong ClientProcessId;
    public uint GateRootLengthBytes, Reserved;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string GateRoot;
}

[StructLayout(LayoutKind.Sequential, Pack = 1, CharSet = CharSet.Unicode)]
struct RgEvent
{
    public uint ProtocolVersion, EventType, PathStatus, Flags;
    public ulong Sequence;
    public long SystemTime100ns;
    public ulong ProcessId, ThreadId;
    public long ByteOffset;
    public uint Length, FileInformationClass, DroppedBeforeThis, DestinationPathStatus;
    public ulong RelatedSequence;
    public uint CompletionStatus;
    public ulong CompletionInformation;
    public uint IdentityStatus;
    public ulong VolumeSerialNumber, FileIdLow, FileIdHigh;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] public string? Path;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 512)] public string? DestinationPath;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct RgGateReply
{
    public uint ProtocolVersion;
    public RgGateDecision Decision;
    public ulong RequestSequence;
    public uint ErrorCode;
    public uint Reserved;
}

static class Native
{
    [DllImport("fltlib.dll", CharSet = CharSet.Unicode)]
    private static extern int FilterConnectCommunicationPort(string lpPortName, uint dwOptions, IntPtr lpContext,
        ushort wSizeOfContext, IntPtr lpSecurityAttributes, out SafeFileHandle hPort);
    [DllImport("fltlib.dll")]
    public static extern int FilterGetMessage(SafeFileHandle hPort, IntPtr lpMessageBuffer, uint dwMessageBufferSize, IntPtr lpOverlapped);
    [DllImport("fltlib.dll")]
    private static extern int FilterReplyMessage(SafeFileHandle hPort, IntPtr lpReplyBuffer, uint dwReplyBufferSize);
    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CancelIoEx(SafeFileHandle hFile, IntPtr lpOverlapped);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern uint QueryDosDevice(string lpDeviceName, StringBuilder lpTargetPath, int ucchMax);

    public static SafeFileHandle Connect(string name, RgConnectContext context)
    {
        const uint FltPortFlagSyncHandle = 0x00000001;
        var size = Marshal.SizeOf<RgConnectContext>();
        if (size != 544) throw new InvalidOperationException($"Unexpected connect context size: {size}");
        var ptr = Marshal.AllocHGlobal(size);
        try
        {
            Marshal.StructureToPtr(context, ptr, false);
            var hr = FilterConnectCommunicationPort(name, FltPortFlagSyncHandle, ptr, checked((ushort)size), IntPtr.Zero, out var handle);
            if (hr != 0 || handle.IsInvalid) throw new InvalidOperationException($"FilterConnectCommunicationPort failed HRESULT=0x{hr:X8}.");
            return handle;
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static void Reply(SafeFileHandle port, ulong messageId, RgGateReply payload)
    {
        var headerSize = Marshal.SizeOf<FilterReplyHeader>();
        var payloadSize = Marshal.SizeOf<RgGateReply>();
        var total = checked(headerSize + payloadSize);
        var ptr = Marshal.AllocHGlobal(total);
        try
        {
            Marshal.StructureToPtr(new FilterReplyHeader { Status = 0, MessageId = messageId }, ptr, false);
            Marshal.StructureToPtr(payload, IntPtr.Add(ptr, headerSize), false);
            var hr = FilterReplyMessage(port, ptr, (uint)total);
            if (hr != 0) throw new InvalidOperationException($"FilterReplyMessage failed HRESULT=0x{hr:X8}");
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static void Cancel(SafeFileHandle handle) { if (!handle.IsInvalid) _ = CancelIoEx(handle, IntPtr.Zero); }
}
