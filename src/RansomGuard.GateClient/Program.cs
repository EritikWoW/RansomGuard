using Microsoft.Win32.SafeHandles;
using RansomGuard.Rollback;
using System.ComponentModel;
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
var restartSummary = await RestartReconciliation.ObservePendingAsync(
    repository,
    options.Root,
    checked(options.MaxStoreMiB * RollbackStorageBudget.MiB),
    checked(options.MinFreeMiB * RollbackStorageBudget.MiB),
    CancellationToken.None).ConfigureAwait(false);
var sessionId = options.SessionId ?? $"gate-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
var store = repository.CreateSession(sessionId);
var writeStore = new RangeRollbackStore(Path.Combine(store.Root, "write-cow"));
var createStore = new CreateRollbackStore(Path.Combine(store.Root, "create-state"));
var createOperationStore = new CreateOperationStore(Path.Combine(store.Root, "create-state"));
var identityStore = new FileIdentityStore(Path.Combine(store.Root, "identity-state"));
var renameStore = new RenameRollbackStore(Path.Combine(store.Root, "rename-state"));
var pagingStore = new PagingWriteEvidenceStore(Path.Combine(store.Root, "paging-state"));
var sectionStore = new WritableSectionEvidenceStore(Path.Combine(store.Root, "section-state"));
var activationStore = new ActivationPreflightStore(Path.Combine(store.Root, "activation-state"));
var topologyStore = new ActivationTopologyStore(Path.Combine(store.Root, "activation-topology-state"));
var storageBudget = new RollbackStorageBudget(
    store.Root,
    checked(options.MaxStoreMiB * RollbackStorageBudget.MiB),
    checked(options.MinFreeMiB * RollbackStorageBudget.MiB));
var ntRoot = DevicePathResolver.ToNtRoot(options.Root);

Console.WriteLine("RansomGuard LAB pre-write gate v0.7.17.0");
Console.WriteLine("LAB ONLY: use only inside a disposable test directory on a test machine/VM.");
Console.WriteLine($"Protected LAB root : {options.Root}");
Console.WriteLine($"Kernel NT root     : {ntRoot}");
Console.WriteLine($"Rollback session   : {sessionId}");
Console.WriteLine($"Rollback store     : {store.Root}");
Console.WriteLine($"Restart evidence   : observed={restartSummary.Observed}, completed-evidence={restartSummary.SupportsCompleted}, not-completed-evidence={restartSummary.SupportsNotCompleted}, ambiguous={restartSummary.Ambiguous}");
Console.WriteLine("CREATE/write/rename/delete/truncate in this root are gated by durable preservation semantics.");
Console.WriteLine($"Bounded gate workers : {options.GateWorkers}");
Console.WriteLine($"Rollback budget      : max-session={options.MaxStoreMiB} MiB; min-free={options.MinFreeMiB} MiB");
Console.WriteLine("Press Ctrl+C to disconnect. The driver then stops gating because no client is connected.");

var context = new RgConnectContext
{
    ProtocolVersion = 11,
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
if (headerSize != 16 || eventSize != 2168 || replyHeaderSize != 16 || gateReplySize != 24 ||
    Marshal.SizeOf<RgControlRequest>() != 16 || Marshal.SizeOf<RgControlReply>() != 16)
    throw new InvalidOperationException($"Unexpected protocol sizes: message={headerSize}, event={eventSize}, replyHeader={replyHeaderSize}, gateReply={gateReplySize}");

var resolver = new DevicePathResolver();
var activationSummary = await ActivationPreflight.RunAsync(
    port, options.Root, resolver, activationStore, topologyStore, storageBudget, cts.Token).ConfigureAwait(false);
Console.WriteLine($"Activation preflight: directories={activationSummary.DirectoriesHeld}, files={activationSummary.FilesChecked}, writable-views=0, kernel gate ACTIVE.");


using var workerSlots = new SemaphoreSlim(options.GateWorkers, options.GateWorkers);
var activeWorkers = new List<Task>();
var replySync = new object();
var buffer = Marshal.AllocHGlobal(checked(headerSize + eventSize));

async Task ProcessMessageAsync(FilterMessageHeader header, RgEvent ev)
{
    try
    {
        if ((RgEventType)ev.EventType == RgEventType.WritableSection)
        {
            if (ev.ProtocolVersion != 11 ||
                ev.PathStatus != (uint)RgPathStatus.Resolved ||
                ev.RelatedSequence == 0 ||
                ev.CompletionInformation > uint.MaxValue)
                throw new InvalidDataException("Invalid writable-section attestation event.");

            var trackedPath = resolver.Resolve(ev.Path);
            if (string.IsNullOrWhiteSpace(trackedPath) || !PathPolicy.Under(trackedPath, options.Root))
                throw new InvalidDataException("Writable-section attestation escaped the explicit LAB root.");

            var intent = createOperationStore.Intents.SingleOrDefault(x => x.RequestSequence == ev.RelatedSequence);
            createOperationStore.TryGetCompletion(ev.RelatedSequence, out var completion);
            var preservationDecision = checked((uint)ev.CompletionInformation);
            var state = WritableSectionAttestation.Evaluate(
                intent, completion, trackedPath, preservationDecision);

            DurableFileIdentity? identity = null;
            if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
                (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
            {
                identity = new DurableFileIdentity(
                    ev.VolumeSerialNumber.ToString("X16"),
                    ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
            }

            await using var sectionReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "writable-section-evidence",
                cts.Token).ConfigureAwait(false);
            var evidence = await sectionStore.RecordAsync(
                ev.Sequence,
                ev.RelatedSequence,
                trackedPath,
                ev.Flags,
                preservationDecision,
                state,
                identity,
                cts.Token).ConfigureAwait(false);

            var line = $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.WritableSection,-20} {evidence.State,-20} request={evidence.CreateRequestSequence} protection=0x{evidence.PageProtection:X8} {evidence.TrackedPath}";
            if (state == WritableSectionAttestationState.BaselineVerified)
                Console.WriteLine(line);
            else
                Console.Error.WriteLine(line);
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.PagingWrite)
        {
            if (ev.ProtocolVersion != 11 || ev.PathStatus != (uint)RgPathStatus.Resolved)
                throw new InvalidDataException("Invalid paging-write evidence event.");

            var trackedPath = resolver.Resolve(ev.Path);
            if (string.IsNullOrWhiteSpace(trackedPath) || !PathPolicy.Under(trackedPath, options.Root))
                throw new InvalidDataException("Paging-write evidence escaped the explicit LAB root.");

            DurableFileIdentity? identity = null;
            if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
                (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
            {
                identity = new DurableFileIdentity(
                    ev.VolumeSerialNumber.ToString("X16"),
                    ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
            }

            await using var pagingReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "paging-write-evidence",
                cts.Token).ConfigureAwait(false);
            var evidence = await pagingStore.RecordAsync(
                ev.Sequence,
                trackedPath,
                ev.ByteOffset,
                ev.Length,
                identity,
                ev.Flags,
                cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.PagingWrite,-20} evidence-only offset={evidence.ByteOffset} length={evidence.Length} {evidence.TrackedPath}");
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.CreateResult)
        {
            await using var createResultReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "create-completion-evidence",
                cts.Token).ConfigureAwait(false);
            var completion = await CreateReconciliation.HandleAsync(
                ev, resolver, options.Root, createOperationStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.CreateResult,-20} request={ev.RelatedSequence,-7} {completion.State,-34} status=0x{completion.CompletionStatus:X8} {completion.FinalPath}");
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.RenameResult)
        {
            await using var renameResultReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "rename-completion-evidence",
                cts.Token).ConfigureAwait(false);
            var completion = await RenameReconciliation.HandleAsync(
                ev, resolver, options.Root, renameStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.RenameResult,-20} request={ev.RelatedSequence,-7} {completion.State,-24} status=0x{completion.CompletionStatus:X8} {completion.FinalDestinationPath}");
            return;
        }

        var reply = await GateDecision.EvaluateAsync(
            ev, resolver, options.Root, store, writeStore, createStore, createOperationStore,
            identityStore, renameStore, storageBudget, cts.Token).ConfigureAwait(false);

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

        await workerSlots.WaitAsync().ConfigureAwait(false);
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

static class ActivationPreflight
{
    private const uint WritableViewFlag = 0x00000002;

    public static async Task<ActivationPreflightSummary> RunAsync(
        SafeFileHandle port,
        string root,
        DevicePathResolver resolver,
        ActivationPreflightStore evidenceStore,
        ActivationTopologyStore topologyStore,
        RollbackStorageBudget storageBudget,
        CancellationToken cancellationToken)
    {
        var options = new EnumerationOptions
        {
            RecurseSubdirectories = true,
            IgnoreInaccessible = false,
            ReturnSpecialDirectories = false,
            AttributesToSkip = FileAttributes.ReparsePoint
        };

        var checkedFiles = 0;
        var heldDirectories = 0;
        var heldHandles = new List<SafeFileHandle>();
        try
        {
            var rootPath = Path.GetFullPath(root);
            var rootHandle = Native.OpenPreflightDirectory(rootPath);
            heldHandles.Add(rootHandle);
            var rootIdentity = FileIdentityStore.QueryHandleIdentity(rootHandle);
            await using (var rootReservation = await storageBudget.ReserveAsync(
                             RollbackStorageBudget.MetadataReservationBytes,
                             "activation-topology-root",
                             cancellationToken).ConfigureAwait(false))
            {
                _ = await topologyStore.RecordAsync(rootPath, rootIdentity, isRoot: true, cancellationToken)
                    .ConfigureAwait(false);
            }
            heldDirectories++;

            var directories = Directory.EnumerateDirectories(rootPath, "*", options)
                .Select(Path.GetFullPath)
                .OrderBy(x => x.Count(ch => ch == Path.DirectorySeparatorChar))
                .ThenBy(x => x, StringComparer.OrdinalIgnoreCase)
                .ToArray();

            foreach (var directory in directories)
            {
                cancellationToken.ThrowIfCancellationRequested();
                if ((File.GetAttributes(directory) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException($"Activation preflight refuses reparse directory: {directory}");

                var directoryHandle = Native.OpenPreflightDirectory(directory);
                heldHandles.Add(directoryHandle);
                var directoryIdentity = FileIdentityStore.QueryHandleIdentity(directoryHandle);
                await using (var directoryReservation = await storageBudget.ReserveAsync(
                                 RollbackStorageBudget.MetadataReservationBytes,
                                 "activation-topology-directory",
                                 cancellationToken).ConfigureAwait(false))
                {
                    _ = await topologyStore.RecordAsync(directory, directoryIdentity, isRoot: false, cancellationToken)
                        .ConfigureAwait(false);
                }
                heldDirectories++;
            }

            foreach (var rawPath in Directory.EnumerateFiles(rootPath, "*", options))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var path = Path.GetFullPath(rawPath);
                if ((File.GetAttributes(path) & FileAttributes.ReparsePoint) != 0)
                    throw new InvalidOperationException($"Activation preflight refuses reparse file: {path}");

                var arm = Native.Control(port, new RgControlRequest
                {
                    ProtocolVersion = 11,
                    Command = (uint)RgControlCommand.ArmPreflight
                });
                if (arm.ProtocolVersion != 11 ||
                    arm.Command != (uint)RgControlCommand.ArmPreflight ||
                    arm.Status != 0 ||
                    arm.GateActivated != 0)
                    throw new InvalidOperationException(
                        $"Kernel refused to arm activation preflight for '{path}'. NTSTATUS=0x{arm.Status:X8}.");

                var file = Native.OpenPreflight(path);
                heldHandles.Add(file);
                var ev = await ReceivePreflightEventAsync(port, path, resolver, cancellationToken).ConfigureAwait(false);

            DurableFileIdentity? identity = null;
            if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
                (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
            {
                identity = new DurableFileIdentity(
                    ev.VolumeSerialNumber.ToString("X16"),
                    ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
            }

            var writableView = (ev.Flags & WritableViewFlag) != 0;
            await using (var fileReservation = await storageBudget.ReserveAsync(
                             RollbackStorageBudget.MetadataReservationBytes,
                             "activation-file-evidence",
                             cancellationToken).ConfigureAwait(false))
            {
                _ = await evidenceStore.RecordAsync(
                    ev.Sequence, path, ev.CompletionStatus, writableView, identity, cancellationToken)
                    .ConfigureAwait(false);
            }

            if (!NtSuccess(ev.CompletionStatus))
                throw new InvalidOperationException(
                    $"Activation preflight kernel open failed for '{path}', NTSTATUS=0x{ev.CompletionStatus:X8}.");
            if (identity is null)
                throw new InvalidOperationException($"Activation preflight could not bind FILE_ID_INFO for '{path}'.");
            if (writableView)
                throw new InvalidOperationException(
                    $"Activation refused: '{path}' already has a user-writable mapped view.");

                checkedFiles++;
            }

            var activationReply = Native.Control(port, new RgControlRequest
            {
                ProtocolVersion = 11,
                Command = (uint)RgControlCommand.ActivateGate
            });
            if (activationReply.ProtocolVersion != 11 ||
                activationReply.Command != (uint)RgControlCommand.ActivateGate ||
                activationReply.Status != 0 ||
                activationReply.GateActivated != 1)
                throw new InvalidOperationException(
                    $"Kernel refused LAB activation after preflight. NTSTATUS=0x{activationReply.Status:X8}, active={activationReply.GateActivated}.");

            return new ActivationPreflightSummary(checkedFiles, heldDirectories);
        }
        finally
        {
            foreach (var handle in heldHandles) handle.Dispose();
        }
    }

    private static async Task<RgEvent> ReceivePreflightEventAsync(
        SafeFileHandle port,
        string expectedPath,
        DevicePathResolver resolver,
        CancellationToken cancellationToken)
    {
        var headerSize = Marshal.SizeOf<FilterMessageHeader>();
        var eventSize = Marshal.SizeOf<RgEvent>();
        var buffer = Marshal.AllocHGlobal(checked(headerSize + eventSize));
        try
        {
            while (true)
            {
                cancellationToken.ThrowIfCancellationRequested();
                var receive = Task.Run(() =>
                    Native.FilterGetMessage(port, buffer, (uint)(headerSize + eventSize), IntPtr.Zero),
                    CancellationToken.None);
                var winner = await Task.WhenAny(receive, Task.Delay(TimeSpan.FromSeconds(5), cancellationToken))
                    .ConfigureAwait(false);
                if (winner != receive)
                {
                    Native.Cancel(port);
                    _ = await receive.ConfigureAwait(false); // Do not free the unmanaged buffer until canceled I/O has completed.
                    cancellationToken.ThrowIfCancellationRequested();
                    throw new TimeoutException($"Timed out waiting for activation preflight evidence for '{expectedPath}'.");
                }

                var hr = await receive.ConfigureAwait(false);
                if (hr != 0)
                    throw new InvalidOperationException($"FilterGetMessage during activation preflight failed HRESULT=0x{hr:X8}.");

                var ev = Marshal.PtrToStructure<RgEvent>(IntPtr.Add(buffer, headerSize));
                var type = (RgEventType)ev.EventType;
                if (type is RgEventType.PagingWrite or RgEventType.WritableSection)
                    throw new InvalidOperationException("Activation refused: protected-root memory-mapped activity occurred during preflight.");
                if (type != RgEventType.ActivationPreflight)
                    throw new InvalidDataException($"Unexpected event {type} during activation preflight.");
                if (ev.ProtocolVersion != 11 || ev.PathStatus != (uint)RgPathStatus.Resolved)
                    throw new InvalidDataException("Invalid activation preflight event.");

                var resolved = resolver.Resolve(ev.Path);
                if (string.IsNullOrWhiteSpace(resolved) ||
                    !Path.GetFullPath(resolved).Equals(Path.GetFullPath(expectedPath), StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException(
                        $"Activation preflight path mismatch. expected='{expectedPath}', actual='{resolved ?? "<unresolved>"}'.");
                return ev;
            }
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;
}

readonly record struct ActivationPreflightSummary(int FilesChecked, int DirectoriesHeld);

static class CreateReconciliation
{
    public static async Task<CreateOperationCompletion> HandleAsync(
        RgEvent ev,
        DevicePathResolver resolver,
        string root,
        CreateOperationStore operationStore,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != 11 || ev.RelatedSequence == 0)
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
        if (ev.ProtocolVersion != 11 || ev.RelatedSequence == 0)
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
        RenameRollbackStore renameStore, RollbackStorageBudget storageBudget,
        CancellationToken cancellationToken)
    {
        try
        {
            // Never preserve or authorize against a truncated path. The kernel only sends a truncated
            // gate event when its known prefix is already inside the explicit LAB root, so deny it here.
            if (ev.ProtocolVersion != 11 || ev.PathStatus != (uint)RgPathStatus.Resolved)
                return Deny(ev.Sequence, 1);

            var path = resolver.Resolve(ev.Path);
            if (string.IsNullOrWhiteSpace(path) || !PathPolicy.Under(path, root))
                return Deny(ev.Sequence, 2);

            var eventType = (RgEventType)ev.EventType;
            await using var eventReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                $"gate-event:{eventType}",
                cancellationToken).ConfigureAwait(false);

            if (eventType == RgEventType.Create)
                return await EvaluateCreateAsync(
                    ev, path, store, createStore, createOperationStore, identityStore,
                    storageBudget, cancellationToken).ConfigureAwait(false);

            var state = PathProbe.Get(path);
            if (state != CreateTargetState.File)
                return Deny(ev.Sequence, 3);

            var sourceOriginallyAbsent = createStore.WasOriginallyAbsent(path);
            var identityBaseline = await identityStore.CaptureOrVerifyAsync(path, cancellationToken)
                .ConfigureAwait(false);

            if (eventType == RgEventType.Rename)
                return await EvaluateRenameAsync(ev, resolver, root, path, store, createStore,
                    identityStore, renameStore, identityBaseline, sourceOriginallyAbsent,
                    storageBudget, cancellationToken).ConfigureAwait(false);

            // Once a path is known to have been absent at incident start, later non-rename mutations must not
            // manufacture a pre-image from data that was created during the incident.
            if (sourceOriginallyAbsent)
                return Allow(ev.Sequence, RgGateDecision.BaselineCommitted);

            if (eventType == RgEventType.Write)
            {
                if (ev.ByteOffset < 0)
                    return Deny(ev.Sequence, 6);
                var estimate = RollbackStorageBudget.EstimateRangeCaptureBytes(
                    writeStore, path, ev.ByteOffset, ev.Length);
                await using var captureReservation = await storageBudget.ReserveAsync(
                    estimate, "range-write-preimage", cancellationToken).ConfigureAwait(false);
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
                var estimate = RollbackStorageBudget.EstimateFullPreimageBytes(store, path);
                await using var captureReservation = await storageBudget.ReserveAsync(
                    estimate, $"full-preimage:{eventType}", cancellationToken).ConfigureAwait(false);
                _ = await store.CapturePreimageAsync(path, mutation, identityBaseline.Identity, cancellationToken)
                    .ConfigureAwait(false);
            }

            return Allow(ev.Sequence, RgGateDecision.SnapshotCommitted);
        }
        catch (RollbackStorageBudgetExceededException ex)
        {
            Console.Error.WriteLine(
                $"Rollback storage budget denied {ex.Purpose}: requested={ex.RequestedBytes}, actual={ex.ActualSessionBytes}, reserved={ex.ReservedBytes}, free={ex.AvailableFreeBytes}, max={ex.MaxSessionBytes}, minFree={ex.MinFreeBytes}.");
            return Deny(ev.Sequence, 13);
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
        RollbackStorageBudget storageBudget,
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
            var sourceEstimate = RollbackStorageBudget.EstimateFullPreimageBytes(store, sourcePath);
            await using var sourceReservation = await storageBudget.ReserveAsync(
                sourceEstimate, "rename-source-preimage", cancellationToken).ConfigureAwait(false);
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
                    {
                        var absenceEstimate = RollbackStorageBudget.EstimateOriginallyAbsentBytes(
                            createStore, destinationPath);
                        await using var absenceReservation = await storageBudget.ReserveAsync(
                            absenceEstimate, "rename-destination-absence", cancellationToken).ConfigureAwait(false);
                        _ = await createStore.CaptureAbsentAsync(destinationPath, cancellationToken)
                            .ConfigureAwait(false);
                    }
                    destinationState = RenameDestinationState.OriginallyAbsent;
                    break;

                case CreateTargetState.File:
                {
                    var destinationBaseline = await identityStore.CaptureOrVerifyAsync(destinationPath, cancellationToken)
                        .ConfigureAwait(false);
                    destinationIdentity = destinationBaseline.Identity;
                    if (destinationIdentity.Equals(sourceIdentity.Identity))
                    {
                        // Hard-link/self-alias replacement semantics are not yet modeled safely.
                        return Deny(ev.Sequence, 11);
                    }

                    var destinationEstimate = RollbackStorageBudget.EstimateFullPreimageBytes(
                        store, destinationPath);
                    await using var destinationReservation = await storageBudget.ReserveAsync(
                        destinationEstimate, "rename-destination-preimage", cancellationToken).ConfigureAwait(false);
                    _ = await store.CapturePreimageAsync(destinationPath, RollbackMutationKind.RenameDestination,
                            destinationIdentity, cancellationToken)
                        .ConfigureAwait(false);
                    destinationState = RenameDestinationState.ExistingFile;
                    break;
                }

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
        FileIdentityStore identityStore, RollbackStorageBudget storageBudget,
        CancellationToken cancellationToken)
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
            action = CreateGatePolicy.Decide(disposition, observedState, createOptions, ev.Length);
            switch (action)
            {
                case CreatePreservationAction.CaptureExistingPreimage:
                {
                    var identityBaseline = await identityStore.CaptureOrVerifyAsync(path, cancellationToken)
                        .ConfigureAwait(false);
                    originalIdentity = identityBaseline.Identity;
                    var fullEstimate = RollbackStorageBudget.EstimateFullPreimageBytes(store, path);
                    await using var fullReservation = await storageBudget.ReserveAsync(
                        fullEstimate, "create-existing-preimage", cancellationToken).ConfigureAwait(false);
                    var capture = await store.CapturePreimageAsync(
                            path,
                            RollbackMutationKind.Create,
                            identityBaseline.Identity,
                            cancellationToken)
                        .ConfigureAwait(false);
                    preservationRecordSha256 = capture.RecordSha256;
                    break;
                }

                case CreatePreservationAction.RecordOriginallyAbsent:
                    var absenceEstimate = RollbackStorageBudget.EstimateOriginallyAbsentBytes(
                        createStore, path);
                    await using (var absenceReservation = await storageBudget.ReserveAsync(
                                     absenceEstimate, "create-absence-baseline", cancellationToken)
                               .ConfigureAwait(false))
                    {
                        var absent = await createStore.CaptureAbsentAsync(path, cancellationToken)
                            .ConfigureAwait(false);
                        preservationRecordSha256 = absent.RecordSha256;
                    }
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
        ProtocolVersion = 11,
        Decision = decision,
        RequestSequence = sequence,
        ErrorCode = 0
    };

    private static RgGateReply Deny(ulong sequence, uint errorCode) => new()
    {
        ProtocolVersion = 11,
        Decision = RgGateDecision.Deny,
        RequestSequence = sequence,
        ErrorCode = errorCode
    };
}

static class RestartReconciliation
{
    public static async Task<RestartReconciliationSummary> ObservePendingAsync(
        RollbackRepository repository,
        string currentRoot,
        long maxSessionBytes,
        long minFreeBytes,
        CancellationToken cancellationToken)
    {
        var observed = 0;
        var supportsCompleted = 0;
        var supportsNotCompleted = 0;
        var ambiguous = 0;

        foreach (var sessionId in repository.SessionIds())
        {
            cancellationToken.ThrowIfCancellationRequested();
            var session = repository.OpenSession(sessionId);
            var storageBudget = new RollbackStorageBudget(
                session.Root, maxSessionBytes, minFreeBytes);
            var restartStore = new RestartReconciliationStore(Path.Combine(session.Root, "restart-state"));

            var createRoot = Path.Combine(session.Root, "create-state");
            if (Directory.Exists(createRoot))
            {
                var createOperations = new CreateOperationStore(createRoot);
                foreach (var intent in createOperations.PendingIntents)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!PathPolicy.Under(intent.OriginalPath, currentRoot))
                        continue;

                    var current = PathProbe.ObserveForRestart(intent.OriginalPath);
                    var evidence = RestartReconciliationClassifier.ClassifyCreate(intent, current);
                    await using var restartCreateReservation = await storageBudget.ReserveAsync(
                        RollbackStorageBudget.MetadataReservationBytes,
                        "restart-create-evidence",
                        cancellationToken).ConfigureAwait(false);
                    _ = await restartStore.RecordObservationAsync(
                            RestartOperationKind.Create,
                            intent.RequestSequence,
                            intent.RecordSha256,
                            evidence,
                            intent.OriginalPath,
                            current,
                            cancellationToken: cancellationToken)
                        .ConfigureAwait(false);
                    Count(evidence, ref observed, ref supportsCompleted, ref supportsNotCompleted, ref ambiguous);
                }
            }

            var renameRoot = Path.Combine(session.Root, "rename-state");
            if (Directory.Exists(renameRoot))
            {
                var renames = new RenameRollbackStore(renameRoot);
                foreach (var intent in renames.PendingIntents)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!PathPolicy.Under(intent.SourcePath, currentRoot) ||
                        !PathPolicy.Under(intent.DestinationPath, currentRoot))
                        continue;

                    var source = PathProbe.ObserveForRestart(intent.SourcePath);
                    var destination = PathProbe.ObserveForRestart(intent.DestinationPath);
                    var evidence = RestartReconciliationClassifier.ClassifyRename(intent, source, destination);
                    await using var restartRenameReservation = await storageBudget.ReserveAsync(
                        RollbackStorageBudget.MetadataReservationBytes,
                        "restart-rename-evidence",
                        cancellationToken).ConfigureAwait(false);
                    _ = await restartStore.RecordObservationAsync(
                            RestartOperationKind.Rename,
                            intent.RequestSequence,
                            intent.RecordSha256,
                            evidence,
                            intent.SourcePath,
                            source,
                            intent.DestinationPath,
                            destination,
                            cancellationToken)
                        .ConfigureAwait(false);
                    Count(evidence, ref observed, ref supportsCompleted, ref supportsNotCompleted, ref ambiguous);
                }
            }
        }

        return new RestartReconciliationSummary(
            observed, supportsCompleted, supportsNotCompleted, ambiguous);
    }

    private static void Count(
        RestartEvidenceState evidence,
        ref int observed,
        ref int supportsCompleted,
        ref int supportsNotCompleted,
        ref int ambiguous)
    {
        observed++;
        if (evidence == RestartEvidenceState.SupportsCompleted) supportsCompleted++;
        else if (evidence == RestartEvidenceState.SupportsNotCompleted) supportsNotCompleted++;
        else ambiguous++;
    }
}

readonly record struct RestartReconciliationSummary(
    int Observed,
    int SupportsCompleted,
    int SupportsNotCompleted,
    int Ambiguous);

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

    public static RestartPathObservation ObserveForRestart(string path)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                return new RestartPathObservation(RestartPathState.ReparsePoint, null);
            if ((attributes & FileAttributes.Directory) != 0)
                return new RestartPathObservation(RestartPathState.Directory, null);

            using var input = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Write | FileShare.Delete, 4096, FileOptions.None);
            var identity = FileIdentityStore.QueryHandleIdentity(input.SafeFileHandle);
            return new RestartPathObservation(RestartPathState.File, identity);
        }
        catch (FileNotFoundException)
        {
            return new RestartPathObservation(RestartPathState.Missing, null);
        }
        catch (DirectoryNotFoundException)
        {
            return new RestartPathObservation(RestartPathState.Missing, null);
        }
        catch
        {
            return new RestartPathObservation(RestartPathState.QueryFailed, null);
        }
    }
}

sealed record Options(
    string Root,
    string StoreRoot,
    string? SessionId,
    bool PrepareOnly,
    int GateWorkers,
    long MaxStoreMiB,
    long MinFreeMiB)
{
    public const int DefaultGateWorkers = 4;
    public const int MaxGateWorkers = 8;
    public const long DefaultMaxStoreMiB = 8192;
    public const long DefaultMinFreeMiB = 2048;
    public const long MaxConfigMiB = 1048576;

    public static Options Parse(string[] args)
    {
        string? root = null;
        string? store = null;
        string? session = null;
        var prepare = false;
        var gateWorkers = DefaultGateWorkers;
        long maxStoreMiB = DefaultMaxStoreMiB;
        long minFreeMiB = DefaultMinFreeMiB;
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
                case "--max-store-mib" when i + 1 < args.Length:
                    if (!long.TryParse(args[++i], out maxStoreMiB) || maxStoreMiB < 64 || maxStoreMiB > MaxConfigMiB)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            $"--max-store-mib must be between 64 and {MaxConfigMiB}.");
                    break;
                case "--min-free-mib" when i + 1 < args.Length:
                    if (!long.TryParse(args[++i], out minFreeMiB) || minFreeMiB < 64 || minFreeMiB > MaxConfigMiB)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            $"--min-free-mib must be between 64 and {MaxConfigMiB}.");
                    break;
                case "--prepare-root": prepare = true; break;
                default: throw new ArgumentException($"Unknown/incomplete argument: {args[i]}");
            }
        }
        if (string.IsNullOrWhiteSpace(root)) throw new ArgumentException("Pass --root <disposable-test-directory>.");
        store ??= Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "RansomGuardV072", "GateRollback");
        return new Options(root, store, session, prepare, gateWorkers, maxStoreMiB, minFreeMiB);
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
enum RgEventType : uint { Invalid = 0, Write = 1, Rename = 2, DeleteDisposition = 3, Truncate = 4, Create = 5, RenameResult = 6, CreateResult = 7, PagingWrite = 8, WritableSection = 9, ActivationPreflight = 10 }
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

enum RgControlCommand : uint { Invalid = 0, ActivateGate = 1, QueryActivation = 2, ArmPreflight = 3 }

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct RgControlRequest
{
    public uint ProtocolVersion;
    public uint Command;
    public uint Reserved0;
    public uint Reserved1;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct RgControlReply
{
    public uint ProtocolVersion;
    public uint Command;
    public uint Status;
    public uint GateActivated;
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
    [DllImport("fltlib.dll")]
    private static extern int FilterSendMessage(SafeFileHandle hPort, IntPtr lpInBuffer, uint dwInBufferSize,
        IntPtr lpOutBuffer, uint dwOutBufferSize, out uint lpBytesReturned);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern SafeFileHandle CreateFileW(string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);
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

    public static RgControlReply Control(SafeFileHandle port, RgControlRequest request)
    {
        var inSize = Marshal.SizeOf<RgControlRequest>();
        var outSize = Marshal.SizeOf<RgControlReply>();
        var input = Marshal.AllocHGlobal(inSize);
        var output = Marshal.AllocHGlobal(outSize);
        try
        {
            Marshal.StructureToPtr(request, input, false);
            var hr = FilterSendMessage(port, input, (uint)inSize, output, (uint)outSize, out var returned);
            if (hr != 0) throw new InvalidOperationException($"FilterSendMessage failed HRESULT=0x{hr:X8}.");
            if (returned != outSize) throw new InvalidDataException($"Unexpected control reply size: {returned}.");
            return Marshal.PtrToStructure<RgControlReply>(output);
        }
        finally
        {
            Marshal.FreeHGlobal(input);
            Marshal.FreeHGlobal(output);
        }
    }

    public static SafeFileHandle OpenPreflight(string path)
    {
        const uint FileReadAttributes = 0x00000080;
        const uint ShareRead = 0x00000001;
        const uint OpenExisting = 3;
        const uint FileAttributeNormal = 0x00000080;

        // Hold a read-shared handle through activation. This deliberately denies coexistence with
        // pre-existing write/delete handles and prevents new write/delete handles from racing the scan.
        var handle = CreateFileW(path, FileReadAttributes, ShareRead,
            IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"Activation preflight could not open '{path}'.");
        }
        return handle;
    }

    public static SafeFileHandle OpenPreflightDirectory(string path)
    {
        const uint FileReadAttributes = 0x00000080;
        const uint ShareRead = 0x00000001;
        const uint OpenExisting = 3;
        const uint FileFlagBackupSemantics = 0x02000000;

        var handle = CreateFileW(path, FileReadAttributes, ShareRead,
            IntPtr.Zero, OpenExisting, FileFlagBackupSemantics, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error,
                $"Activation topology preflight could not hold directory '{path}' with read-only sharing.");
        }
        return handle;
    }

    public static void Cancel(SafeFileHandle handle) { if (!handle.IsInvalid) _ = CancelIoEx(handle, IntPtr.Zero); }
}
