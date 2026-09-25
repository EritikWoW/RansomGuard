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

if (options.Profile == GateProfile.Production)
    ProductionRootPolicy.Validate(options.Root);
else
    LabRootPolicy.Validate(options.Root);

if (PathPolicy.Under(options.StoreRoot, options.Root))
    throw new InvalidOperationException("Rollback store must be outside the protected root.");
if (options.Profile == GateProfile.Production)
{
    if (!Directory.Exists(options.StoreRoot))
        throw new DirectoryNotFoundException(
            $"Production rollback store is not initialized: {options.StoreRoot}. The service must initialize its protected store first.");
}
else
{
    Directory.CreateDirectory(options.StoreRoot);
}
var repository = new RollbackRepository(options.StoreRoot);
repository.VerifyAll(); // Refuse to start a new gate session on top of ambiguous/crash-damaged rollback state.
var restartSummary = await RestartReconciliation.ObservePendingAsync(
    repository,
    options.Root,
    checked(options.MaxStoreMiB * RollbackStorageBudget.MiB),
    checked(options.MinFreeMiB * RollbackStorageBudget.MiB),
    CancellationToken.None).ConfigureAwait(false);
if (options.ReconcileOnly)
{
    Console.WriteLine(
        $"RECONCILE ONLY: observed={restartSummary.Observed}; completed-evidence={restartSummary.SupportsCompleted}; not-completed-evidence={restartSummary.SupportsNotCompleted}; ambiguous={restartSummary.Ambiguous}");
    return;
}
var sessionId = options.SessionId ?? $"gate-{DateTime.UtcNow:yyyyMMdd-HHmmss}-{Guid.NewGuid():N}";
var store = repository.CreateSession(sessionId);
var lifecycleStore = new RollbackSessionLifecycleStore(store.Root);
var writeStore = new RangeRollbackStore(Path.Combine(store.Root, "write-cow"));
var createStore = new CreateRollbackStore(Path.Combine(store.Root, "create-state"));
var createOperationStore = new CreateOperationStore(Path.Combine(store.Root, "create-state"));
var identityStore = new FileIdentityStore(Path.Combine(store.Root, "identity-state"));
var renameStore = new RenameRollbackStore(Path.Combine(store.Root, "rename-state"));
var truncateStore = new TruncateOperationStore(Path.Combine(store.Root, "truncate-state"));
var deleteStore = new DeleteOperationStore(Path.Combine(store.Root, "delete-state"));
var pagingStore = new PagingWriteEvidenceStore(Path.Combine(store.Root, "paging-state"));
var sectionStore = new WritableSectionEvidenceStore(Path.Combine(store.Root, "section-state"));
var activationStore = new ActivationPreflightStore(Path.Combine(store.Root, "activation-state"));
var topologyStore = new ActivationTopologyStore(Path.Combine(store.Root, "activation-topology-state"));
var containmentStore = new ContainmentEvidenceStore(Path.Combine(store.Root, "containment-state"));
var storageBudget = new RollbackStorageBudget(
    store.Root,
    checked(options.MaxStoreMiB * RollbackStorageBudget.MiB),
    checked(options.MinFreeMiB * RollbackStorageBudget.MiB));
var ntScope = DevicePathResolver.ToNtScope(options.Root);
var ntRoot = ntScope.Root;
var ntVolume = ntScope.Volume;
var productVersion = System.Reflection.Assembly.GetEntryAssembly()?.GetName().Version?.ToString() ?? "unknown";

Console.WriteLine($"RansomGuard {(options.Profile == GateProfile.Production ? "PRODUCTION" : "LAB")} pre-write gate v{productVersion}");
Console.WriteLine(options.Profile == GateProfile.Production
    ? "ProductionGate profile: LAB fault-injection and containment controls are disabled."
    : "LAB ONLY: use only inside a disposable test directory on a test machine/VM.");
Console.WriteLine($"Protected root     : {options.Root}");
Console.WriteLine($"Kernel NT root     : {ntRoot}");
Console.WriteLine($"Kernel NT volume   : {ntVolume}");
Console.WriteLine($"Rollback session   : {sessionId}");
Console.WriteLine($"Rollback store     : {store.Root}");
Console.WriteLine($"Restart evidence   : observed={restartSummary.Observed}, completed-evidence={restartSummary.SupportsCompleted}, not-completed-evidence={restartSummary.SupportsNotCompleted}, ambiguous={restartSummary.Ambiguous}");
Console.WriteLine("CREATE/write/rename/delete/truncate in this root are gated by durable preservation semantics.");
Console.WriteLine($"Bounded gate workers : {options.GateWorkers}");
Console.WriteLine($"Rollback budget      : max-session={options.MaxStoreMiB} MiB; min-free={options.MinFreeMiB} MiB");
if (options.DropFirstCreateCompletion)
    Console.WriteLine("LAB completion-loss injection : ARMED for the first authoritative CREATE result.");
if (options.DropFirstRenameCompletion)
    Console.WriteLine("LAB completion-loss injection : ARMED for the first authoritative RENAME result.");
if (options.DropFirstTruncateCompletion)
    Console.WriteLine("LAB completion-loss injection : ARMED for the first authoritative TRUNCATE result.");
if (options.DropFirstDeleteCompletion)
    Console.WriteLine("LAB completion-loss injection : ARMED for the first authoritative DELETE disposition result.");
Console.WriteLine("Press Ctrl+C for a clean shutdown. A clean, transaction-complete session explicitly deactivates the gate before disconnect.");
Console.WriteLine("Abrupt GateClient loss after activation leaves the kernel in DEGRADED_PROTECTED for the retained root/profile.");

var context = new RgConnectContext
{
    ProtocolVersion = ProtocolContract.Version,
    ClientMode = (uint)(options.Profile == GateProfile.Production
        ? RgClientMode.ProductionGate
        : RgClientMode.LabGate),
    ClientProcessId = (ulong)Environment.ProcessId,
    GateRootLengthBytes = checked((uint)(ntRoot.Length * 2)),
    GateVolumeLengthBytes = checked((uint)(ntVolume.Length * 2)),
    GateRoot = ntRoot
};

using var port = Native.Connect(PortName, context);
using var cts = new CancellationTokenSource();
var productionServiceShutdownAuthorized = 0;
Console.CancelKeyPress += (_, e) => { e.Cancel = true; cts.Cancel(); Native.Cancel(port); };

async Task MonitorServiceControlAsync()
{
    if (!options.ServiceControlStdin)
        return;

    try
    {
        while (!cts.IsCancellationRequested)
        {
            var line = await Console.In.ReadLineAsync().WaitAsync(cts.Token).ConfigureAwait(false);
            if (line is null)
            {
                // The supervising service disappeared or closed its private control pipe.
                // Never translate that failure into an authorized whole-gate deactivation.
                cts.Cancel();
                Native.Cancel(port);
                try { Console.Error.WriteLine("Production service control channel closed unexpectedly; disconnect will remain fail-safe."); }
                catch (IOException) { }
                return;
            }
            if (!string.Equals(line, "shutdown", StringComparison.Ordinal))
            {
                Console.Error.WriteLine("Production service control ignored an unknown command.");
                continue;
            }

            Interlocked.Exchange(ref productionServiceShutdownAuthorized, 1);
            Console.WriteLine($"RG-LIFECYCLE STOPPING schema=1 pid={Environment.ProcessId} session={sessionId}");
            cts.Cancel();
            Native.Cancel(port);
            return;
        }
    }
    catch (OperationCanceledException) when (cts.IsCancellationRequested)
    {
    }
}

async Task MonitorShutdownFileAsync()
{
    if (string.IsNullOrWhiteSpace(options.ShutdownFile))
        return;

    try
    {
        while (!cts.IsCancellationRequested)
        {
            if (File.Exists(options.ShutdownFile))
            {
                Console.WriteLine($"LAB graceful shutdown marker observed: {options.ShutdownFile}");
                cts.Cancel();
                Native.Cancel(port);
                return;
            }
            await Task.Delay(100, cts.Token).ConfigureAwait(false);
        }
    }
    catch (OperationCanceledException) when (cts.IsCancellationRequested)
    {
    }
}
var serviceControlMonitor = MonitorServiceControlAsync();
var shutdownMonitor = MonitorShutdownFileAsync();

var headerSize = Marshal.SizeOf<FilterMessageHeader>();
var eventSize = Marshal.SizeOf<RgEvent>();
var replyHeaderSize = Marshal.SizeOf<FilterReplyHeader>();
var gateReplySize = Marshal.SizeOf<RgGateReply>();
if (headerSize != 16 || eventSize != 2168 || replyHeaderSize != 16 || gateReplySize != 24 ||
    Marshal.SizeOf<RgControlRequest>() != 16 || Marshal.SizeOf<RgControlReply>() != 32)
    throw new InvalidOperationException($"Unexpected protocol sizes: message={headerSize}, event={eventSize}, replyHeader={replyHeaderSize}, gateReply={gateReplySize}");

var resolver = new DevicePathResolver();
var activationSummary = await ActivationPreflight.RunAsync(
    port, options.Root, resolver, activationStore, topologyStore, storageBudget,
    options.Profile == GateProfile.Lab ? options.ContainPid : null, cts.Token).ConfigureAwait(false);
Console.WriteLine($"Activation preflight: directories={activationSummary.DirectoriesHeld}, files={activationSummary.FilesChecked}, writable-views=0, kernel gate ACTIVE.");
Console.WriteLine(activationSummary.ContainedProcessId is ulong containedPid
    ? $"LAB containment  : ACTIVE for kernel-bound process pid={containedPid}; abrupt disconnect clears only this PEPROCESS latch while root protection degrades fail-safe."
    : options.Profile == GateProfile.Production
        ? "Production containment: disabled by profile."
        : "LAB containment  : not pre-armed.");
if (options.Profile == GateProfile.Production && options.ServiceControlStdin)
    Console.WriteLine($"RG-LIFECYCLE READY schema=1 pid={Environment.ProcessId} session={sessionId} profile=ProductionGate");

if (options.Profile == GateProfile.Lab && options.ScopeAmbiguityPid is ulong scopeAmbiguityPid)
{
    var ambiguityReply = Native.Control(port, new RgControlRequest
    {
        ProtocolVersion = ProtocolContract.Version,
        Command = (uint)RgControlCommand.ArmScopeAmbiguity,
        TargetProcessId = scopeAmbiguityPid
    });
    if (ambiguityReply.ProtocolVersion != ProtocolContract.Version ||
        ambiguityReply.Command != (uint)RgControlCommand.ArmScopeAmbiguity ||
        ambiguityReply.Status != 0 ||
        ambiguityReply.GateActivated != 1 ||
        ambiguityReply.ProtectionState != (uint)RgProtectionState.Protected)
        throw new InvalidOperationException(
            $"Kernel refused LAB scope-ambiguity probe arm for pid={scopeAmbiguityPid}. NTSTATUS=0x{ambiguityReply.Status:X8}, state={(RgProtectionState)ambiguityReply.ProtectionState}.");

    Console.WriteLine($"LAB scope ambiguity : ARMED for exact kernel process pid={scopeAmbiguityPid}; next destructive callback is forced name-unresolved.");
}

using var containmentTrigger = options.Profile == GateProfile.Lab && options.ContainAfterPid is int triggerPid
    ? new LabContainmentTrigger(triggerPid, options.ContainAfterEvents, options.ContainAfterPaths)
    : null;
if (containmentTrigger is not null)
    Console.WriteLine($"LAB transition   : pid={containmentTrigger.ProcessId}; after={options.ContainAfterEvents} preserved mutations across {options.ContainAfterPaths} paths; event-bound PEPROCESS latch.");

using var workerSlots = new SemaphoreSlim(options.GateWorkers, options.GateWorkers);
var activeWorkers = new List<Task>();
var replySync = new object();
var gateWorkerFailures = 0;
var droppedCreateCompletion = 0;
var droppedRenameCompletion = 0;
var droppedTruncateCompletion = 0;
var droppedDeleteCompletion = 0;
var buffer = Marshal.AllocHGlobal(checked(headerSize + eventSize));

async Task ProcessMessageAsync(FilterMessageHeader header, RgEvent ev)
{
    try
    {
        if ((RgEventType)ev.EventType == RgEventType.ContainmentActivated)
        {
            if (options.Profile != GateProfile.Lab)
                throw new InvalidDataException("ProductionGate received forbidden containment activation evidence.");
            if (ev.ProtocolVersion != ProtocolContract.Version ||
                ev.RelatedSequence == 0 ||
                ev.ProcessId <= 4 ||
                ev.CompletionStatus != 0)
                throw new InvalidDataException("Invalid containment activation evidence event.");

            var request = containmentStore.Records.SingleOrDefault(x =>
                x.Phase == ContainmentEvidencePhase.Requested &&
                x.KernelSequence == ev.RelatedSequence);
            var activationPath = resolver.Resolve(ev.Path);
            if (request is null ||
                request.ProcessId != ev.ProcessId ||
                string.IsNullOrWhiteSpace(activationPath) ||
                !PathPolicy.Under(activationPath, options.Root) ||
                !Path.GetFullPath(activationPath).Equals(request.Path, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException("Containment activation evidence has no exact durable request/path binding.");

            await using (var reservation = await storageBudget.ReserveAsync(
                             RollbackStorageBudget.MetadataReservationBytes,
                             "containment-kernel-active",
                             cts.Token).ConfigureAwait(false))
            {
                _ = await containmentStore.RecordKernelActiveAsync(
                    request.KernelSequence,
                    request.ProcessId,
                    request.ProcessCreationFileTimeUtc,
                    request.EventType,
                    request.Path,
                    request.PreservationDecision,
                    request.EvidenceCount,
                    request.DistinctPathCount,
                    ev.CompletionStatus,
                    ev.ProcessId,
                    cts.Token).ConfigureAwait(false);
            }

            Console.WriteLine(
                $"LAB CONTAINMENT ACTIVE: pid={ev.ProcessId}; exact gate sequence={ev.RelatedSequence}; process-object latch confirmed by kernel evidence.");
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.WritableSection)
        {
            if (ev.ProtocolVersion != ProtocolContract.Version ||
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
            if (ev.ProtocolVersion != ProtocolContract.Version || ev.PathStatus != (uint)RgPathStatus.Resolved)
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
            if (options.DropFirstCreateCompletion &&
                Interlocked.CompareExchange(ref droppedCreateCompletion, 1, 0) == 0)
            {
                Console.Error.WriteLine(
                    $"LAB COMPLETION LOSS: intentionally dropping authoritative CREATE result request={ev.RelatedSequence}; status=0x{ev.CompletionStatus:X8}; exiting cleanly for restart reconciliation.");
                cts.Cancel();
                Native.Cancel(port);
                return;
            }

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
            if (options.DropFirstRenameCompletion &&
                Interlocked.CompareExchange(ref droppedRenameCompletion, 1, 0) == 0)
            {
                Console.Error.WriteLine(
                    $"LAB COMPLETION LOSS: intentionally dropping authoritative RENAME result request={ev.RelatedSequence}; status=0x{ev.CompletionStatus:X8}; exiting cleanly for restart reconciliation.");
                cts.Cancel();
                Native.Cancel(port);
                return;
            }

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

        if ((RgEventType)ev.EventType == RgEventType.TruncateResult)
        {
            if (options.DropFirstTruncateCompletion &&
                Interlocked.CompareExchange(ref droppedTruncateCompletion, 1, 0) == 0)
            {
                Console.Error.WriteLine(
                    $"LAB COMPLETION LOSS: intentionally dropping authoritative TRUNCATE result request={ev.RelatedSequence}; status=0x{ev.CompletionStatus:X8}; exiting cleanly for restart reconciliation.");
                cts.Cancel();
                Native.Cancel(port);
                return;
            }

            await using var truncateResultReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "truncate-completion-evidence",
                cts.Token).ConfigureAwait(false);
            var completion = await TruncateReconciliation.HandleAsync(
                ev, truncateStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.TruncateResult,-20} request={ev.RelatedSequence,-7} {completion.State,-36} status=0x{completion.CompletionStatus:X8} observed={completion.ObservedLength}");
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.DeleteDispositionResult)
        {
            if (options.DropFirstDeleteCompletion &&
                Interlocked.CompareExchange(ref droppedDeleteCompletion, 1, 0) == 0)
            {
                Console.Error.WriteLine(
                    $"LAB COMPLETION LOSS: intentionally dropping authoritative DELETE disposition result request={ev.RelatedSequence}; status=0x{ev.CompletionStatus:X8}; exiting cleanly for restart reconciliation.");
                cts.Cancel();
                Native.Cancel(port);
                return;
            }

            await using var deleteResultReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "delete-completion-evidence",
                cts.Token).ConfigureAwait(false);
            var completion = await DeleteReconciliation.HandleDispositionAsync(
                ev, deleteStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.DeleteDispositionResult,-20} request={ev.RelatedSequence,-7} {completion.State,-30} status=0x{completion.CompletionStatus:X8} pending={completion.DeletePending}");
            return;
        }

        if ((RgEventType)ev.EventType == RgEventType.DeleteFinalized)
        {
            await using var deleteFinalizationReservation = await storageBudget.ReserveAsync(
                RollbackStorageBudget.MetadataReservationBytes,
                "delete-finalization-evidence",
                cts.Token).ConfigureAwait(false);
            var finalization = await DeleteReconciliation.HandleFinalizationAsync(
                ev, deleteStore, cts.Token).ConfigureAwait(false);
            Console.WriteLine(
                $"{DateTime.Now:HH:mm:ss.fff} {RgEventType.DeleteFinalized,-20} request={ev.RelatedSequence,-7} {finalization.State,-28} source={finalization.Source} path-state={finalization.PathState}");

            if (finalization.State == DeleteFinalizationState.CleanupObserved)
            {
                // Cleanup is handle-lifecycle evidence, not proof that the pathname has vanished.
                // Give Close a short bounded window to finish, then probe topology separately.
                await Task.Delay(100, cts.Token).ConfigureAwait(false);
                await using var topologyReservation = await storageBudget.ReserveAsync(
                    RollbackStorageBudget.MetadataReservationBytes,
                    "delete-live-topology-evidence",
                    cts.Token).ConfigureAwait(false);
                var topology = await DeleteReconciliation.ObserveTopologyAsync(
                    ev.RelatedSequence,
                    DeleteFinalizationSource.LivePostCleanupProbe,
                    deleteStore,
                    cts.Token).ConfigureAwait(false);
                Console.WriteLine(
                    $"{DateTime.Now:HH:mm:ss.fff} DELETE topology probe       request={ev.RelatedSequence,-7} {topology.State,-28} source={topology.Source} path-state={topology.PathState}");
            }
            return;
        }

        var reply = await GateDecision.EvaluateAsync(
            ev, resolver, options.Root, store, writeStore, createStore, createOperationStore,
            identityStore, renameStore, truncateStore, deleteStore, storageBudget, cts.Token).ConfigureAwait(false);

        var path = resolver.Resolve(ev.Path) ?? ev.Path ?? "<unresolved>";
        ContainmentTriggerEvidence? containmentRequest = null;
        if (containmentTrigger is not null &&
            containmentTrigger.TryRequest(ev, reply, path, out var triggerEvidence))
        {
            containmentRequest = triggerEvidence;
            await using (var reservation = await storageBudget.ReserveAsync(
                             RollbackStorageBudget.MetadataReservationBytes,
                             "containment-request",
                             cts.Token).ConfigureAwait(false))
            {
                _ = await containmentStore.RecordRequestAsync(
                    ev.Sequence,
                    ev.ProcessId,
                    triggerEvidence.ProcessCreationFileTimeUtc,
                    ev.EventType,
                    path,
                    (uint)reply.Decision,
                    triggerEvidence.EvidenceCount,
                    triggerEvidence.DistinctPathCount,
                    cts.Token).ConfigureAwait(false);
            }
            reply.Flags |= (uint)RgGateReplyFlags.ContainRequestor;
        }

        lock (replySync)
        {
            Native.Reply(port, header.MessageId, reply);
        }

        if (containmentRequest is not null)
        {
            Console.WriteLine(
                $"LAB containment requested: pid={ev.ProcessId}; exact gate sequence={ev.Sequence}; awaiting no-reply kernel activation evidence.");
        }

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
        Interlocked.Increment(ref gateWorkerFailures);
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
        var worker = Task.Run(() => ProcessMessageAsync(header, ev));

        // The communication port is opened with FLT_PORT_FLAG_SYNC_HANDLE. A second blocking
        // FilterGetMessage on that same synchronous handle can serialize ahead of a worker's
        // FilterReplyMessage and starve the kernel waiter until RG_GATE_TIMEOUT_MS expires.
        // Therefore every request that requires a reply is completed before this receive loop
        // issues the next FilterGetMessage. No-reply evidence may remain concurrently bounded.
        if (GateMessagePolicy.RequiresReply((RgEventType)ev.EventType))
        {
            await worker.ConfigureAwait(false);
        }
        else
        {
            activeWorkers.Add(worker);
        }
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
    if (!cts.IsCancellationRequested)
        cts.Cancel();
    await serviceControlMonitor.ConfigureAwait(false);
    await shutdownMonitor.ConfigureAwait(false);
}

repository.VerifyAll();
var pendingCreateCount = createOperationStore.PendingIntents.Count;
var pendingRenameCount = renameStore.PendingIntents.Count;
var pendingTruncateCount = truncateStore.PendingIntents.Count;
var unsettledDeleteCount = deleteStore.UnsettledIntents.Count;
var containmentRecords = containmentStore.Records;
var pendingContainmentAckCount = containmentRecords.Count(x =>
    x.Phase == ContainmentEvidencePhase.Requested &&
    !containmentRecords.Any(y =>
        y.Phase == ContainmentEvidencePhase.KernelActive &&
        y.KernelSequence == x.KernelSequence));
var workerFailureCount = Volatile.Read(ref gateWorkerFailures);
var productionShutdownAuthorized =
    options.Profile != GateProfile.Production ||
    !options.ServiceControlStdin ||
    Volatile.Read(ref productionServiceShutdownAuthorized) == 1;
var cleanShutdown = productionShutdownAuthorized &&
                    workerFailureCount == 0 &&
                    pendingCreateCount == 0 &&
                    pendingRenameCount == 0 &&
                    pendingTruncateCount == 0 &&
                    unsettledDeleteCount == 0 &&
                    pendingContainmentAckCount == 0;
var lifecycleReason = !productionShutdownAuthorized
    ? "gate-shutdown-faulted:production-service-shutdown-not-authorized"
    : cleanShutdown
        ? "clean-gate-shutdown"
        : $"gate-shutdown-faulted:workers={workerFailureCount};pending-create={pendingCreateCount};pending-rename={pendingRenameCount};pending-truncate={pendingTruncateCount};unsettled-delete={unsettledDeleteCount};pending-containment-ack={pendingContainmentAckCount}";

await using (var lifecycleReservation = await storageBudget.ReserveAsync(
                 RollbackStorageBudget.MetadataReservationBytes,
                 "session-lifecycle-terminal",
                 CancellationToken.None).ConfigureAwait(false))
{
    if (cleanShutdown)
    {
        _ = await lifecycleStore.MarkCompletedAsync(lifecycleReason, CancellationToken.None)
            .ConfigureAwait(false);
        Console.WriteLine("Rollback session lifecycle: Completed.");
    }
    else
    {
        _ = await lifecycleStore.MarkFaultedAsync(lifecycleReason, CancellationToken.None)
            .ConfigureAwait(false);
        Console.Error.WriteLine($"Rollback session lifecycle: Faulted ({lifecycleReason}).");
    }
}

if (cleanShutdown)
{
    RgControlReply deactivationReply = default;
    const int deactivationAttempts = 30;
    for (var attempt = 1; attempt <= deactivationAttempts; attempt++)
    {
        deactivationReply = Native.Control(port, new RgControlRequest
        {
            ProtocolVersion = ProtocolContract.Version,
            Command = (uint)RgControlCommand.DeactivateGate
        });
        if (deactivationReply.Status == 0)
            break;

        if (deactivationReply.ProtocolVersion != ProtocolContract.Version ||
            deactivationReply.Command != (uint)RgControlCommand.DeactivateGate ||
            deactivationReply.GateActivated != 1 ||
            deactivationReply.ProtectionState != (uint)RgProtectionState.Maintenance)
            throw new InvalidOperationException(
                $"Kernel returned an inconsistent state while draining for deactivation. NTSTATUS=0x{deactivationReply.Status:X8}, active={deactivationReply.GateActivated}, state={(RgProtectionState)deactivationReply.ProtectionState}.");

        if (attempt == deactivationAttempts)
            throw new InvalidOperationException(
                $"Kernel remained busy for clean gate deactivation after {deactivationAttempts} attempts. NTSTATUS=0x{deactivationReply.Status:X8}.");

        await Task.Delay(100).ConfigureAwait(false);
    }

    if (deactivationReply.ProtocolVersion != ProtocolContract.Version ||
        deactivationReply.Command != (uint)RgControlCommand.DeactivateGate ||
        deactivationReply.Status != 0 ||
        deactivationReply.GateActivated != 0 ||
        deactivationReply.ContainmentActive != 0 ||
        deactivationReply.ContainedProcessId != 0 ||
        deactivationReply.ProtectionState != (uint)RgProtectionState.Maintenance)
        throw new InvalidOperationException(
            $"Kernel refused clean gate deactivation. NTSTATUS=0x{deactivationReply.Status:X8}, state={(RgProtectionState)deactivationReply.ProtectionState}.");

    Console.WriteLine("Kernel gate graceful deactivation: MAINTENANCE authorized; port close may release the retained LAB root.");
    if (options.Profile == GateProfile.Production && options.ServiceControlStdin)
        Console.WriteLine($"RG-LIFECYCLE STOPPED schema=1 pid={Environment.ProcessId} session={sessionId} clean=1");
}
else
{
    Console.Error.WriteLine("Kernel gate graceful deactivation NOT authorized; disconnect must remain fail-safe for the retained LAB root.");
    if (options.Profile == GateProfile.Production && options.ServiceControlStdin)
        Console.WriteLine($"RG-LIFECYCLE STOPPED schema=1 pid={Environment.ProcessId} session={sessionId} clean=0");
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
        ulong? containPid,
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
                    ProtocolVersion = ProtocolContract.Version,
                    Command = (uint)RgControlCommand.ArmPreflight
                });
                if (arm.ProtocolVersion != ProtocolContract.Version ||
                    arm.Command != (uint)RgControlCommand.ArmPreflight ||
                    arm.Status != 0 ||
                    arm.GateActivated != 0 ||
                    arm.ProtectionState != (uint)RgProtectionState.Preflight)
                    throw new InvalidOperationException(
                        $"Kernel refused to arm activation preflight for '{path}'. NTSTATUS=0x{arm.Status:X8}.");

                // First issue an attribute-only probe that deliberately shares READ/WRITE/DELETE.
                // This lets the minifilter inspect the existing section object even when a writable
                // mapping already keeps a write-capable file object alive.
                using var probe = Native.OpenPreflightProbe(path);
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

                // Only after kernel attestation is clean do we acquire the share-sensitive hold.
                // Keep the probe open until the hold exists, then verify the held object is the same
                // FILE_ID_INFO so a rename/replace race cannot silently swap the file between phases.
                var hold = Native.OpenPreflightHold(path);
                var holdIdentity = FileIdentityStore.QueryHandleIdentity(hold);
                if (!identity.Equals(holdIdentity))
                {
                    hold.Dispose();
                    throw new InvalidOperationException(
                        $"Activation refused: file identity changed while freezing '{path}'.");
                }

                var linkCount = FileIdentityStore.QueryHandleLinkCount(hold);
                if (linkCount != 1)
                {
                    hold.Dispose();
                    throw new InvalidOperationException(
                        $"Activation refused: '{path}' has NumberOfLinks={linkCount}; protected regular files must have exactly one hard link.");
                }

                heldHandles.Add(hold);

                checkedFiles++;
            }

            var activationCommand = containPid.HasValue
                ? RgControlCommand.ActivateAndContainProcess
                : RgControlCommand.ActivateGate;
            var activationReply = Native.Control(port, new RgControlRequest
            {
                ProtocolVersion = ProtocolContract.Version,
                Command = (uint)activationCommand,
                TargetProcessId = containPid ?? 0
            });
            if (activationReply.ProtocolVersion != ProtocolContract.Version ||
                activationReply.Command != (uint)activationCommand ||
                activationReply.Status != 0 ||
                activationReply.GateActivated != 1 ||
                activationReply.ProtectionState != (uint)RgProtectionState.Protected)
                throw new InvalidOperationException(
                    $"Kernel refused LAB activation after preflight. NTSTATUS=0x{activationReply.Status:X8}, active={activationReply.GateActivated}.");

            if (containPid.HasValue &&
                (activationReply.ContainmentActive != 1 ||
                 activationReply.ContainedProcessId != containPid.Value))
                throw new InvalidOperationException(
                    $"Kernel activation did not bind requested containment pid={containPid.Value}. active={activationReply.ContainmentActive}, pid={activationReply.ContainedProcessId}.");
            if (!containPid.HasValue &&
                (activationReply.ContainmentActive != 0 ||
                 activationReply.ContainedProcessId != 0))
                throw new InvalidOperationException("Kernel reported unexpected containment on a normal LAB activation.");

            return new ActivationPreflightSummary(checkedFiles, heldDirectories, containPid);
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
                if (ev.ProtocolVersion != ProtocolContract.Version || ev.PathStatus != (uint)RgPathStatus.Resolved)
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

readonly record struct ActivationPreflightSummary(int FilesChecked, int DirectoriesHeld, ulong? ContainedProcessId);

static class CreateReconciliation
{
    public static async Task<CreateOperationCompletion> HandleAsync(
        RgEvent ev,
        DevicePathResolver resolver,
        string root,
        CreateOperationStore operationStore,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != ProtocolContract.Version || ev.RelatedSequence == 0)
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
        if (ev.ProtocolVersion != ProtocolContract.Version || ev.RelatedSequence == 0)
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

static class TruncateReconciliation
{
    public static async Task<TruncateOperationCompletion> HandleAsync(
        RgEvent ev,
        TruncateOperationStore store,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != ProtocolContract.Version || ev.RelatedSequence == 0)
            throw new InvalidDataException("Invalid TRUNCATE completion correlation.");

        var intent = store.Intents.SingleOrDefault(x => x.RequestSequence == ev.RelatedSequence)
            ?? throw new InvalidDataException("TRUNCATE result has no committed intent.");
        if (ev.FileInformationClass != intent.FileInformationClass)
            throw new InvalidDataException("TRUNCATE result information class does not match its intent.");

        if (!NtSuccess(ev.CompletionStatus))
        {
            return await store.RecordCompletionAsync(
                    ev.RelatedSequence,
                    TruncateCompletionState.Failed,
                    ev.CompletionStatus,
                    ev.CompletionInformation,
                    -1,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        DurableFileIdentity? identity = null;
        if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
            (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
        {
            identity = new DurableFileIdentity(
                ev.VolumeSerialNumber.ToString("X16"),
                ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
        }

        var metricResolved = intent.Metric != TruncateMetric.ValidDataLength && ev.ByteOffset >= 0;
        var identityResolved = identity is not null;
        var state = (metricResolved, identityResolved) switch
        {
            (true, true) => TruncateCompletionState.Succeeded,
            (false, true) => TruncateCompletionState.SucceededMetricUnresolved,
            (true, false) => TruncateCompletionState.SucceededIdentityUnresolved,
            _ => TruncateCompletionState.SucceededMetricAndIdentityUnresolved
        };

        return await store.RecordCompletionAsync(
                ev.RelatedSequence,
                state,
                ev.CompletionStatus,
                ev.CompletionInformation,
                metricResolved ? ev.ByteOffset : -1,
                identity,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;
}

static class DeleteReconciliation
{
    private const uint DeletePendingFlag = 0x00000004;
    private const uint DeleteCancelledFlag = 0x00000008;
    private const uint DeleteCleanupFlag = 0x00000010;
    private const uint DeleteStateResolvedFlag = 0x00000020;

    public static async Task<DeleteDispositionCompletion> HandleDispositionAsync(
        RgEvent ev,
        DeleteOperationStore store,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != ProtocolContract.Version || ev.RelatedSequence == 0)
            throw new InvalidDataException("Invalid DELETE disposition completion correlation.");

        var intent = store.Intents.SingleOrDefault(x => x.RequestSequence == ev.RelatedSequence)
            ?? throw new InvalidDataException("DELETE disposition result has no committed intent.");
        if (ev.FileInformationClass != intent.FileInformationClass)
            throw new InvalidDataException("DELETE disposition result information class does not match its intent.");

        if (!NtSuccess(ev.CompletionStatus))
        {
            return await store.RecordCompletionAsync(
                    ev.RelatedSequence,
                    DeleteDispositionCompletionState.Failed,
                    ev.CompletionStatus,
                    ev.CompletionInformation,
                    null,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        DurableFileIdentity? identity = null;
        if (ev.IdentityStatus == (uint)RgIdentityStatus.Resolved &&
            (ev.VolumeSerialNumber != 0 || ev.FileIdLow != 0 || ev.FileIdHigh != 0))
        {
            identity = new DurableFileIdentity(
                ev.VolumeSerialNumber.ToString("X16"),
                ev.FileIdLow.ToString("X16") + ev.FileIdHigh.ToString("X16"));
        }

        var stateResolved = (ev.Flags & DeleteStateResolvedFlag) != 0;
        bool? deletePending = stateResolved
            ? (ev.Flags & DeletePendingFlag) != 0
            : null;

        var state = deletePending switch
        {
            true => DeleteDispositionCompletionState.AcceptedDeletePending,
            false => DeleteDispositionCompletionState.AcceptedDeleteNotPending,
            null => DeleteDispositionCompletionState.AcceptedStateUnresolved
        };

        return await store.RecordCompletionAsync(
                ev.RelatedSequence,
                state,
                ev.CompletionStatus,
                ev.CompletionInformation,
                deletePending,
                identity,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task<DeleteFinalizationObservation> HandleFinalizationAsync(
        RgEvent ev,
        DeleteOperationStore store,
        CancellationToken cancellationToken)
    {
        if (ev.ProtocolVersion != ProtocolContract.Version || ev.RelatedSequence == 0)
            throw new InvalidDataException("Invalid DELETE finalization correlation.");

        var intent = store.Intents.SingleOrDefault(x => x.RequestSequence == ev.RelatedSequence)
            ?? throw new InvalidDataException("DELETE finalization has no committed intent.");

        if ((ev.Flags & DeleteCancelledFlag) != 0)
        {
            return await store.RecordFinalizationAsync(
                    intent,
                    DeleteFinalizationSource.DispositionCancellation,
                    DeleteFinalizationState.Cancelled,
                    RestartPathState.QueryFailed,
                    null,
                    cancellationToken)
                .ConfigureAwait(false);
        }

        if ((ev.Flags & DeleteCleanupFlag) == 0)
            throw new InvalidDataException("DELETE finalization is neither cancellation nor cleanup evidence.");
        if (!NtSuccess(ev.CompletionStatus))
            throw new InvalidDataException(
                $"DELETE cleanup callback failed with NTSTATUS 0x{ev.CompletionStatus:X8}.");

        return await store.RecordFinalizationAsync(
                intent,
                DeleteFinalizationSource.KernelCleanup,
                DeleteFinalizationState.CleanupObserved,
                RestartPathState.QueryFailed,
                null,
                cancellationToken)
            .ConfigureAwait(false);
    }

    public static async Task<DeleteFinalizationObservation> ObserveTopologyAsync(
        ulong requestSequence,
        DeleteFinalizationSource source,
        DeleteOperationStore store,
        CancellationToken cancellationToken)
    {
        if (source is not
            (DeleteFinalizationSource.LivePostCleanupProbe or DeleteFinalizationSource.RestartProbe))
            throw new ArgumentOutOfRangeException(nameof(source));

        var intent = store.Intents.SingleOrDefault(x => x.RequestSequence == requestSequence)
            ?? throw new InvalidDataException("DELETE topology probe has no committed intent.");
        var current = PathProbe.ObserveForRestart(intent.OriginalPath);
        var state = DeleteOperationStore.ClassifyPathObservation(
            intent, current.State, current.Identity);
        return await store.RecordFinalizationAsync(
                intent,
                source,
                state,
                current.State,
                current.Identity,
                cancellationToken)
            .ConfigureAwait(false);
    }

    private static bool NtSuccess(uint status) => (status & 0x80000000u) == 0;
}

static class GateMessagePolicy
{
    public static bool RequiresReply(RgEventType type) =>
        type is RgEventType.Write or
            RgEventType.Rename or
            RgEventType.DeleteDisposition or
            RgEventType.Truncate or
            RgEventType.Create;
}

static class GateDecision
{
    public static async Task<RgGateReply> EvaluateAsync(RgEvent ev, DevicePathResolver resolver, string root,
        RollbackStore store, RangeRollbackStore writeStore, CreateRollbackStore createStore,
        CreateOperationStore createOperationStore, FileIdentityStore identityStore,
        RenameRollbackStore renameStore, TruncateOperationStore truncateStore,
        DeleteOperationStore deleteStore,
        RollbackStorageBudget storageBudget,
        CancellationToken cancellationToken)
    {
        try
        {
            // Never preserve or authorize against a truncated path. The kernel only sends a truncated
            // gate event when its known prefix is already inside the explicit LAB root, so deny it here.
            if (ev.ProtocolVersion != ProtocolContract.Version || ev.PathStatus != (uint)RgPathStatus.Resolved)
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

            if (eventType == RgEventType.Truncate)
                return await EvaluateTruncateAsync(ev, path, store, truncateStore,
                    identityBaseline, sourceOriginallyAbsent, storageBudget, cancellationToken)
                    .ConfigureAwait(false);

            if (eventType == RgEventType.DeleteDisposition)
                return await EvaluateDeleteAsync(ev, path, store, deleteStore,
                    identityBaseline, sourceOriginallyAbsent, storageBudget, cancellationToken)
                    .ConfigureAwait(false);

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
                throw new InvalidOperationException("Unsupported gate event type.");
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

    private static async Task<RgGateReply> EvaluateDeleteAsync(
        RgEvent ev,
        string path,
        RollbackStore store,
        DeleteOperationStore deleteStore,
        FileIdentityBaseline identityBaseline,
        bool sourceOriginallyAbsent,
        RollbackStorageBudget storageBudget,
        CancellationToken cancellationToken)
    {
        if (ev.FileInformationClass is not
            (DeleteOperationStore.FileDispositionInformation or
             DeleteOperationStore.FileDispositionInformationEx))
            return Deny(ev.Sequence, 15);

        var requestDelete = (ev.Flags & DeleteOperationStore.FileDispositionDelete) != 0;
        var preservationRecordSha256 = string.Empty;

        if (requestDelete && !sourceOriginallyAbsent)
        {
            var estimate = RollbackStorageBudget.EstimateFullPreimageBytes(store, path);
            await using var captureReservation = await storageBudget.ReserveAsync(
                estimate, "delete-full-preimage", cancellationToken).ConfigureAwait(false);
            var capture = await store.CapturePreimageAsync(
                    path,
                    RollbackMutationKind.Delete,
                    identityBaseline.Identity,
                    cancellationToken)
                .ConfigureAwait(false);
            preservationRecordSha256 = capture.RecordSha256;
        }

        _ = await deleteStore.RecordIntentAsync(
                ev.Sequence,
                path,
                ev.FileInformationClass,
                ev.Flags,
                identityBaseline.Identity,
                sourceOriginallyAbsent,
                preservationRecordSha256,
                cancellationToken)
            .ConfigureAwait(false);

        if (!requestDelete)
            return Allow(ev.Sequence, RgGateDecision.NoPreservationRequired);

        return Allow(
            ev.Sequence,
            sourceOriginallyAbsent
                ? RgGateDecision.BaselineCommitted
                : RgGateDecision.SnapshotCommitted);
    }

    private static async Task<RgGateReply> EvaluateTruncateAsync(
        RgEvent ev,
        string path,
        RollbackStore store,
        TruncateOperationStore truncateStore,
        FileIdentityBaseline identityBaseline,
        bool sourceOriginallyAbsent,
        RollbackStorageBudget storageBudget,
        CancellationToken cancellationToken)
    {
        if (ev.ByteOffset < 0)
            return Deny(ev.Sequence, 14);

        var standard = FileIdentityStore.QueryPathStandardInfo(path, identityBaseline.Identity);
        var originalObservedLength = ev.FileInformationClass switch
        {
            TruncateOperationStore.FileEndOfFileInformation => standard.EndOfFile,
            TruncateOperationStore.FileAllocationInformation => standard.AllocationSize,
            TruncateOperationStore.FileValidDataLengthInformation => -1,
            _ => throw new InvalidDataException(
                $"Unsupported TRUNCATE information class {ev.FileInformationClass}.")
        };

        var preservationRecordSha256 = string.Empty;
        if (!sourceOriginallyAbsent)
        {
            var estimate = RollbackStorageBudget.EstimateFullPreimageBytes(store, path);
            await using var captureReservation = await storageBudget.ReserveAsync(
                estimate, "truncate-full-preimage", cancellationToken).ConfigureAwait(false);
            var capture = await store.CapturePreimageAsync(
                    path, RollbackMutationKind.Write, identityBaseline.Identity, cancellationToken)
                .ConfigureAwait(false);
            preservationRecordSha256 = capture.RecordSha256;
        }

        _ = await truncateStore.RecordIntentAsync(
                ev.Sequence,
                path,
                ev.FileInformationClass,
                ev.ByteOffset,
                originalObservedLength,
                identityBaseline.Identity,
                sourceOriginallyAbsent,
                preservationRecordSha256,
                cancellationToken)
            .ConfigureAwait(false);

        return Allow(
            ev.Sequence,
            sourceOriginallyAbsent
                ? RgGateDecision.BaselineCommitted
                : RgGateDecision.SnapshotCommitted);
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
        ProtocolVersion = ProtocolContract.Version,
        Decision = decision,
        RequestSequence = sequence,
        ErrorCode = 0
    };

    private static RgGateReply Deny(ulong sequence, uint errorCode) => new()
    {
        ProtocolVersion = ProtocolContract.Version,
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

            var truncateRoot = Path.Combine(session.Root, "truncate-state");
            if (Directory.Exists(truncateRoot))
            {
                var truncates = new TruncateOperationStore(truncateRoot);
                foreach (var intent in truncates.PendingIntents)
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!PathPolicy.Under(intent.OriginalPath, currentRoot))
                        continue;

                    var current = PathProbe.ObserveTruncateForRestart(intent.OriginalPath, intent.Metric);
                    var evidence = TruncateOperationStore.ClassifyRestart(
                        intent, current.PathState, current.Identity, current.ObservedLength);
                    await using var restartTruncateReservation = await storageBudget.ReserveAsync(
                        RollbackStorageBudget.MetadataReservationBytes,
                        "restart-truncate-evidence",
                        cancellationToken).ConfigureAwait(false);
                    _ = await truncates.RecordRestartObservationAsync(
                            intent,
                            evidence,
                            current.PathState,
                            current.Identity,
                            current.ObservedLength,
                            cancellationToken)
                        .ConfigureAwait(false);
                    Count(evidence, ref observed, ref supportsCompleted, ref supportsNotCompleted, ref ambiguous);
                }
            }

            var deleteRoot = Path.Combine(session.Root, "delete-state");
            if (Directory.Exists(deleteRoot))
            {
                var deletes = new DeleteOperationStore(deleteRoot);
                foreach (var intent in deletes.UnsettledIntents.Where(x => x.RequestDelete))
                {
                    cancellationToken.ThrowIfCancellationRequested();
                    if (!PathPolicy.Under(intent.OriginalPath, currentRoot))
                        continue;

                    var current = PathProbe.ObserveForRestart(intent.OriginalPath);
                    var finalizationState = DeleteOperationStore.ClassifyPathObservation(
                        intent, current.State, current.Identity);
                    await using var restartDeleteReservation = await storageBudget.ReserveAsync(
                        RollbackStorageBudget.MetadataReservationBytes,
                        "restart-delete-evidence",
                        cancellationToken).ConfigureAwait(false);
                    _ = await deletes.RecordFinalizationAsync(
                            intent,
                            DeleteFinalizationSource.RestartProbe,
                            finalizationState,
                            current.State,
                            current.Identity,
                            cancellationToken)
                        .ConfigureAwait(false);

                    var evidence = finalizationState switch
                    {
                        DeleteFinalizationState.DeletedObserved => RestartEvidenceState.SupportsCompleted,
                        DeleteFinalizationState.StillPresentSameIdentity => RestartEvidenceState.SupportsNotCompleted,
                        _ => RestartEvidenceState.Ambiguous
                    };
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

    public static TruncateRestartProbe ObserveTruncateForRestart(string path, TruncateMetric metric)
    {
        try
        {
            var attributes = File.GetAttributes(path);
            if ((attributes & FileAttributes.ReparsePoint) != 0)
                return new TruncateRestartProbe(RestartPathState.ReparsePoint, null, -1);
            if ((attributes & FileAttributes.Directory) != 0)
                return new TruncateRestartProbe(RestartPathState.Directory, null, -1);

            using var input = new FileStream(path, FileMode.Open, FileAccess.Read,
                FileShare.Read | FileShare.Write | FileShare.Delete, 4096, FileOptions.None);
            var identity = FileIdentityStore.QueryHandleIdentity(input.SafeFileHandle);
            var standard = FileIdentityStore.QueryHandleStandardInfo(input.SafeFileHandle);
            var observedLength = metric == TruncateMetric.EndOfFile ? standard.EndOfFile : -1;
            return new TruncateRestartProbe(RestartPathState.File, identity, observedLength);
        }
        catch (FileNotFoundException)
        {
            return new TruncateRestartProbe(RestartPathState.Missing, null, -1);
        }
        catch (DirectoryNotFoundException)
        {
            return new TruncateRestartProbe(RestartPathState.Missing, null, -1);
        }
        catch
        {
            return new TruncateRestartProbe(RestartPathState.QueryFailed, null, -1);
        }
    }
}

readonly record struct TruncateRestartProbe(
    RestartPathState PathState,
    DurableFileIdentity? Identity,
    long ObservedLength);

sealed record ContainmentTriggerEvidence(
    long ProcessCreationFileTimeUtc,
    int EvidenceCount,
    int DistinctPathCount);

sealed class LabContainmentTrigger : IDisposable
{
    private readonly Process _process;
    private readonly long _createdFileTimeUtc;
    private readonly int _requiredEvents;
    private readonly int _requiredPaths;
    private readonly HashSet<string> _paths = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _sync = new();
    private int _events;
    private bool _requested;

    public int ProcessId => _process.Id;

    public LabContainmentTrigger(int processId, int requiredEvents, int requiredPaths)
    {
        if (processId <= 4 || processId == Environment.ProcessId)
            throw new ArgumentOutOfRangeException(nameof(processId));
        if (requiredEvents < 2 || requiredEvents > 64)
            throw new ArgumentOutOfRangeException(nameof(requiredEvents));
        if (requiredPaths < 1 || requiredPaths > requiredEvents)
            throw new ArgumentOutOfRangeException(nameof(requiredPaths));

        _process = Process.GetProcessById(processId);
        _createdFileTimeUtc = _process.StartTime.ToUniversalTime().ToFileTimeUtc();
        _ = _process.Handle; // Hold this exact process object open; PID reuse cannot silently re-authorize a replacement.
        if (_process.HasExited)
            throw new InvalidOperationException("Containment transition target already exited.");
        _requiredEvents = requiredEvents;
        _requiredPaths = requiredPaths;
    }

    public bool TryRequest(
        RgEvent ev,
        RgGateReply reply,
        string path,
        out ContainmentTriggerEvidence evidence)
    {
        evidence = default!;
        if (ev.ProcessId != (ulong)_process.Id ||
            reply.Decision is not (RgGateDecision.SnapshotCommitted or RgGateDecision.BaselineCommitted))
            return false;

        var type = (RgEventType)ev.EventType;
        if (type is not (RgEventType.Create or RgEventType.Write or RgEventType.Rename or
            RgEventType.DeleteDisposition or RgEventType.Truncate))
            return false;

        lock (_sync)
        {
            if (_requested) return false;
            if (_process.HasExited)
                throw new InvalidOperationException("Authorized containment transition process exited before the latch.");

            _events++;
            if (!string.IsNullOrWhiteSpace(path))
                _paths.Add(Path.GetFullPath(path));

            if (_events < _requiredEvents || _paths.Count < _requiredPaths)
                return false;

            _requested = true;
            evidence = new ContainmentTriggerEvidence(
                _createdFileTimeUtc,
                _events,
                _paths.Count);
            return true;
        }
    }

    public void Dispose() => _process.Dispose();
}

enum GateProfile { Lab = 0, Production = 1 }

sealed record Options(
    GateProfile Profile,
    string Root,
    string StoreRoot,
    string? SessionId,
    bool PrepareOnly,
    int GateWorkers,
    long MaxStoreMiB,
    long MinFreeMiB,
    ulong? ContainPid,
    ulong? ScopeAmbiguityPid,
    int? ContainAfterPid,
    int ContainAfterEvents,
    int ContainAfterPaths,
    bool DropFirstCreateCompletion,
    bool DropFirstRenameCompletion,
    bool DropFirstTruncateCompletion,
    bool DropFirstDeleteCompletion,
    bool ReconcileOnly,
    bool ServiceControlStdin,
    string? ShutdownFile)
{
    public const int DefaultGateWorkers = 4;
    public const int MaxGateWorkers = 8;
    public const long DefaultMaxStoreMiB = 8192;
    public const long DefaultMinFreeMiB = 2048;
    public const long MaxConfigMiB = 1048576;
    public const int DefaultContainAfterEvents = 4;
    public const int DefaultContainAfterPaths = 2;

    public static Options Parse(string[] args)
    {
        var profile = GateProfile.Lab;
        string? root = null;
        string? store = null;
        string? session = null;
        var prepare = false;
        var gateWorkers = DefaultGateWorkers;
        long maxStoreMiB = DefaultMaxStoreMiB;
        long minFreeMiB = DefaultMinFreeMiB;
        ulong? containPid = null;
        ulong? scopeAmbiguityPid = null;
        int? containAfterPid = null;
        var containAfterEvents = DefaultContainAfterEvents;
        var containAfterPaths = DefaultContainAfterPaths;
        var containThresholdSpecified = false;
        var dropFirstCreateCompletion = false;
        var dropFirstRenameCompletion = false;
        var dropFirstTruncateCompletion = false;
        var dropFirstDeleteCompletion = false;
        var reconcileOnly = false;
        var serviceControlStdin = false;
        string? shutdownFile = null;
        for (var i = 0; i < args.Length; i++)
        {
            switch (args[i].ToLowerInvariant())
            {
                case "--production": profile = GateProfile.Production; break;
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
                case "--contain-pid" when i + 1 < args.Length:
                    if (!uint.TryParse(args[++i], out var parsedPid) || parsedPid <= 4 || parsedPid == Environment.ProcessId)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            "--contain-pid must identify a non-system process other than GateClient.");
                    containPid = parsedPid;
                    break;
                case "--scope-ambiguity-pid" when i + 1 < args.Length:
                    if (!uint.TryParse(args[++i], out var parsedScopePid) || parsedScopePid <= 4 || parsedScopePid == Environment.ProcessId)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            "--scope-ambiguity-pid must identify a non-system process other than GateClient.");
                    scopeAmbiguityPid = parsedScopePid;
                    break;
                case "--contain-after-pid" when i + 1 < args.Length:
                    if (!int.TryParse(args[++i], out var parsedTransitionPid) || parsedTransitionPid <= 4 || parsedTransitionPid == Environment.ProcessId)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            "--contain-after-pid must identify a non-system process other than GateClient.");
                    containAfterPid = parsedTransitionPid;
                    break;
                case "--contain-after-events" when i + 1 < args.Length:
                    if (!int.TryParse(args[++i], out containAfterEvents) || containAfterEvents < 2 || containAfterEvents > 64)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            "--contain-after-events must be between 2 and 64.");
                    containThresholdSpecified = true;
                    break;
                case "--contain-after-paths" when i + 1 < args.Length:
                    if (!int.TryParse(args[++i], out containAfterPaths) || containAfterPaths < 1 || containAfterPaths > 16)
                        throw new ArgumentOutOfRangeException(nameof(args),
                            "--contain-after-paths must be between 1 and 16.");
                    containThresholdSpecified = true;
                    break;
                case "--drop-first-create-completion": dropFirstCreateCompletion = true; break;
                case "--drop-first-rename-completion": dropFirstRenameCompletion = true; break;
                case "--drop-first-truncate-completion": dropFirstTruncateCompletion = true; break;
                case "--drop-first-delete-completion": dropFirstDeleteCompletion = true; break;
                case "--reconcile-only": reconcileOnly = true; break;
                case "--service-control-stdin": serviceControlStdin = true; break;
                case "--shutdown-file" when i + 1 < args.Length:
                    shutdownFile = Path.GetFullPath(args[++i]);
                    break;
                case "--prepare-root": prepare = true; break;
                default: throw new ArgumentException($"Unknown/incomplete argument: {args[i]}");
            }
        }
        if (string.IsNullOrWhiteSpace(root))
            throw new ArgumentException("Pass --root <protected-directory>.");
        if (shutdownFile is not null && PathPolicy.Under(shutdownFile, root))
            throw new ArgumentException("--shutdown-file must be outside the protected root.");
        if (prepare && (containPid.HasValue || scopeAmbiguityPid.HasValue || containAfterPid.HasValue || dropFirstCreateCompletion || dropFirstRenameCompletion || dropFirstTruncateCompletion || dropFirstDeleteCompletion || reconcileOnly || shutdownFile is not null))
            throw new ArgumentException("Containment/fault/reconciliation/shutdown options cannot be combined with --prepare-root.");
        if (reconcileOnly && (containPid.HasValue || scopeAmbiguityPid.HasValue || containAfterPid.HasValue || dropFirstCreateCompletion || dropFirstRenameCompletion || dropFirstTruncateCompletion || dropFirstDeleteCompletion || containThresholdSpecified || shutdownFile is not null))
            throw new ArgumentException("--reconcile-only cannot be combined with containment, fault injection, or a shutdown marker.");
        if ((dropFirstCreateCompletion ? 1 : 0) + (dropFirstRenameCompletion ? 1 : 0) + (dropFirstTruncateCompletion ? 1 : 0) + (dropFirstDeleteCompletion ? 1 : 0) > 1)
            throw new ArgumentException("Only one completion-loss injection may be armed per GateClient session.");
        if ((containPid.HasValue ? 1 : 0) + (scopeAmbiguityPid.HasValue ? 1 : 0) + (containAfterPid.HasValue ? 1 : 0) > 1)
            throw new ArgumentException("--contain-pid, --scope-ambiguity-pid and --contain-after-pid are mutually exclusive.");
        if (containThresholdSpecified && !containAfterPid.HasValue)
            throw new ArgumentException("Containment thresholds require --contain-after-pid.");
        if (containAfterPaths > containAfterEvents)
            throw new ArgumentException("--contain-after-paths cannot exceed --contain-after-events.");
        if (serviceControlStdin && profile != GateProfile.Production)
            throw new ArgumentException("--service-control-stdin is reserved for the ProductionGate service lifecycle.");

        if (profile == GateProfile.Production)
        {
            if (prepare || reconcileOnly || shutdownFile is not null ||
                containPid.HasValue || scopeAmbiguityPid.HasValue || containAfterPid.HasValue ||
                containThresholdSpecified || dropFirstCreateCompletion || dropFirstRenameCompletion ||
                dropFirstTruncateCompletion || dropFirstDeleteCompletion)
                throw new ArgumentException(
                    "ProductionGate forbids LAB prepare/fault/reconciliation/shutdown/containment options.");

            var fixedStore = Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "RansomGuardV03",
                "Rollback"));
            if (store is not null && !PathPolicy.Equal(store, fixedStore))
                throw new ArgumentException(
                    $"ProductionGate rollback store is fixed to '{fixedStore}'.");
            store = fixedStore;
        }
        else
        {
            store ??= Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "RansomGuardV072",
                "GateRollback");
        }

        return new Options(
            profile, root, store!, session, prepare, gateWorkers, maxStoreMiB, minFreeMiB,
            containPid, scopeAmbiguityPid, containAfterPid, containAfterEvents, containAfterPaths,
            dropFirstCreateCompletion, dropFirstRenameCompletion, dropFirstTruncateCompletion,
            dropFirstDeleteCompletion, reconcileOnly, serviceControlStdin, shutdownFile);
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

static class ProductionRootPolicy
{
    public static void Validate(string root)
    {
        var full = Path.GetFullPath(root).TrimEnd('\\');
        var drive = Path.GetPathRoot(full)?.TrimEnd('\\');
        if (string.IsNullOrWhiteSpace(drive) || drive.Length != 2 || drive[1] != ':' ||
            full.Equals(drive, StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException("ProductionGate root must be an explicit directory on a local drive.");
        if (!Directory.Exists(full))
            throw new DirectoryNotFoundException(full);

        for (var current = full; !string.IsNullOrWhiteSpace(current); current = Path.GetDirectoryName(current))
        {
            if ((File.GetAttributes(current) & FileAttributes.ReparsePoint) != 0)
                throw new InvalidOperationException("ProductionGate root/ancestor cannot be a reparse point: " + current);
            if (current.TrimEnd('\\').Equals(drive, StringComparison.OrdinalIgnoreCase))
                break;
        }

        foreach (var systemPath in new[]
        {
            Environment.GetFolderPath(Environment.SpecialFolder.Windows),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles),
            Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86),
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData)
        }.Where(x => !string.IsNullOrWhiteSpace(x)))
        {
            if (PathPolicy.Under(full, systemPath))
                throw new InvalidOperationException(
                    "ProductionGate root must not be inside Windows, Program Files, or ProgramData.");
        }
    }
}

static class PathPolicy
{
    public static bool Equal(string left, string right) =>
        Path.GetFullPath(left).TrimEnd('\\').Equals(
            Path.GetFullPath(right).TrimEnd('\\'),
            StringComparison.OrdinalIgnoreCase);

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

    public static NtScope ToNtScope(string dosRoot)
    {
        var full = Path.GetFullPath(dosRoot).TrimEnd('\\');
        var drive = Path.GetPathRoot(full)?.TrimEnd('\\') ?? throw new InvalidOperationException("No drive root.");
        if (drive.Length != 2 || drive[1] != ':') throw new InvalidOperationException("Gate protection supports local drive paths only.");
        var sb = new StringBuilder(1024);
        if (Native.QueryDosDevice(drive, sb, sb.Capacity) == 0)
            throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error(), "QueryDosDevice failed.");
        var device = sb.ToString().Split('\0')[0];
        if (string.IsNullOrWhiteSpace(device) || !device.StartsWith(@"\Device\", StringComparison.OrdinalIgnoreCase))
            throw new InvalidOperationException($"Unexpected local volume device name: '{device}'.");
        return new NtScope(device + full[drive.Length..], device);
    }

    public readonly record struct NtScope(string Root, string Volume);
}

static class ProtocolContract
{
    public const uint Version = 18;
}

enum RgClientMode : uint { Audit = 1, LabGate = 2, ProductionGate = 3 }
enum RgProtectionState : uint { Inactive = 0, Preflight = 1, Protected = 2, DegradedProtected = 3, Maintenance = 4 }
enum RgEventType : uint { Invalid = 0, Write = 1, Rename = 2, DeleteDisposition = 3, Truncate = 4, Create = 5, RenameResult = 6, CreateResult = 7, PagingWrite = 8, WritableSection = 9, ActivationPreflight = 10, ContainmentActivated = 11, TruncateResult = 12, DeleteDispositionResult = 13, DeleteFinalized = 14 }
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
    public uint GateRootLengthBytes, GateVolumeLengthBytes;
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
    public uint Flags;
}

[Flags]
enum RgGateReplyFlags : uint
{
    None = 0,
    ContainRequestor = 0x00000001
}

enum RgControlCommand : uint { Invalid = 0, ActivateGate = 1, QueryActivation = 2, ArmPreflight = 3, ActivateAndContainProcess = 4, QueryContainment = 5, DeactivateGate = 6, ArmScopeAmbiguity = 7 }

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct RgControlRequest
{
    public uint ProtocolVersion;
    public uint Command;
    public ulong TargetProcessId;
}

[StructLayout(LayoutKind.Sequential, Pack = 1)]
struct RgControlReply
{
    public uint ProtocolVersion;
    public uint Command;
    public uint Status;
    public uint GateActivated;
    public uint ContainmentActive;
    public uint ProtectionState;
    public ulong ContainedProcessId;
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

    public static SafeFileHandle OpenPreflightProbe(string path)
    {
        const uint FileReadAttributes = 0x00000080;
        const uint ShareRead = 0x00000001;
        const uint ShareWrite = 0x00000002;
        const uint ShareDelete = 0x00000004;
        const uint OpenExisting = 3;
        const uint FileAttributeNormal = 0x00000080;

        // This handle exists only to trigger the armed kernel preflight callback and inspect
        // SectionObjectPointer. Sharing all mutation modes is intentional here: a pre-existing
        // writable mapping must be observable by MmDoesFileHaveUserWritableReferences rather
        // than being hidden behind an early Win32 sharing violation.
        var handle = CreateFileW(path, FileReadAttributes, ShareRead | ShareWrite | ShareDelete,
            IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error, $"Activation kernel probe could not open '{path}'.");
        }
        return handle;
    }

    public static SafeFileHandle OpenPreflightHold(string path)
    {
        const uint FileReadData = 0x00000001;
        const uint FileReadAttributes = 0x00000080;
        const uint ShareRead = 0x00000001;
        const uint OpenExisting = 3;
        const uint FileAttributeNormal = 0x00000080;

        // After kernel attestation reports no writable mapping, acquire the actual topology hold.
        // FILE_READ_DATA makes this handle share-sensitive; ShareRead alone rejects pre-existing
        // or racing WRITE/DELETE handles and keeps them out until kernel activation completes.
        var handle = CreateFileW(path, FileReadData | FileReadAttributes, ShareRead,
            IntPtr.Zero, OpenExisting, FileAttributeNormal, IntPtr.Zero);
        if (handle.IsInvalid)
        {
            var error = Marshal.GetLastWin32Error();
            handle.Dispose();
            throw new Win32Exception(error,
                $"Activation topology preflight could not hold file '{path}' with read-only sharing.");
        }
        return handle;
    }

    public static SafeFileHandle OpenPreflightDirectory(string path)
    {
        const uint FileListDirectory = 0x00000001;
        const uint FileReadAttributes = 0x00000080;
        const uint ShareRead = 0x00000001;
        const uint OpenExisting = 3;
        const uint FileFlagBackupSemantics = 0x02000000;

        // FILE_READ_ATTRIBUTES alone does not participate in normal CreateFile share checks.
        // Request FILE_LIST_DIRECTORY as well so this read-shared handle conflicts with any
        // pre-existing or racing WRITE/DELETE directory handle and freezes directory topology
        // until kernel activation completes.
        var handle = CreateFileW(path, FileListDirectory | FileReadAttributes, ShareRead,
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
