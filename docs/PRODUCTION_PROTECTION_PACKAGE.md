# Production protection package admission and lifecycle

Version 0.8.6 retains the cryptographically bound ProductionProtection package and adds the first normal-service Production Enforce driver/GateClient lifecycle above protocol v18. The default normal package remains Audit and still excludes the protection package. Kernel activation occurs only when an operator explicitly requests `Mode=Enforce`, configures exactly one explicit local protected root, and provisions this fixed package beside the running service:

```text
Protection/
  protection-package.json
  GateClient/
    RansomGuard.GateClient.exe
  Driver/
    RansomGuardMinifilter.sys
    RansomGuardMinifilter.inf
    RansomGuardMinifilter.cat
```

The descriptor schema is:

```json
{
  "Schema": 1,
  "Profile": "ProductionProtection",
  "Version": "0.8.6.0",
  "Protocol": 18,
  "Provider": "RansomGuard",
  "Altitude": "<Microsoft-assigned-production-altitude>",
  "GateClientSha256": "<64 hex>",
  "DriverSysSha256": "<64 hex>",
  "DriverInfSha256": "<64 hex>",
  "DriverCatSha256": "<64 hex>"
}
```

Admission is fail-closed. The service verifies the fixed non-reparse paths and final file identities; bounded file sizes; exact product version and protocol; descriptor SHA-256 values against the actual files; INF provider, DriverVer and altitude; and rejects the Engineering LAB provider/placeholder altitude `370099.4242`.

The running `RansomGuard.Service.exe`, GateClient and driver catalog must all have a cache-verifiable Authenticode signature. GateClient and CAT must be signed by the same signing certificate as the running service. The driver SYS and INF must each verify as members of the supplied signed CAT through the Windows catalog APIs (`CryptCATAdminAcquireContext2`, `CryptCATAdminCalcHashFromFileHandle2` and catalog-mode `WinVerifyTrust`).

A successful admission produces **ReadyForLifecycle**. That result is still not a `Protected` claim.

When launched by Windows SCM, the executable first establishes a minimal outer `WindowsServiceLifetime` host and reports service startup before performing SecureStore access, rollback verification, package admission or driver/GateClient lifecycle work. Those operations run inside a hosted bootstrap after the SCM handshake; the normal runtime itself is an inner Generic Host. This keeps startup fail-closed without making SCM startup depend on potentially expensive security/package validation.

The 0.8.6 lifecycle then performs the following ordered transition:

1. The service verifies the private rollback repository before any kernel-start transition.
2. The admitted driver package is staged/registered only when the `RansomGuardMinifilter` service is absent. Existing registration is never silently replaced.
3. The registered service must remain filesystem-driver type / demand-start, its default instance altitude must equal the admitted descriptor, automatic attachment must remain suppressed, and the installed SYS bytes must hash-match the admitted SYS.
4. Filter Manager loads the minifilter and requires exactly one active instance, on the local volume containing the configured protected root. A pre-existing attachment on another volume, or multiple instances, is rejected rather than accepted as partially correct.
5. The exact admitted `RansomGuard.GateClient.exe` is spawned with the ProductionGate profile and the fixed ProgramData rollback store.
6. The service waits for a bounded lifecycle readiness signal emitted only after ProductionGate activation preflight and kernel `ActivateGate` succeed.
7. Only then does the service publish `Protected` / `KernelEnforcementActive=true`.

A loaded driver, SCM Running service, spawned GateClient or connected filter port is not sufficient to publish protection.

## GateClient loss and reconnect

Unexpected ProductionGate termination after activation does not authorize driver unload or fail open. The kernel retains the exact protected root, volume and ProductionGate profile in `DegradedProtected` and denies covered destructive ordinary user-mode mutations according to the existing fail-safe policy. The service publishes the same degraded state and retries the admitted ProductionGate after a bounded delay. One root-bound rollback session is selected before the supervisor loop and remains the evidence namespace for that retained protection epoch; replacement ProductionGate processes explicitly reopen only that Active session. A reconnect returns to `Protected` only after repository/restart reconciliation and a fresh activation preflight complete for the retained root/profile. If a reconnect child never emits the post-preflight `READY` signal before timeout, the service kills that child without sending the maintenance-authorizing `shutdown` command; uncertain or late activation therefore remains fail-safe instead of racing into `DeactivateGate`.

Loss/EOF of the private service-control stdin is also **not** maintenance authorization. ProductionGate cancels its work and exits without `DeactivateGate`; when no worker fault occurred it deliberately leaves the rollback lifecycle `Active` rather than writing a terminal `Faulted` record, because the kernel still retains the same protection epoch. After a Service process crash, a later Service start must pass package/rollback validation again, discover exactly one Active production session bound to the configured root, reopen that same session, reconcile pending evidence and reconnect ProductionGate through a fresh activation preflight before normal protected mutations resume. Multiple Active sessions or an Active session bound to another root fail closed. A service-owned `production-*` session that is `Faulted` or lacks managed lifecycle metadata also blocks automatic Enforce startup; the service never creates a fresh evidence namespace on top of unresolved production evidence.

Initial activation failure is different: if ProductionGate never reaches readiness, the child is terminated without maintenance authorization, the service publishes `Failed`, sets a non-zero process exit status and stops the Enforce host rather than continuing without a supervisor. This intentionally permits an uncertain late kernel activation to remain fail-safe for a later service restart instead of guessing that no gate was armed.

## Authorized maintenance shutdown

The service uses a private redirected-stdin control channel to request ProductionGate shutdown; ProductionGate does not expose a public mutation API for this transition. It first drains workers and verifies that durable mutation/containment evidence has no unresolved transactions, then requests whole-gate `DeactivateGate`. Only after the kernel confirms `Maintenance` does GateClient durably mark the rollback session `Completed` and emit the matching clean lifecycle stop signal; only then may the service publish `Maintenance` and attempt Filter Manager detach/unload. If deactivation or the post-Maintenance completion commit fails, no clean STOPPED signal is emitted and the session remains non-Completed.

Clean maintenance is bounded to a 10-second GateClient confirmation window, a 3-second child-exit window and a shared 10-second driver detach/unload cleanup budget so one hung lifecycle utility cannot multiply the Service stop time. If the service has already authorized shutdown but clean deactivation cannot be proved, it does not unload the driver and it does not claim that kernel enforcement is still active: the maintenance outcome is explicitly `Failed`/unconfirmed. If the kernel has already confirmed `Maintenance` but subsequent Filter Manager detach/unload fails, the state remains truthfully `Maintenance`; this is recorded separately as driver cleanup failure rather than being misreported as unknown enforcement. If shutdown occurs before any ProductionGate has proved `READY`, no maintenance authorization is sent at all; the uncertain child is terminated and any retained kernel gate remains fail-safe for restart. Windows lifecycle helper processes are also terminated on service cancellation so package/load/attach commands cannot continue orphaned after the Enforce host stops.

## Version-bound service update transition

The 0.9 RC hardening path treats `Protection/` as part of the immutable service-version identity whenever production protection has been provisioned. A service update is therefore not allowed to copy only a new `RansomGuard.Service.exe` while silently retaining or dropping an older version-bound GateClient/driver package.

Before the SCM image-path commit, the updater now revalidates the current configuration, the previous immutable `Protection/` package when present, the target descriptor, exact package layout, SHA-256 inventory, GateClient FileVersion, INF provider/altitude/DriverVer, and any existing `RansomGuardMinifilter` registration. If the installed version has a protection package, the target must carry its own package. The staged package is copied into the new immutable version directory and revalidated after copying.

An in-place service update may reuse an already registered production minifilter only when the filter identity is unchanged: protocol/provider remain compatible, the admitted altitude is identical, and the target SYS SHA-256 is identical. A changed SYS or altitude is deliberately refused before SCM commit. Such a change requires a separate explicit driver-maintenance transaction; the service updater never replaces a registered kernel component implicitly.

This preserves rollback safety. The previous service directory and its version-bound `Protection/` package remain untouched. The updated service still performs the full Authenticode/catalog admission on startup; if that post-commit verification fails, the updater returns the SCM registration to the previous immutable service image. Because the allowed in-place path does not change the registered SYS/altitude, the previous version remains compatible with the retained registration.

## Deliberate remaining boundaries

The protection-package admission and updater compatibility checks do not prove that a numeric altitude was assigned by Microsoft, and they do not replace controlled production signing. Release governance must bind the shipped INF/descriptor to the external Microsoft assignment and approved signing identity.

Any transition that changes the registered production minifilter binary or altitude remains a separate release task and must have its own Maintenance transaction, rollback contract and disposable-VM qualification. Source/hosted CI alone is not proof of Filter Manager lifecycle behavior; release acceptance remains exact-SHA VM evidence.
