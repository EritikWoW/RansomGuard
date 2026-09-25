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

A successful admission produces **ReadyForLifecycle**. That result is still not a `Protected` claim. The 0.8.6 lifecycle then performs the following ordered transition:

1. The service verifies the private rollback repository before any kernel-start transition.
2. The admitted driver package is staged/registered only when the `RansomGuardMinifilter` service is absent. Existing registration is never silently replaced.
3. The registered service must remain filesystem-driver type / demand-start, its default instance altitude must equal the admitted descriptor, automatic attachment must remain suppressed, and the installed SYS bytes must hash-match the admitted SYS.
4. Filter Manager loads the minifilter and requires exactly one active instance, on the local volume containing the configured protected root. A pre-existing attachment on another volume, or multiple instances, is rejected rather than accepted as partially correct.
5. The exact admitted `RansomGuard.GateClient.exe` is spawned with the ProductionGate profile and the fixed ProgramData rollback store.
6. The service waits for a bounded lifecycle readiness signal emitted only after ProductionGate activation preflight and kernel `ActivateGate` succeed.
7. Only then does the service publish `Protected` / `KernelEnforcementActive=true`.

A loaded driver, SCM Running service, spawned GateClient or connected filter port is not sufficient to publish protection.

## GateClient loss and reconnect

Unexpected ProductionGate termination after activation does not authorize driver unload or fail open. The kernel retains the exact protected root, volume and ProductionGate profile in `DegradedProtected` and denies covered destructive ordinary user-mode mutations according to the existing fail-safe policy. The service publishes the same degraded state and retries the admitted ProductionGate after a bounded delay. A reconnect returns to `Protected` only after a fresh activation preflight completes for the retained root/profile. If a reconnect child never emits the post-preflight `READY` signal before timeout, the service kills that child without sending the maintenance-authorizing `shutdown` command; uncertain or late activation therefore remains fail-safe instead of racing into `DeactivateGate`.

Loss/EOF of the private service-control stdin is also **not** maintenance authorization. ProductionGate cancels its work and exits without `DeactivateGate`; closing the filter port therefore leaves the kernel in the retained fail-safe state. After a Service process crash, a later Service start must pass package/rollback validation again and reconnect ProductionGate through a fresh activation preflight before normal protected mutations resume.

Initial activation failure is different: if ProductionGate never reaches readiness, the service publishes `Failed` and never claims that kernel enforcement became active.

## Authorized maintenance shutdown

The service uses a private redirected-stdin control channel to request ProductionGate shutdown; ProductionGate does not expose a public mutation API for this transition. It first drains its work, commits terminal rollback-session evidence, requests whole-gate `DeactivateGate`, and requires the kernel to confirm `Maintenance`. Only after the service receives the matching clean lifecycle stop signal may it publish `Maintenance` and attempt Filter Manager detach/unload.

If clean deactivation cannot be proved, the service does not unload the driver. An active session stays fail-safe rather than trading recoverability for a convenient shutdown.

## Deliberate remaining boundaries

Automatic detector-to-containment authorization remains disabled in 0.8.6; `AutomaticContainment=true` is rejected. Production recovery orchestration, local Administrator/SYSTEM self-protection, controlled release signing, installer/update/uninstall orchestration and a Microsoft-assigned production altitude remain separate release work.

The admission check can validate syntax and cryptographic package binding, but a numeric altitude in a local descriptor is not proof that Microsoft assigned it. Release governance must bind the shipped INF/descriptor to the external Microsoft assignment and controlled production signing identity.

The 0.8.6 lifecycle implementation must be exact-head qualified on the disposable Windows VM before it is treated as a release gate. Source/hosted CI alone is not proof of Filter Manager lifecycle behavior.
