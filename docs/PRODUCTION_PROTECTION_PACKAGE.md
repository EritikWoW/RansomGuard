# Production protection package admission

Version 0.8.2 retains the trust/admission boundary for the future Production Enforce driver lifecycle. It does **not** install, start, load, attach or unload the minifilter.

The normal package remains Audit by default and still excludes the protection package. When `Mode=Enforce` is requested, the service inspects only this fixed layout beside its own executable:

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
  "Version": "0.8.2.0",
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

A successful result is only **ReadyForLifecycle**. It is not a Protected claim and does not perform any SCM, Filter Manager or process lifecycle action. Version 0.8.2 still reports `EnforceUnavailable` after package admission. Protocol v18 now defines a distinct ProductionGate client contract, but the normal service still does not install/load/attach or supervise it; that lifecycle remains the next separately qualified milestone.

This source-level admission boundary does not prove that an altitude was actually assigned by Microsoft merely because a numeric value is present in the package. Release governance must bind the shipped altitude to the external Microsoft assignment before distribution. Likewise, local Administrator/SYSTEM tamper resistance remains a later self-protection milestone.
