# RansomGuard disposable runtime VM validation — v0.7.14.0

This workflow is intentionally separate from normal GitHub-hosted CI. It loads the engineering minifilter and therefore may run only inside a disposable, snapshotted Windows VM.

## What it validates

The runtime harness exercises two protocol-v11 scenarios against the exact checked-out commit:

1. **Pre-existing writable mapping before GateClient**
   - create a writable mapped view;
   - close the original file handle while keeping the mapped section/view alive;
   - start GateClient;
   - activation preflight must detect the writable view through `MmDoesFileHaveUserWritableReferences`;
   - the kernel gate must not become active;
   - `activation-preflight-journal.jsonl` must persist `writableViewPresent=true`.

2. **Clean activation followed by a writable mapping**
   - start with an unmapped existing file;
   - GateClient must complete activation preflight and report `kernel gate ACTIVE`;
   - opening the file content-write-capable must commit its eager full pre-image;
   - creating PAGE_READWRITE mapping must produce `WritableSection = BaselineVerified`;
   - modifying and `FlushViewOfFile`-ing the mapping must produce paging-write evidence;
   - the committed pre-image SHA-256 must equal the original file SHA-256;
   - the live file must actually change.

## Runner requirements

The workflow `.github/workflows/minifilter-runtime-vm.yml` is **workflow_dispatch only** and requires a self-hosted runner with all labels:

- `self-hosted`
- `Windows`
- `X64`
- `ransomguard-lab-vm`

The runner must be an administrator inside a disposable VM snapshot and must already have:

- Visual Studio C++ build tools;
- Windows SDK/WDK;
- .NET 10 SDK capability;
- driver test-signing configuration prepared manually for that VM;
- a test-signing certificate with a private key installed in CurrentUser/My or LocalMachine/My.

The repository/environment secret `RANSOMGUARD_TEST_CERT_THUMBPRINT` must point to that installed test certificate.

RansomGuard tooling deliberately does **not**:

- enable TESTSIGNING;
- disable Secure Boot;
- install trust roots;
- disable Defender;
- weaken Windows security settings.

If those lab prerequisites are not already valid, the runtime workflow fails.

## Exact-commit guarantee

The runtime workflow builds both components from the checked-out GitHub SHA:

- `RansomGuardMinifilter.sys`;
- `RansomGuard.GateClient.exe`.

The freshly built SYS is test-signed inside the VM, a fresh catalog is generated and signed, then that exact package is installed/loaded/attached. The workflow does not download or reuse an older driver artifact.

## Safety boundary

The runtime scripts require the environment marker:

`RANSOMGUARD_RUNTIME_VM=YES-I-AM-DISPOSABLE`

They also verify that Windows reports an obvious VM model. Normal CI validates that the runtime workflow cannot gain push/pull_request/schedule triggers or GitHub-hosted runner labels.

Driver unload/detach runs under `if: always()`. The VM itself should still be reverted to its known-good snapshot after each runtime run.

## What passing does not prove

A passing v0.7.14 runtime test validates these two mapped-I/O ordering scenarios on the tested Windows/NTFS/driver build only. It does not prove:

- production driver compatibility;
- ReFS coverage;
- universal cache-manager ordering;
- crash recovery across reboot;
- production signing/altitude readiness;
- containment efficacy;
- large-file performance.
