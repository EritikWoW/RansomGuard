# Self-hosted runtime VM runner

The `Minifilter runtime VM lab` workflow is intentionally manual and must run only on a disposable Windows VM. It installs, loads and attaches kernel code and therefore must not target a workstation or production machine.

## Required runner shape

Use a disposable/snapshotted Windows x64 VM with:

- a local or domain account that is an Administrator;
- Git;
- Visual Studio / Build Tools with the x64 C++ toolchain;
- a complete Windows SDK + WDK containing `fltKernel.h`, `FltMgr.lib`, `signtool.exe`, `Inf2Cat.exe`, `infverif.exe`, `ApiValidator.exe` and `Aitstatic.exe`;
- Windows filter/driver tools available through `fltmc.exe`, `pnputil.exe` and `rundll32.exe`;
- a lab driver-signing certificate with an accessible private key in `CurrentUser\My` or `LocalMachine\My`;
- whatever trust/test-signing state the disposable image requires for that certificate.

RansomGuard does not enable TESTSIGNING, disable Secure Boot, install a trust root, or weaken Defender. Those VM-image prerequisites are deliberately outside repository automation.

## GitHub runner configuration

Register a repository self-hosted GitHub Actions runner on the VM and add the custom label:

`ransomguard-lab-vm`

The workflow also requires the standard labels `self-hosted`, `Windows` and `X64`.

Run the Actions runner under an account that is elevated for the workflow and can access the signing certificate private key. If the certificate is stored under `CurrentUser\My`, it must belong to that same runner identity. A machine-store certificate can be used instead when its private-key ACL permits the runner account.

Create or use the GitHub environment:

`ransomguard-lab-vm`

and define its secret:

`RANSOMGUARD_LAB_CERT_THUMBPRINT`

The value is the 40-hex SHA-1 certificate thumbprint, without relying on spaces.

## One-time VM readiness check

Inside the repository checkout on the VM, run an elevated PowerShell session:

```powershell
$env:RANSOMGUARD_LAB_VM='I_UNDERSTAND'
.\minifilter-tools\verify_runtime_runner_readiness.ps1 -CertificateThumbprint '<40-HEX-THUMBPRINT>'
```

The readiness check is read-only with respect to boot/security policy. It verifies the VM marker/model, elevation, certificate/private key, Visual Studio C++ toolchain, WDK files/tools and required Windows commands.

Do not dispatch the runtime workflow until this check passes.

## Running the lab

Dispatch `Minifilter runtime VM lab` manually. The job:

1. checks out the exact requested commit;
2. re-runs the VM readiness contract;
3. builds the Engineering LAB userspace bundle;
4. builds and signs an exact-commit driver package;
5. verifies package provenance against `github.sha`;
6. installs/loads/attaches the minifilter only inside the disposable VM;
7. executes activation, mapping, preservation, pre-armed containment and event-bound containment scenarios;
8. writes `runtime-result.json` and uploads runtime evidence;
9. unloads the filter and removes the temporary signed package.

A green compile workflow is not a substitute for this runtime workflow.

## Reset discipline

Treat each runtime campaign as destructive to the VM image even if cleanup succeeds. Prefer reverting to a known snapshot between campaigns, especially before Driver Verifier, power-loss, forced-crash or filesystem fault-injection work.

Do not reuse this runner for ordinary development, credentials, personal files or production workloads.
