# RansomGuard 0.6.3.0: live UI and independent dump recovery

## Scope and safety boundary

Ordinary applications remain AUDIT ONLY. No new process suspension, injection,
cryptographic API hook, driver load, or security-setting change is added here.
Only the existing explicitly launched/hash-enrolled synthetic lab child may be
frozen and dumped after LAB confirmation. It is resumed in the existing finally
path. Offline key discovery runs AFTER resume; it must not prolong the freeze.
The driver remains a separate observation-only prototype, not installed by this build.

The supported decryption adapter is RGTEST03: AES-256-GCM, 12-byte nonce,
16-byte tag, no AAD. This is our synthetic simulator format, not a universal
ransomware format. An arbitrary high-entropy file is NOT identified as AES.
A recognized header gives a hypothesis; a candidate becomes a recovered key only
when AesGcm.Decrypt authenticates an input's GCM tag. Unsupported formats return
UnsupportedFormat. Missing keys return KeyNotFound. Neither is called success.

## Build

Extract the entire source archive into a NEW directory (not an older release).
Use .NET 10 SDK on Windows. No WDK is needed for this user-mode change.

    .\build_windows.cmd

Normal bundle: Audit engine, UI and the separate offline Recovery executable.
To include our owned test simulator and lab launchers:

    .\build_lab.cmd

The scripts execute the existing policy tests and new offline recovery/framing
tests, restore with vulnerability auditing, publish self-contained win-x64
executables, and run the existing WPF rendering tests before writing BUILD_STATUS.
Failures do not become successful releases. No .sys is installed or loaded.

## Live UI test (no encryption)

Stop an earlier audit console with Ctrl+C. Do not force-kill by process name.
Use both executables from the SAME new release (normal or Lab):

1. Run run_audit.cmd and accept its existing UAC prompt.
2. In a normal, non-elevated console run launch_ui.cmd from that same release.
3. Inspect the live stream/message state in Settings. Counts refresh from push
   messages, not a five-second polling timer.
4. Close UI: audit engine must remain alive. Reopen UI: it obtains a full snapshot.
5. Stop audit gracefully: UI must mark disconnection, not retain a healthy badge.
6. Restart the same release: the UI reconnects and accepts a new service instance.

Protocol v2 pipe: RansomGuard.ReadOnly.v2. Commands are status, incidents,
diagnostics and subscribe; there is NO decrypt/kill/trust/set-config request.
The UI checks the server image path using QUERY_LIMITED_INFORMATION, against its
sibling release executable, with no process control. This is a development-layout
identity check, not signed-software attestation or protection against an admin
who can replace the release files. UI and service from different releases refuse
connection. Old protocol-v1 UI is not compatible with this stream.

Initial frame: complete status, diagnostics, latest 50 incident summaries and
recovery state. Subsequent frames: changed sections; a heartbeat at most about
2 seconds apart during idle periods. Every frame has a per-connection sequence
and a service boot ID. A gap/disconnect causes reconnection and a fresh snapshot.
Only the latest 100 incidents are retained in live memory and the latest 50 sent;
this is NOT an unlimited reliable replay log. The protected incident archive is
still the source for older cases. A coalesced update can skip intermediate metric
values without blocking detection. IncidentRevision exposes history changes.

Telemetry snapshots are produced every 500 ms. Monitor transitions and recorded
incidents signal immediately, without a polling interval. Disk heartbeat logging
remains every 30 seconds. Driver service-state checks remain infrequent. UI live
transport DOES NOT eliminate Kernel ETW buffering or unresolved filenames.

Transport bounds: four client workers, one queued wake-up each, 1 MiB maximum
frame, 4 KiB initial request, 2-second request deadline, 3-second write deadline,
7-second client read deadline, capped reconnection backoff. Slow UI is disconnected;
no detector waits for UI. NETWORK/ANONYMOUS denied. Users get individual data rights,
not GENERIC_WRITE/CreateNewInstance. Client uses SECURITY_IDENTIFICATION, not an
impersonation-capable connection. No recovered key bytes are sent over IPC.

## Full independent recovery test

Use the new Lab release. Stop run_audit.cmd first; the lab starts its own engine
and cannot share an active audit instance's global lock. UI may remain open from
this SAME Lab release and reconnect automatically. Do NOT start the simulator
manually for this test: that would be an ordinary AuditOnly process without a dump.

    .\test_lab_full_dump.cmd

Type LAB when asked. Prefer an isolated VM for the privileged dump experiment;
no kernel driver is required. The test creates exactly ten new synthetic files,
records their SHA-256 values BEFORE encryption, and starts its owned simulator.
After a detected lab event:

    enrolled child -> freeze -> full dump -> resume
    child finishes -> scan immutable dump -> authenticate candidates
    write NEW recovered copies -> verify all original SHA-256 values

The recovery module does NOT read recovery-key.bin. The simulator still uses its
existing test key file internally and its explicit --recover utility still works;
that path is separate from this independent dump recovery. The module never calls
--recover or imports that file. Existing known-key search was removed, not renamed.

Results in the protected incident directory:

    incident.json
    response.json
    process.dmp                  # confidential; keep local
    crypto-recovery.json         # no key bytes or offsets
    RecoveredFromDump/           # new plaintext copies, never overwritten

Successful independent proof requires:

    KeyRecovered: true
    Algorithm: AES-256-GCM
    ReferenceKeyFileUsed: false
    WrittenFiles: 10
    OriginalHashVerifiedFiles: 10

These are acceptance criteria, NOT a claim that every dump must contain a usable key.
A missing dump, capture refusal, no candidate, tag error, baseline mismatch, scan
limit or output write failure is a failed/partial test. GCM-valid plaintext with a
wrong baseline hash is not written. The full-memory test returns a nonzero exit if
all ten originals are not verified. UI shows non-sensitive recovery progress.

The simulator intentionally resumes; ten encrypted files at test completion does
not imply that freeze failed. Compare LockedFilesAtFreeze and LockedFilesBeforeResume
in response.json. Independent scanning is not performed while the child is frozen.

## Offline use on an existing supported case

No service or live process is needed. Give an authorized local dump, a directory
of RGTEST03 .rglocked files (top level only), and a NEW output directory:

    .\Recovery\RansomGuard.Recovery.exe --dump "C:\Cases\case1\process.dmp" --files "C:\Cases\case1\Encrypted" --output "C:\Cases\case1\Recovered-new"

The output parent must exist. Do not point output to the encrypted input directory.
Use an elevated console only when the protected case ACL requires it; do not weaken
ProgramData permissions for convenience. A sibling <output>.report.json records the
result. Without a separately recorded original hash, GCM authentication confirms the
key/tag pair but the report does not claim an original SHA-256 comparison.

Limits: local files only, no reparse/symlink paths, no ADS or UNC, single hard-link
inputs on Windows, immutable input handles, maximum 512 MiB offline input dump (the existing live lab capture still has its separate 128 MiB quota), 64 selected files,
1 MiB each, 8192 distinct candidate keys, 16384 validation attempts, 90 seconds for
scanning, cancellation supported. New output files use CreateNew; originals, the
dump and saved key are not modified. An interrupted write can leave partial NEW
output files; evidence remains untouched. Reports are not the key itself.

## Candidate discovery and its limitations

- Parse bounded MINIDUMP_MEMORY64_LIST / MINIDUMP_MEMORY_LIST captured regions;
  never load a DLL or execute code from the dump.
- Recognize complete forward AES-128/192/256 schedules (BE or byte-swapped uint32
  words) by the FIPS-197 recurrence, not by entropy alone. Decryption schedules,
  nonstandard representations and unaligned/split schedules are not all supported.
- Also examine CoreCLR AMD64 byte-array layout candidates with plausible captured
  method-table flags. This is a HEURISTIC, dependent on runtime layout, not proof
  that every candidate is a key. Windows CNG contexts are not fully parsed here.
- Validate candidates against supplied RGTEST03 AES-256-GCM envelopes; the current
  adapter uses only 32-byte keys. Failed authentication emits no plaintext.
- No general RSA private-key recovery, ChaCha context parser, CryptoAPI hooking,
  arbitrary algorithm inference, external cloud service or process injection.

Independent reference experiment performed during development: on a previously
provided simulator dump, ten candidate arrays were enumerated and a candidate
successfully authenticated four encrypted buffers also present in that dump.
All four recovered byte strings matched the entire reconstructed synthetic fixture,
not just a readable prefix. No saved key was read, and no key/offset/plaintext was
exported. This was a Python reference experiment, not execution of the new C# binary
and not restoration of four supplied disk files. See docs/INDEPENDENT_PROOF.json.

## Verification status

The environment that prepared this archive could not execute .NET, PowerShell,
WPF or Windows kernel code. New C# test sources are included but must pass locally.
Static checks, asset-hash preservation and the independent reference cryptographic
experiment are recorded separately in docs/VALIDATION.json. A build passing does
not establish production anti-ransomware effectiveness or kernel safety.
