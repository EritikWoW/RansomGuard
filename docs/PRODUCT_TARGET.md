# Product target

RansomGuard is not a general antivirus. It is a Windows anti-encryption and recovery layer.

The finished product must provide three independent safety paths:

1. **Preserve** original data before destructive mutation through a production minifilter and copy-on-write/pre-image protection.
2. **Contain** continued destructive writes once the system has enough evidence that a process is encrypting or otherwise corrupting protected data.
3. **Recover** affected data through verified rollback and, when runtime state is available, adaptive cryptographic analysis/key-state recovery.

The detector is a trigger, not the product. ETW can remain useful for telemetry and forensics, but a release
is not prevention-capable merely because ETW identifies a suspicious process. Prevention requires a proven
pre-mutation preservation path.

## Current milestone

Version 0.7.2.0 extends the engineering-only single-root pre-write gate with range-aware write copy-on-write:

`WRITE -> durable original-length baseline + first touched blocks -> allow mutation`.

Rename, delete and truncate-class operations remain on a conservative full-file pre-image path.
The gate is intentionally not enabled in the normal bundle and is not production-safe yet.

The next core milestones are exact create/rename transaction modeling, durable volume/file identity,
bounded concurrent and crash-reconciled gating, containment, process-state capture, adaptive crypto analysis,
and verified recovery orchestration.
