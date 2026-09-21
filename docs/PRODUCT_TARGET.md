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

Version 0.7.1.0 adds an engineering-only single-root pre-write gate to prove the ordering:

`I/O arrives -> durable first pre-image commit -> allow mutation`.

It is intentionally not enabled in the normal bundle and is not production-safe yet. The next milestones
are production-grade range copy-on-write, exact create/rename/delete transaction modeling, containment,
process-state capture, adaptive crypto analysis, and verified recovery orchestration.
