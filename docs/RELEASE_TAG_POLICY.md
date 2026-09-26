# Release tag and identity policy

RansomGuard release identity is intentionally separate from build success and from LAB qualification.

A release tag is valid only when all of the following are true:

1. the proposed source commit is already reachable from protected `main`;
2. the tag name matches the product version declared by `Directory.Build.props`;
3. release-candidate security qualification for the relevant product bytes is complete;
4. release artifact governance evidence exists for the exact source/artifact set;
5. production signing is performed in the separate controlled signing boundary;
6. the final release tag is an immutable, cryptographically signed annotated tag;
7. the GitHub Release, if one is published, points to that exact protected tag.

## Tag names

Production releases:

```text
vMAJOR.MINOR.PATCH
```

Release candidates:

```text
vMAJOR.MINOR.PATCH-rc.N
```

Examples:

```text
v0.9.0
v0.9.0-rc.1
v1.0.0
```

Mutable channel names such as `latest`, `stable`, `prod` or `release` are not release identities.

The numeric `MAJOR.MINOR.PATCH` part must equal the first three numeric components of the repository product `Version`. RansomGuard currently keeps a fourth .NET revision component of zero, for example `0.8.7.0` maps to release identity `v0.8.7`.

## Preflight

Before creating a tag, run:

```text
.github/workflows/release-identity-preflight.yml
```

Inputs:

- proposed tag name;
- exact 40-character source SHA.

The workflow:

- runs the repository automation, supply-chain and threat-model gates;
- checks out the exact proposed source;
- proves the source is reachable from protected `main`;
- validates tag syntax;
- validates tag version against `Directory.Build.props`;
- proves the checked-out source is exactly the requested SHA;
- emits a retained JSON preflight evidence artifact.

A successful preflight does **not** create a tag and does **not** claim production signing.

## Production tag creation

Production/RC tags must be created only after the external production-signing/release process has bound the signed artifacts back to the qualified source and release inventory.

The tag must be:

- annotated;
- cryptographically signed by an approved release identity;
- created at the exact preflight-approved commit;
- pushed only after the repository release-tag ruleset is active.

A lightweight tag is not an acceptable production release identity.

## Repository rulesets

Release tags matching `v*` should be covered by two repository-owner rulesets:

1. **Protect immutable release tags**
   - restrict updates;
   - restrict deletions;
   - no bypass actors.

2. **Control release tag creation**
   - restrict creations;
   - only the repository owner or designated release actor may bypass the creation restriction.

The release actor must not receive bypass rights in the immutable-tag ruleset. This allows controlled creation while preventing an already published release identity from being moved or deleted.

## Publication

A GitHub Release must not be treated as authoritative merely because its binaries were uploaded successfully.

The release record must bind:

```text
qualified source SHA
  -> immutable qualification package/evidence
  -> release governance inventory/SBOM
  -> controlled production signing
  -> signed-artifact hashes
  -> signed immutable release tag
  -> GitHub Release
```

If any security-relevant product bytes change after qualification, the affected evidence is invalid and a new candidate must be qualified before a new release identity is created.
