# Release tag and identity policy

RansomGuard release identity is intentionally separate from build success and from LAB qualification.

A release tag is valid only when all of the following are true:

1. the proposed source commit is already reachable from protected `main`;
2. the tag name matches the product version declared by `Directory.Build.props`;
3. release-candidate security qualification for the relevant product bytes is complete;
4. release artifact governance evidence exists for the exact source/artifact set;
5. production artifact signing is performed in the separate controlled signing boundary;
6. the final release tag is an immutable annotated tag protected by the repository release-tag rulesets;
7. release identity is cryptographically attributable by either an approved signed annotated tag or a GitHub/Sigstore release-identity attestation that binds the immutable tag object, exact protected-main source SHA and governed release artifact hashes;
8. the GitHub Release, if one is published, points to that exact protected tag.

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
- created at the exact preflight-approved commit;
- pushed only after both repository release-tag rulesets are active;
- immutable after creation.

A lightweight tag is not an acceptable production release identity.

Cryptographic attribution must then use one of two reviewed routes:

- a cryptographically signed annotated tag from the approved external release identity; or
- the repository `release-identity-attestation.yml` workflow, which uses GitHub/Sigstore provenance to bind the existing annotated tag object, exact protected-main source SHA, successful main Windows-build run and governed artifact hashes.

The Sigstore route does not weaken production artifact-signing requirements and does not create or move Git tags.

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

### Repository-owner import path

Two ready-to-import repository ruleset files are committed with this policy:

- `docs/github-rulesets/protect-immutable-release-tags.json`
- `docs/github-rulesets/control-release-tag-creation.json`

Repository owner procedure:

1. Open **Settings → Rules → Rulesets**.
2. Choose **New ruleset → Import a ruleset**.
3. Import `protect-immutable-release-tags.json`; review that it targets tags matching `refs/tags/v*`, is **Active**, has **Restrict updates** + **Restrict deletions**, and has **no bypass actors**.
4. Import `control-release-tag-creation.json`; review that it targets the same `v*` tag namespace, is **Active**, has **Restrict creations**, and the only bypass actor is user `EritikWoW`.
5. After both rulesets are active, run the release identity workflow. It reads the live repository rulesets and fails closed if the imported protection differs from this contract.

The creation template binds the bypass actor to GitHub user id `116751610` (EritikWoW). If GitHub's import UI asks to remap that actor, select only the repository owner and do not add an immutable-ruleset bypass.

## GitHub/Sigstore release identity attestation

The alternative cryptographic identity route is:

```text
.github/workflows/release-identity-attestation.yml
```

Inputs:

- existing protected annotated release tag;
- exact 40-character source SHA;
- successful `Windows build` run id.

The workflow fails closed unless:

- it is dispatched from protected `main` and `github.sha` equals the requested source SHA;
- the release tag rulesets are active for `v*`;
- one no-bypass ruleset prevents release-tag update/deletion;
- a separate creation-control ruleset restricts tag creation to an explicit release actor;
- the existing tag is annotated and resolves to the exact source SHA;
- the supplied Windows-build run is a successful `push` run on `main` for the same source SHA;
- downloaded release ZIP bytes match the exact release-governance SHA-256 inventory.

It then creates GitHub/Sigstore provenance for the governed release artifact checksums and for a release-identity manifest containing the tag object SHA, source SHA, Windows-build run id and artifact inventory. The generated Sigstore bundles and identity evidence are retained as a workflow artifact and the published attestations are verified before the job succeeds.

## Publication

A GitHub Release must not be treated as authoritative merely because its binaries were uploaded successfully.

The release record must bind:

```text
qualified source SHA
  -> immutable qualification package/evidence
  -> successful exact-SHA main Windows build
  -> release governance inventory/SBOM
  -> controlled production artifact signing
  -> governed artifact hashes
  -> immutable annotated release tag object
  -> signed tag OR GitHub/Sigstore release-identity attestation
  -> GitHub Release
```

If any security-relevant product bytes change after qualification, the affected evidence is invalid and a new candidate must be qualified before a new release identity is created.
