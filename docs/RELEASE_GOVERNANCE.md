# Release artifact governance

RansomGuard release builds must be traceable from one exact source commit to the bytes distributed to users.

Windows CI generates a release-governance evidence bundle after the validated release ZIPs are produced. The bundle contains:

- `release-artifact-inventory.json` — exact source SHA, release-file paths, sizes, SHA-256 values and observed Authenticode status/signer metadata.
- `SHA256SUMS.txt` — portable SHA-256 manifest for every file under `release/`.
- `ransomguard.spdx.json` — SPDX 2.3 SBOM containing shipped-file hashes and NuGet dependencies resolved from committed `packages.lock.json` files.
- `release-governance-attestation.json` — hashes of the governance evidence itself plus the declared signing boundary.

## Signing boundary

CI deliberately does **not** perform production/EV signing and does not require a production private key in ordinary GitHub repository secrets.

Production signing must occur in a separately controlled trust boundary (for example, an approved hardware-backed or managed code-signing service). A release is not production-signing-qualified merely because CI produced a valid SBOM or SHA-256 inventory.

The final production release process must bind:

```text
qualified source SHA
  -> qualified immutable candidate package/evidence
  -> unsigned release artifact inventory
  -> controlled production signing event
  -> signed artifact SHA-256 inventory
  -> published release/tag identity
```

The signed artifact inventory must therefore be generated or re-verified again after the external signing step; signing changes executable bytes.

## Candidate invalidation

Security qualification evidence remains bound to the exact candidate and package described by the candidate issue. Adding or changing release-governance automation must not rewrite or silently re-label an already-qualified frozen candidate.

Any change to driver, GateClient protocol, ProductionGate semantics, production lifecycle, preservation/rollback behavior, package admission or package bytes invalidates the affected candidate evidence and requires a new qualification record.

## Cryptographic release identity

Frozen release governance uses GitHub Actions OIDC with Sigstore-backed artifact attestations. No long-lived attestation private key is stored in repository secrets.

For each exact-source frozen release, the workflow:

- requires the normal release ZIP name to contain the canonical four-part product version from `Directory.Build.props`;
- records the release ZIP SHA-256 together with the exact frozen candidate source SHA in `release-governance-attestation.json`;
- creates a custom signed release-governance attestation for the release ZIP;
- creates a signed SPDX 2.3 SBOM attestation for the same release ZIP;
- verifies both signatures with `gh attestation verify`, constraining repository, signer workflow and orchestration source digest;
- re-checks the signed custom predicate's `sourceSha` against the requested frozen candidate;
- stores the Sigstore bundles and a machine-readable `artifact-attestation-record.json` in the governance evidence artifact.

This provides a cryptographically attributable repository release identity before a public GitHub Release/tag exists. A later public release must use the same canonical product version and must publish bytes whose SHA-256 values match the attested subjects. Production EV/Authenticode signing remains a separate controlled trust boundary and requires post-signing re-hashing because signing changes executable bytes.

