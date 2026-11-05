# Releasing

Releases are built by `.github/workflows/release.yml` when a tag `vX.Y.Z` is pushed. The workflow
creates a **draft** GitHub release; nothing is public until a person publishes it. `.goreleaser.yaml`
holds the build configuration, and CI runs the same pipeline as a snapshot (no signing, no
publishing) on every change.

## What a release contains

- `kennel_<version>_<os>_<arch>.tar.gz` (`.zip` on Windows) for linux, darwin and windows on amd64
  and arm64. Static binaries (`CGO_ENABLED=0`), `-trimpath`, version stamped from the tag.
- macOS and Windows binaries carry the Linux gateway (build tag `embedgw`), because the gateway runs
  in a Linux container; Linux binaries build the gateway image from themselves.
- `checksums.txt` (SHA-256), one SPDX SBOM per archive (`*.sbom.json`), a Sigstore signature bundle
  for the checksum file (`checksums.txt.sigstore.json`), and a SLSA build-provenance attestation.

## Verify a download

```sh
# 1. The checksum file was signed by this repository's release workflow (needs cosign):
cosign verify-blob \
  --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/middle-systems/kennel/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  checksums.txt

# 2. The archive matches the signed checksum file:
sha256sum --ignore-missing -c checksums.txt        # macOS: shasum -a 256 -c

# 3. Optionally, the build provenance (needs the GitHub CLI):
gh attestation verify kennel_<version>_<os>_<arch>.tar.gz --repo middle-systems/kennel
```

`scripts/install.sh` performs steps 1 and 2 and refuses to install if either fails.

## Cutting a release (maintainers)

1. Update `CHANGELOG.md`; make sure CI is green on `master`.
2. `git tag -s vX.Y.Z && git push origin vX.Y.Z`.
3. Check the draft release (artifact list, `kennel version` of one binary, signature), then publish.

Package-manager manifests (Homebrew cask, Scoop) are generated with `skip_upload` and are not pushed
anywhere until the tap and bucket repositories exist.

## Not yet decided

The name (Kennel) and licence (MIT) are settled in ADR 0010, which also lists the checks left before
a first public release. `SECURITY.md` relies on GitHub private vulnerability reporting, which must be
enabled in the repository settings (Security → Private vulnerability reporting) before release.
