---
title: Releasing
weight: 6
---

How Kura is versioned, released, and verified. If you're **installing** Kura,
the [Verifying a release](#verifying-a-release) section is what you want. If
you're a **maintainer** cutting a release, start at [Cutting a
release](#cutting-a-release).

## Version scheme

Kura uses [semantic versioning](https://semver.org): `vMAJOR.MINOR.PATCH`.
While Kura is pre-1.0 (the `v0.x` line), minor releases may include breaking
changes; pin an exact version in deployment repos. Pre-releases use a suffix,
e.g. `v1.0.0-rc.1`, and are published as GitHub pre-releases (as is every
`v0.x` release).

The running binary reports its version:

```sh
kura version
```

The version is injected at build time. A release binary reports its tag (e.g.
`v0.1.0`); a binary from `go install …@vX` resolves the version from the module
build info; a plain local `go build` reports `dev` (or the `git describe`
output when built via `make build`).

## Installing

Install the latest tagged CLI with Go:

```sh
go install github.com/bensyverson/kura/cmd/kura@latest   # or @v0.1.0
```

Or download a prebuilt archive for your platform from the
[Releases page](https://github.com/bensyverson/kura/releases) and verify it
(below) before use.

## Verifying a release

Every release publishes per-platform archives, a `SHA256SUMS` file, and a
**build-provenance attestation** for each archive.

Check the checksum:

```sh
sha256sum -c SHA256SUMS --ignore-missing
```

Verify the provenance attestation with the GitHub CLI — this proves the archive
was built by Kura's release workflow from this repository, not tampered with
after the fact:

```sh
gh attestation verify kura_v0.1.0_linux_amd64.tar.gz --repo bensyverson/kura
```

## Immutability

Release tags are immutable: a `v*` tag ruleset blocks tag deletion and
tag-moving, so a published release's tag can never be repointed. Maintainers
additionally enable GitHub's "Immutable releases" setting so the published
assets cannot be altered. (Both are applied by
[`scripts/github-posture.sh`](https://github.com/bensyverson/kura/blob/main/scripts/github-posture.sh)
and its documented manual step.)

## Cutting a release

Maintainers only. Releases are cut from a clean `main` that is in sync with
`origin/main`.

1. Run the release script with the target version:

   ```sh
   scripts/release.sh 0.1.0
   ```

   It validates the version, runs the full gate (`gofmt`, `go vet`, `go test`,
   `govulncheck`), builds the binary and verifies it reports the version, then
   creates an annotated (signed, if signing is configured) tag. It does **not**
   push.

2. Push the tag to publish:

   ```sh
   git push origin v0.1.0
   ```

   To undo before pushing: `git tag -d v0.1.0`.

Pushing the `v*` tag triggers
[`.github/workflows/release.yml`](https://github.com/bensyverson/kura/blob/main/.github/workflows/release.yml),
which re-runs the gate, cross-compiles `kura` for linux/darwin/windows on
amd64/arm64, generates `SHA256SUMS`, attests build provenance, and publishes the
GitHub Release with auto-generated notes (from squash-merged PR titles — keep
PR titles descriptive).
