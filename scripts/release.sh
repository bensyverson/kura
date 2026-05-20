#!/usr/bin/env bash
#
# Cuts a Kura release: validates inputs, runs the full quality gate, builds
# the binary and verifies it reports the version, then creates an annotated
# (signed, if signing is configured) tag. Pushing the tag is left to you —
# pushing a v* tag is what triggers .github/workflows/release.yml to build
# the cross-platform binaries, attest their provenance, and publish the
# GitHub Release.
#
# Usage:
#   scripts/release.sh 0.1.0
#   scripts/release.sh v0.1.0      # a leading v is fine
#
# To publish after a successful run:
#   git push origin vX.Y.Z
#
# To undo before pushing:
#   git tag -d vX.Y.Z
#
# See docs for the full release process and how to verify published artifacts.

set -euo pipefail
cd "$(dirname "$0")/.."

# --- arguments ---------------------------------------------------------------
if [[ $# -ne 1 ]]; then
	echo "Usage: $0 <version>   # e.g. 0.1.0 or v0.1.0" >&2
	exit 2
fi
version="${1#v}"
if [[ ! "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$ ]]; then
	echo "Error: version must look like X.Y.Z or X.Y.Z-suffix (got: $1)" >&2
	exit 2
fi
tag="v$version"

# --- required tools ----------------------------------------------------------
for tool in git go; do
	if ! command -v "$tool" >/dev/null 2>&1; then
		echo "Error: required tool '$tool' is not installed." >&2
		exit 2
	fi
done

# --- preconditions -----------------------------------------------------------
branch=$(git symbolic-ref --short HEAD 2>/dev/null || echo "<detached>")
if [[ "$branch" != "main" ]]; then
	echo "Error: cut releases from 'main', not '$branch'. Switch to main first." >&2
	exit 2
fi

if ! git diff-index --quiet HEAD --; then
	echo "Error: working tree has uncommitted changes. Commit or stash first." >&2
	exit 2
fi

if git rev-parse "refs/tags/$tag" >/dev/null 2>&1; then
	echo "Error: tag $tag already exists." >&2
	exit 2
fi

# The tag must point at a commit that is already on origin/main, so the
# published release matches what reviewers merged.
git fetch --quiet origin main 2>/dev/null || true
if git rev-parse --verify --quiet origin/main >/dev/null; then
	if [[ "$(git rev-parse HEAD)" != "$(git rev-parse origin/main)" ]]; then
		echo "Error: local main is not in sync with origin/main." >&2
		echo "       Push or pull so the tag lands on a published commit." >&2
		exit 2
	fi
fi

# --- quality gate ------------------------------------------------------------
echo "==> gofmt check..."
unformatted=$(gofmt -l .)
if [[ -n "$unformatted" ]]; then
	echo "Error: these files are not gofmt-clean:" >&2
	echo "$unformatted" >&2
	exit 1
fi

echo "==> go vet..."
go vet ./...

echo "==> go test..."
go test ./...

echo "==> govulncheck..."
if command -v govulncheck >/dev/null 2>&1; then
	govulncheck ./...
else
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...
fi

# --- build & verify the reported version -------------------------------------
echo "==> building $tag and verifying the binary reports it..."
tmpdir=$(mktemp -d)
trap 'rm -rf "$tmpdir"' EXIT
go build -ldflags "-X main.version=$tag" -o "$tmpdir/kura" ./cmd/kura
reported=$("$tmpdir/kura" version)
if [[ "$reported" != "$tag" ]]; then
	echo "Error: built binary reports '$reported' (expected '$tag')." >&2
	exit 1
fi

# --- tag ---------------------------------------------------------------------
echo "==> tagging $tag..."
if git config --get user.signingkey >/dev/null 2>&1; then
	git tag -s "$tag" -m "Release $tag"
	echo "    (signed tag)"
else
	git tag -a "$tag" -m "Release $tag"
	echo "    (annotated tag; configure user.signingkey to sign)"
fi

cat <<EOF

$tag is tagged locally. To publish (this triggers the release workflow):

  git push origin $tag

To undo before pushing:

  git tag -d $tag

EOF
