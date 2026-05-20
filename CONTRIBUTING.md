# Contributing to Kura

Thanks for your interest in Kura — an open-source, auditable secure-data-store
template. This guide covers how to build, test, and propose changes.

## Reporting security issues

**Do not open a public issue for a vulnerability.** Follow [SECURITY.md](SECURITY.md)
and use GitHub's private vulnerability reporting instead.

## Getting started

Kura is a Go project. You need the Go toolchain pinned in [`go.mod`](go.mod)
(the build will fetch the right version automatically).

```sh
make build      # build ./kura
make test       # run all unit tests (integration tests skip without a DB)
make vet        # go vet ./...
make fmt        # go fmt ./...
./kura version  # the build version
```

Integration tests need a Postgres instance; bring up the containerized one and
run the full suite with:

```sh
make test-integration
```

(See [`scripts/test-db.sh`](scripts/test-db.sh); we use a lightweight container
runtime such as Colima rather than Docker Desktop.)

## Architecture: where code belongs

Kura is **adapter-over-core**. The core enforcement library lives in
[`internal/`](internal/) — Cedar authorization, audit logging, PII
detection/masking, field-level encryption, and data access. The CLI, the HTTP
API (`kura serve`), the local dashboard, and the MCP server are **thin adapters**
over it.

A policy decision, an audit write, or a masking rule that lives in an adapter is
a bug. Adapters are wiring and presentation only — put logic in `internal/`.

## Development workflow

- **Strict red/green TDD.** Write tests for the behavior you're adding, verify
  they fail, then implement until they pass. If you must change an existing test
  to make it pass, explain why in the PR.
- **Regression first.** Before fixing a bug, add a test that reproduces it.
- **Format and vet** before committing: `gofmt` and `go vet` run as CI checks
  (and `govulncheck` runs as its own job).
- **Keep docs current.** Update [docs/](docs/content/docs/) alongside behavior
  changes; update the README only when a new doc users need is added.
- **Commit messages** complete the sentence "This commit…" — e.g. "Adds an
  email verification flow" — with details in the body.
- **Schema changes** go through a numbered migration in
  [`internal/migrations/`](internal/migrations/); the server applies migrations
  on startup (don't run them by hand).

## Pull requests

1. Branch off `main`.
2. Make your change with tests; keep `make test`, `gofmt`, and `go vet` green.
3. Open a PR. CI (`build-test`, `govulncheck`, CodeQL, dependency review) must
   pass; `main` requires a PR and a passing `build-test` check before merging.
4. Prefer **squash** merges so each change is one revertable commit and shows up
   cleanly in auto-generated release notes.

## Releases

Maintainers cut releases with [`scripts/release.sh`](scripts/release.sh); see the
[releasing guide](docs/content/docs/) for the version scheme and how to verify
published binaries. Contributors don't need to do anything release-specific.
