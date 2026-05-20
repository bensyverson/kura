<!-- Title: complete the sentence "This commit…" e.g. "Adds an email verification flow" -->

## What and why

<!-- What does this change do, and what problem does it solve? Link any issue. -->

## How it was tested

<!-- New/changed tests, and how you ran them. Kura follows strict red/green TDD. -->

## Checklist

- [ ] Tests added/updated and `make test` passes
- [ ] `gofmt` and `go vet` are clean
- [ ] Logic lives in `internal/` (adapters stay wiring + presentation only)
- [ ] Docs updated if behavior changed; schema changes have a numbered migration
- [ ] No secrets, credentials, or real PII in code, tests, or fixtures
