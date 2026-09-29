# Gotchas

Project-specific traps that cost real time and that no general rule predicts. Read at session start; append when you hit one.

- **Fix at the source when you can.** A gotcha is a bug report on our tooling, not a permanent fact — if it can be fixed in code, file it in `job` and fix it instead of recording it here.
- **Delete anything that becomes obvious, gets fixed, or stops recurring.** Keep this list short; a long list is one nobody reads.
- **Feedback about `AGENTS.md` itself** — a rule that was wrong, misread, or cost time — goes here too, prefixed `rule:`. It is harvested when the shared rules are reviewed.

Format: one dated H2 per entry, a bold headline, then what happened and what to do instead.

---

## 2026-08-16 — `go fix` can rewrite staged files silently, and the hook fails the commit

**The pre-commit hook runs `go fix ./...` and hard-fails if it modified any staged file**, printing a re-stage hint — silent rewrites once slipped through and landed as follow-up commits. Run `go fix ./...` yourself until it is clean, then stage, then commit.

## 2026-08-16 — the pre-commit hook does more than format and test

**`scripts/git-hooks/pre-commit` also runs `go vet ./...`, `go mod tidy` (fails if `go.mod`/`go.sum` change) and `node --test internal/web/jstest/*.test.mjs` when Node and that directory exist.** Running only `gofmt` and the touched tests will still bounce.
