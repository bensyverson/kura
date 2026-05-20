BINARY := kura
PKG    := ./cmd/kura

# Build version, injected into main.version. Defaults to the git description
# (a tag like v0.1.0 once tagged, else the short commit, +"-dirty" if the
# tree is modified). scripts/release.sh and the release workflow pass an
# explicit VERSION.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build install run test test-integration fmt fix vet clean help

build:
	go build $(LDFLAGS) -o $(BINARY) $(PKG)

install:
	go install $(LDFLAGS) $(PKG)

# Usage: make run ARGS="status"
run:
	go run $(PKG) $(ARGS)

test:
	go test ./...

# Brings up the containerized Postgres (see scripts/test-db.sh) and runs
# the full suite with the integration tests enabled. Without this, the
# integration tests skip themselves and `make test` stays green.
test-integration:
	eval "$$(scripts/test-db.sh)" && go test ./...

fmt:
	go fmt ./...

fix:
	go fix ./...

vet:
	go vet ./...

clean:
	rm -f $(BINARY)

help:
	@echo "Targets:"
	@echo "  build    - compile ./$(BINARY) from $(PKG)"
	@echo "  install  - go install to \$$GOBIN"
	@echo "  run      - go run (pass args via ARGS=\"...\")"
	@echo "  test     - run all Go tests (integration tests skip without a DB)"
	@echo "  test-integration - bring up the test Postgres and run the full suite"
	@echo "  fmt      - go fmt ./..."
	@echo "  fix      - go fix ./..."
	@echo "  vet      - go vet ./..."
	@echo "  clean    - remove the local binary"
