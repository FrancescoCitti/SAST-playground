# Convenience targets for building and exercising the SAST gate locally.
# CI does not depend on this Makefile; it calls `go build` directly.

GO      ?= go
BIN     ?= bin/sarifgate
PKG     := ./cmd/sarifgate

.PHONY: all build test vet tidy gate clean

all: vet test build

# Produce a single static binary. CGO is disabled so the result has no libc
# dependency and runs on any Linux CI image.
build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o $(BIN) $(PKG)

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy

# Merge every SARIF file under ./sarif-out and apply the default HIGH gate.
# Example: make gate THRESHOLD=MEDIUM
THRESHOLD ?= HIGH
gate: build
	$(BIN) -threshold $(THRESHOLD) -output merged.sarif -glob "sarif-out/*.sarif"

clean:
	rm -rf bin merged.sarif
