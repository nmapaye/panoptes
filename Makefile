SHELL := /bin/bash
GO := go
CARGO := cargo
NPX := npx

.PHONY: all cli engine ui clean test fmt

all: cli engine ui

cli:
	@cd cmd/panoptes && $(GO) build -ldflags "-X github.com/nmapaye/panoptes/internal/cli.Version=$$(git rev-parse --short HEAD 2>/dev/null || echo dev)" -o ../../bin/panoptes

engine:
	@cd engine && $(CARGO) build

ui:
	@cd ui && npm ci && npm run build

fmt:
	@$(GO) fmt ./...
	@cd engine && $(CARGO) fmt || true
	@cd ui && npm run fmt || true

clean:
	@rm -rf bin
	@cd engine && $(CARGO) clean || true
	@cd ui && rm -rf node_modules dist || true

test:
	@$(GO) test ./...
	@cd engine && $(CARGO) test
