SHELL := /bin/bash
GO := go
CARGO := cargo
NPX := npx
OUT_DIR := out
GOCACHE ?= $(CURDIR)/.gocache
GOPATH ?= $(CURDIR)/.gopath
GOMODCACHE ?= $(CURDIR)/.gomodcache

.PHONY: all cli engine ui clean test fmt

all: cli engine ui

cli:
	@cd cmd/panoptes && GOCACHE="$(GOCACHE)" GOPATH="$(GOPATH)" GOMODCACHE="$(GOMODCACHE)" $(GO) build -ldflags "-X github.com/nmapaye/panoptes/internal/cli.Version=$$(git rev-parse --short HEAD 2>/dev/null || echo dev)" -o ../../bin/panoptes

engine:
	@cd engine && $(CARGO) build

ui:
	@cd ui && npm ci && npm run build

fmt:
	@GOCACHE="$(GOCACHE)" GOPATH="$(GOPATH)" GOMODCACHE="$(GOMODCACHE)" $(GO) fmt ./...
	@cd engine && $(CARGO) fmt || true
	@cd ui && npm run fmt || true

clean:
	@rm -rf bin $(OUT_DIR) $(GOCACHE) $(GOPATH) $(GOMODCACHE)
	@cd engine && $(CARGO) clean || true
	@cd ui && rm -rf node_modules dist || true

test:
	@GOCACHE="$(GOCACHE)" GOPATH="$(GOPATH)" GOMODCACHE="$(GOMODCACHE)" $(GO) test ./...
	@cd engine && $(CARGO) test
	@cd ui && npm test
	@cd ui && npm run type-check
	@cd ui && npm run build
