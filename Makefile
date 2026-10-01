MODULE  := github.com/middle-systems/cellwall
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Fixed timestamp source keeps builds reproducible: use the commit time, not "now".
DATE    ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) \
           -X $(MODULE)/internal/version.Commit=$(COMMIT) \
           -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test lint vuln verify-mod spikes cross all
all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o dist/cellwall ./cmd/cellwall

test:
	go test -race ./...

lint:
	go vet ./...
	golangci-lint run

vuln:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

verify-mod:
	go mod verify

# Needs Docker (and root for the DNS meter in s2). These encode security claims; see docs/spikes.md.
spikes:
	for s in s1_internal_network s1b_host_reachability s2_dns s3_ports s4_protected_paths s7_build_cache; do \
	  echo "=== $$s"; bash spikes/$$s.sh || exit 1; done

cross:
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
	  GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 go build -trimpath -o /dev/null ./cmd/cellwall || exit 1; done
