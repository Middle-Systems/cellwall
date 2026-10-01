MODULE  := github.com/middle-systems/cellwall
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# Fixed timestamp source keeps builds reproducible: use the commit time, not "now".
DATE    ?= $(shell git show -s --format=%cI HEAD 2>/dev/null || echo unknown)
LDFLAGS := -s -w -X $(MODULE)/internal/version.Version=$(VERSION) \
           -X $(MODULE)/internal/version.Commit=$(COMMIT) \
           -X $(MODULE)/internal/version.Date=$(DATE)

.PHONY: build test lint vuln verify-mod spikes cross all e2e fuzz gateway-image
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
	# Run every spike even if one fails, so a single CI run shows all results; fail at the end.
	rc=0; for s in s1_internal_network s1b_host_reachability s2_dns s3_ports s4_protected_paths s7_build_cache s9_policy_reload_mount s10_nested_mounts; do \
	  echo "=== $$s"; bash spikes/$$s.sh || rc=1; done; exit $$rc

cross:
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
	  GOOS=$${t%/*} GOARCH=$${t#*/} CGO_ENABLED=0 go build -trimpath -o /dev/null ./cmd/cellwall || exit 1; done

# Builds the gateway image from the host-arch linux binary (the release build uses per-arch binaries).
gateway-image:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(shell go env GOARCH) go build -trimpath -ldflags '$(LDFLAGS)' -o dist/cellwall-linux ./cmd/cellwall
	docker build -f build/gateway/Dockerfile --build-arg BINARY=cellwall-linux -t cellwall-gateway:dev dist

# End-to-end escape checks against real containers (needs Docker). CI sets CELLWALL_E2E_REQUIRE=1
# so a missing Docker is a failure there, not a skip.
e2e:
	go test -tags e2e -count=1 -timeout 10m ./test/e2e/...

# Short fuzzing pass over every fuzz target; FUZZTIME=2m for a longer local run.
FUZZTIME ?= 15s
fuzz:
	set -e; for t in FuzzNormalizeHost FuzzMatch FuzzPattern FuzzParse; do \
	  go test ./internal/policy -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME); done; \
	for t in FuzzReadClientHello FuzzParseClientHello FuzzParseConnectTarget; do \
	  go test ./internal/proxy -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME); done
