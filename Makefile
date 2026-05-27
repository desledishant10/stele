# Stele Makefile — developer-facing orchestration.
#
# Conventions:
#   - Every target is .PHONY (we have no real file outputs to declare).
#   - Targets read only and don't push to remotes. Anything that
#     modifies external state is gated by an explicit user invocation
#     (gh, cosign, kubectl) — not invoked from here.
#   - Output goes to ./bench/ for performance artifacts. Gitignore
#     covers it.

.DEFAULT_GOAL := help

GO        ?= go
GOFLAGS   ?=
RACE      ?= -race
BENCHTIME ?= 2s

# ----------------------------------------------------------------------
# Help / discoverability

.PHONY: help
help: ## Show this help.
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

# ----------------------------------------------------------------------
# Build / verify

.PHONY: build
build: ## Build every binary into ./bin/.
	@mkdir -p bin
	@for cmd in steled stele stele-witness stele-mirror stele-cosigner stele-backup stele-export-chain stele-loadgen; do \
		$(GO) build $(GOFLAGS) -o "bin/$$cmd" "./cmd/$$cmd" || exit 1; \
		echo "  built bin/$$cmd"; \
	done

.PHONY: vet
vet: ## go vet ./...
	$(GO) vet ./...

.PHONY: test
test: ## go test (race detector on by default).
	$(GO) test $(RACE) -count=1 ./...

.PHONY: test-short
test-short: ## Fast tests only (skips bench paths).
	$(GO) test -count=1 -short ./...

.PHONY: vuln
vuln: ## govulncheck — reachable-call CVE scan.
	$(GO) install golang.org/x/vuln/cmd/govulncheck@latest
	govulncheck ./...

# ----------------------------------------------------------------------
# Chaos: deliberate failure injection that the protocol must survive.

.PHONY: chaos
chaos: chaos-byzantine chaos-clock chaos-tamper ## Run every chaos scenario.

.PHONY: chaos-byzantine
chaos-byzantine: ## Byzantine peer: lying witnesses, wrong-key sigs, bit-flips.
	@echo "==> chaos: byzantine witness"
	$(GO) test -count=1 -run 'TestChaos_Peer|TestGossipDetectsFork|TestDishonestPeer' ./pkg/witness/

.PHONY: chaos-clock
chaos-clock: ## Clock skew vs drand beacon — operator must refuse to checkpoint.
	@echo "==> chaos: clock skew"
	$(GO) test -count=1 -run 'TestChaos_ClockSkew|TestChaos_NonDrandBeacon|TestChaos_BeaconUnreachable' ./pkg/core/

.PHONY: chaos-tamper
chaos-tamper: ## Disk tampering: tripwire must detect every mutation.
	@echo "==> chaos: disk tamper"
	$(GO) test -count=1 -run 'TestRun_DetectsLeaf' ./pkg/tripwire/

# ----------------------------------------------------------------------
# Performance: capture + compare benchmarks.
#
# Workflow:
#   make bench-baseline       # captures bench/baseline.txt (commit once)
#   ...make code changes...
#   make bench-current        # captures bench/current.txt
#   make bench-compare        # benchstat baseline vs current
#
# CI uses `bench-compare-strict` which fails on >2x regression.

.PHONY: bench
bench: ## Run benchmarks, print to stdout.
	$(GO) test -bench=. -benchtime=$(BENCHTIME) -run='^$$' -count=5 \
		./pkg/merkle/ ./pkg/core/

.PHONY: bench-baseline
bench-baseline: ## Capture benchmarks into bench/baseline.txt.
	@mkdir -p bench
	$(GO) test -bench=. -benchtime=$(BENCHTIME) -run='^$$' -count=5 \
		./pkg/merkle/ ./pkg/core/ \
		| tee bench/baseline.txt

.PHONY: bench-current
bench-current: ## Capture benchmarks into bench/current.txt.
	@mkdir -p bench
	$(GO) test -bench=. -benchtime=$(BENCHTIME) -run='^$$' -count=5 \
		./pkg/merkle/ ./pkg/core/ \
		| tee bench/current.txt

GOBIN ?= $(shell $(GO) env GOPATH)/bin

.PHONY: bench-compare
bench-compare: ## benchstat-compare bench/current.txt against bench/baseline.txt.
	$(GO) install golang.org/x/perf/cmd/benchstat@latest
	$(GOBIN)/benchstat bench/baseline.txt bench/current.txt

.PHONY: bench-compare-strict
bench-compare-strict: ## Like bench-compare but fail on >2x regression.
	$(GO) install golang.org/x/perf/cmd/benchstat@latest
	@$(GOBIN)/benchstat -row /name -col .file bench/baseline.txt bench/current.txt | tee bench/diff.txt
	@./scripts/check_bench_regression.sh bench/diff.txt

# ----------------------------------------------------------------------
# Load: stele-loadgen against a running server.

.PHONY: load-quick
load-quick: build ## 30s load test (defaults; assumes steled on :8080).
	./bin/stele-loadgen --duration 30s --rps 200 --producers 8

.PHONY: load-burst
load-burst: build ## 60s burst (high concurrency, small payload).
	./bin/stele-loadgen --duration 60s --rps 2000 --producers 32 \
		--concurrency 128 --payload 64

# ----------------------------------------------------------------------
# Clean

.PHONY: clean
clean: ## Remove build artifacts and bench output.
	rm -rf bin/ bench/
