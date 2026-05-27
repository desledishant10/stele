#!/usr/bin/env bash
# run-chaos.sh — orchestrator for the stele chaos rig.
#
# Subcommands:
#   setup              one-time: enroll a producer, register the 3 witnesses
#                      with the operator (each via its toxiproxy URL)
#   baseline           assert healthy; loadgen 30s; print key metrics
#   load [seconds]     start a continuous loadgen in the background
#   latency <w> <ms>   inject `ms` of one-way latency on a witness proxy
#                      (e.g. latency witness-c 500)
#   loss <w> <pct>     inject `pct`% packet loss on a witness proxy
#   partition <w>      full partition (disable the proxy entirely)
#   heal <w>           remove all toxics + re-enable the proxy
#   show               print current toxics per witness proxy
#   metrics            grep stele_* metrics from the operator
#   logs <svc>         tail the docker-compose service's logs
#   down               docker compose down -v
#
# Self-verifying scenarios (each injects, asserts the expected metric
# signature via PromQL, heals, asserts recovery; non-zero exit on any
# assertion failure):
#
#   assert-baseline                confirm healthy + driving appends + 3 witnesses cosigning
#   assert-latency <w> <ms>        latency on `w`: that witness's p99 must climb
#   assert-partition <w>           partition `w`: error rate climbs, other witnesses absorb
#   assert-all                     run all of the above in sequence (acts like a CI gate)
#
# Hosts:
#   operator:           http://localhost:18080
#   mirror:             http://localhost:18444
#   toxiproxy admin:    http://localhost:18474
#   witness via toxiproxy from the operator-side network:
#                       http://toxiproxy:19090  (a)
#                       http://toxiproxy:19091  (b)
#                       http://toxiproxy:19092  (c)
#
# Notes on assertions: the scripts don't fail when the protocol's
# defences fire — they're testing that those defences fire. Watch
# metrics and the structured log to confirm the expected signatures
# (witness cosign error rate climbs during a partition; tree size keeps
# growing; tripwire stays clean; etc.).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_PATH="$SCRIPT_DIR/$(basename "$0")"
cd "$SCRIPT_DIR"

OPERATOR_URL="${OPERATOR_URL:-http://localhost:18080}"
TOXIPROXY_URL="${TOXIPROXY_URL:-http://localhost:18474}"
PROMETHEUS_URL="${PROMETHEUS_URL:-http://localhost:19094}"

usage() {
    sed -n '2,/^set -euo/p' "$SCRIPT_PATH" | sed -e 's/^# \{0,1\}//' | head -n 35
    exit 0
}

require_compose_up() {
    # Lightweight check: operator must reply on its mapped port.
    if ! curl -fsS "$OPERATOR_URL/readyz" > /dev/null 2>&1; then
        echo "operator at $OPERATOR_URL not ready. Run 'docker compose up -d --build' first." >&2
        exit 1
    fi
}

# Witness toxiproxy port mapping (internal name → host port).
# These are toxiproxy's listen ports; the operator container reaches
# the same proxies via toxiproxy:19090/19091/19092 on the docker
# network. Setup uses those internal URLs when registering witnesses.
witness_port() {
    case "$1" in
        witness-a) echo 19090 ;;
        witness-b) echo 19091 ;;
        witness-c) echo 19092 ;;
        *) echo "unknown witness: $1" >&2; exit 2 ;;
    esac
}

cmd_setup() {
    require_compose_up
    # Always regenerate the producer key inside the operator
    # container. Chaos rigs are short-lived; the container's /tmp is
    # gone after `docker compose down`, so reusing a stale host-side
    # cache would point enroll-producer at a missing file.
    docker compose exec operator stele producer-init \
        --id chaos-prod --out /tmp/p > /dev/null
    docker compose exec operator stele enroll-producer \
        --server "http://operator:8080" \
        --id chaos-prod \
        --key /tmp/p \
        --scope "chaos:loadgen" \
        --validity 24h
    # Register every witness with the operator. Each registration uses
    # the toxiproxy URL so all witness traffic flows through it.
    for w in witness-a witness-b witness-c; do
        port=$(witness_port "$w")
        docker compose exec operator stele witness-add \
            --server "http://operator:8080" \
            --id "$w" \
            --url "http://toxiproxy:${port}"
    done
    echo "setup complete: 1 producer, 3 witnesses registered"
}

cmd_baseline() {
    require_compose_up
    echo "==> baseline /readyz on every component"
    for hp in 18080 18444; do
        printf "  localhost:%s/readyz: " "$hp"
        curl -fsS "http://localhost:${hp}/readyz" | head -c 200
        echo
    done
    echo
    echo "==> 30s loadgen at 100 rps (one-shot)"
    docker compose exec operator stele-loadgen \
        --server "http://operator:8080" \
        --producers 4 --rps 100 --duration 30s --warmup 2s \
        --payload 96 --concurrency 32 || true
    echo
    cmd_metrics
}

cmd_load() {
    local secs="${1:-300}"
    require_compose_up
    echo "==> starting continuous loadgen for ${secs}s in the background"
    docker compose run -d --rm loadgen \
        --server "http://operator:8080" \
        --producers 8 --rps 200 \
        --duration "${secs}s" --payload 96 --concurrency 64
    echo "loadgen running in the background. Use 'docker compose logs -f' to follow."
}

# All toxiproxy toxics are scoped to ONE proxy and ONE direction
# (downstream / upstream). For "operator-to-witness slowness" inject on
# `downstream`; "witness-to-operator slowness" use `upstream`. We use
# downstream by default since witness cosign is operator→witness.

toxic_url() { echo "$TOXIPROXY_URL/proxies/$1/toxics"; }

cmd_latency() {
    local w="${1:?witness id required}"
    local ms="${2:?latency ms required}"
    require_compose_up
    curl -fsS -X POST "$(toxic_url "$w")" \
        -H 'Content-Type: application/json' \
        -d "{\"type\":\"latency\",\"name\":\"chaos-latency\",\"stream\":\"downstream\",\"attributes\":{\"latency\":${ms}}}" \
        | head -c 200
    echo
    echo "injected ${ms}ms downstream latency on ${w}"
}

cmd_loss() {
    local w="${1:?witness id required}"
    local pct="${2:?loss pct required}"
    require_compose_up
    # Toxiproxy doesn't have a packet-loss toxic, but `timeout` toxic
    # times out a percentage of connections — same observable effect
    # from the operator's view (calls error out at a rate).
    curl -fsS -X POST "$(toxic_url "$w")" \
        -H 'Content-Type: application/json' \
        -d "{\"type\":\"timeout\",\"name\":\"chaos-timeout\",\"stream\":\"downstream\",\"toxicity\":$(awk -v p=$pct 'BEGIN{print p/100.0}'),\"attributes\":{\"timeout\":0}}" \
        | head -c 200
    echo
    echo "injected ${pct}% connection timeout on ${w}"
}

cmd_partition() {
    local w="${1:?witness id required}"
    require_compose_up
    # Disable the proxy entirely → operator sees connection refused.
    curl -fsS -X POST "$TOXIPROXY_URL/proxies/${w}" \
        -H 'Content-Type: application/json' \
        -d '{"enabled":false}' \
        | head -c 200
    echo
    echo "partitioned ${w} from the operator (proxy disabled)"
}

cmd_heal() {
    local w="${1:?witness id required}"
    require_compose_up
    # Remove every toxic on this proxy.
    curl -fsS "$(toxic_url "$w")" | tr -d '\n' | python3 -c "
import sys, json, urllib.request
toxics = json.load(sys.stdin)
for t in toxics:
    req = urllib.request.Request('${TOXIPROXY_URL}/proxies/${w}/toxics/' + t['name'], method='DELETE')
    urllib.request.urlopen(req).read()
    print('removed', t['name'])
" 2>/dev/null || true
    # Re-enable the proxy if it was disabled by partition.
    curl -fsS -X POST "$TOXIPROXY_URL/proxies/${w}" \
        -H 'Content-Type: application/json' \
        -d '{"enabled":true}' > /dev/null
    echo "healed ${w}: all toxics removed, proxy re-enabled"
}

cmd_show() {
    require_compose_up
    for w in witness-a witness-b witness-c; do
        echo "--- $w ---"
        curl -fsS "$TOXIPROXY_URL/proxies/${w}" \
            | python3 -m json.tool 2>/dev/null || true
        echo
    done
}

cmd_metrics() {
    require_compose_up
    echo "==> stele metrics from operator"
    curl -fsS "$OPERATOR_URL/metrics" \
        | grep -E '^stele_(appends_total|tree_size|active_epoch|ingest_rejects_total|witness_cosign_total|witness_quorum_healthy|last_anchor_age|append_duration_seconds_count)' \
        | sort
}

cmd_logs() {
    local svc="${1:-operator}"
    docker compose logs --tail=50 -f "$svc"
}

cmd_down() {
    docker compose down -v
}

# ----------------------------------------------------------------------
# PromQL-driven scenario assertions.
#
# Each assertion is one Prometheus query + a comparison. The helper
# `promql_assert` evaluates the query, parses the scalar/vector result
# (first sample's value), and tests it against an operator + threshold.
# Designed to be readable in shell so scenarios stay declarative:
#
#   promql_assert "GREATER" 0.5 \
#       "histogram_quantile(0.99, sum by (witness, le) (rate(stele_witness_cosign_duration_seconds_bucket[60s])))" \
#       'witness="witness-c"' \
#       "witness-c p99 latency under chaos"
#
# Args:
#   $1  op          GREATER | LESS | EQUAL_TO_ZERO | NONZERO
#   $2  threshold   numeric (ignored for EQUAL_TO_ZERO / NONZERO)
#   $3  query       PromQL expression
#   $4  label_match optional label-set filter passed to jq (e.g. 'witness="witness-c"')
#                   pass "" if not applicable
#   $5  label       human-readable description for the pass/fail line

promql_assert() {
    local op="$1" threshold="$2" query="$3" label_match="$4" label="$5"
    local raw value
    raw=$(curl -fsG --data-urlencode "query=${query}" "${PROMETHEUS_URL}/api/v1/query") \
        || { echo "  FAIL: $label — prometheus query failed" >&2; return 1; }

    if [ -n "$label_match" ]; then
        # Pick the sample whose labels contain the requested key=value.
        # `label_match` looks like 'witness="witness-c"' — we split it.
        local k v
        k="${label_match%=*}"
        v="${label_match#*=}"
        v="${v%\"}"; v="${v#\"}"
        value=$(echo "$raw" | jq -r --arg k "$k" --arg v "$v" \
            '.data.result[] | select(.metric[$k]==$v) | .value[1]' \
            | head -1)
    else
        value=$(echo "$raw" | jq -r '.data.result[0].value[1] // empty')
    fi

    if [ -z "$value" ] || [ "$value" = "null" ]; then
        # Missing samples treated based on op: NONZERO/GREATER → fail
        # (we expected SOME value); EQUAL_TO_ZERO/LESS → pass (zero is
        # the absence of a contradicting sample).
        case "$op" in
            EQUAL_TO_ZERO|LESS) echo "  OK:   $label (no samples, treated as 0)"; return 0 ;;
            *) echo "  FAIL: $label — no samples returned from PromQL" >&2; return 1 ;;
        esac
    fi

    # Use awk for float compare (bash doesn't do floats).
    local cmp
    case "$op" in
        GREATER)        cmp=$(awk -v a="$value" -v b="$threshold" 'BEGIN{print (a>b)}') ;;
        LESS)           cmp=$(awk -v a="$value" -v b="$threshold" 'BEGIN{print (a<b)}') ;;
        EQUAL_TO_ZERO)  cmp=$(awk -v a="$value" 'BEGIN{print (a==0)}') ;;
        NONZERO)        cmp=$(awk -v a="$value" 'BEGIN{print (a!=0)}') ;;
        *) echo "  FAIL: unknown op $op" >&2; return 1 ;;
    esac
    if [ "$cmp" = "1" ]; then
        printf "  OK:   %-60s value=%s %s %s\n" "$label" "$value" "$op" "$threshold"
        return 0
    fi
    printf "  FAIL: %-60s value=%s NOT %s %s\n" "$label" "$value" "$op" "$threshold" >&2
    return 1
}

# Wait for Prometheus to have scraped at least `dur` seconds of data
# since the last fault was injected. Default 20s — long enough for
# two 10s scrape intervals plus rate-window settling.
wait_for_scrape() {
    local dur="${1:-20}"
    echo "  ... waiting ${dur}s for metrics to propagate"
    sleep "$dur"
}

cmd_assert_baseline() {
    require_compose_up
    echo "==> ASSERT baseline: stack is healthy and producing entries"

    # Drive ~30s of synthetic traffic to populate metrics with
    # something to assert on.
    docker compose exec -T operator stele-loadgen \
        --server "http://operator:8080" \
        --producers 4 --rps 100 --duration 30s --warmup 2s \
        --payload 96 --concurrency 32 > /dev/null 2>&1 || true

    wait_for_scrape 15

    local failed=0
    # 1. Operator is achieving meaningful append throughput.
    promql_assert GREATER 50 \
        "sum(rate(stele_appends_total{outcome=\"ok\"}[1m]))" "" \
        "operator append rate > 50/s" || failed=$((failed+1))

    # 2. Each of the 3 witnesses has cosigned at least one checkpoint.
    for w in witness-a witness-b witness-c; do
        promql_assert GREATER 0 \
            "stele_witness_cosign_total{outcome=\"ok\"}" \
            "witness=\"$w\"" \
            "$w has cosigned at least one checkpoint" || failed=$((failed+1))
    done

    # 3. Zero appends were rejected with server-side errors.
    promql_assert EQUAL_TO_ZERO 0 \
        "sum(rate(stele_appends_total{outcome=\"error\"}[1m]))" "" \
        "operator append error rate is zero" || failed=$((failed+1))

    return $failed
}

cmd_assert_latency() {
    local w="${1:?witness id required}"
    local ms="${2:?latency ms required}"
    require_compose_up
    echo "==> ASSERT latency on ${w} = ${ms}ms"

    # Apply the toxic + drive load so cosign attempts actually fire.
    cmd_latency "$w" "$ms"
    docker compose exec -dT operator stele-loadgen \
        --server "http://operator:8080" \
        --producers 4 --rps 100 --duration 30s --payload 96 --concurrency 32 > /dev/null 2>&1 || true
    wait_for_scrape 25

    local failed=0
    # The injected witness's p99 must rise meaningfully — the toxic
    # is one-way `downstream` latency, so the floor is ms/1000s in
    # round-trip terms.
    local floor
    floor=$(awk -v ms="$ms" 'BEGIN{print (ms/1000)*0.7}')
    promql_assert GREATER "$floor" \
        "histogram_quantile(0.99, sum by (witness, le) (rate(stele_witness_cosign_duration_seconds_bucket[60s])))" \
        "witness=\"$w\"" \
        "$w p99 cosign latency > ${floor}s" || failed=$((failed+1))

    # Other witnesses must NOT see elevated latency (the toxic is
    # scoped to one proxy).
    for other in witness-a witness-b witness-c; do
        [ "$other" = "$w" ] && continue
        promql_assert LESS "$floor" \
            "histogram_quantile(0.99, sum by (witness, le) (rate(stele_witness_cosign_duration_seconds_bucket[60s])))" \
            "witness=\"$other\"" \
            "$other p99 unaffected (< ${floor}s)" || failed=$((failed+1))
    done

    # Operator throughput must hold up — witness gather is best-effort.
    promql_assert GREATER 50 \
        "sum(rate(stele_appends_total{outcome=\"ok\"}[1m]))" "" \
        "operator append rate held > 50/s under chaos" || failed=$((failed+1))

    cmd_heal "$w"
    return $failed
}

cmd_assert_partition() {
    local w="${1:?witness id required}"
    require_compose_up
    echo "==> ASSERT partition on ${w}"

    cmd_partition "$w"
    docker compose exec -dT operator stele-loadgen \
        --server "http://operator:8080" \
        --producers 4 --rps 100 --duration 30s --payload 96 --concurrency 32 > /dev/null 2>&1 || true
    wait_for_scrape 25

    local failed=0
    # Cosign error rate for the partitioned witness rises.
    promql_assert GREATER 0 \
        "rate(stele_witness_cosign_total{outcome=\"error\"}[60s])" \
        "witness=\"$w\"" \
        "$w cosign error rate climbs during partition" || failed=$((failed+1))

    # The other two witnesses keep cosigning successfully.
    for other in witness-a witness-b witness-c; do
        [ "$other" = "$w" ] && continue
        promql_assert GREATER 0 \
            "rate(stele_witness_cosign_total{outcome=\"ok\"}[60s])" \
            "witness=\"$other\"" \
            "$other still cosigning (quorum survives)" || failed=$((failed+1))
    done

    # Operator append throughput unaffected.
    promql_assert GREATER 50 \
        "sum(rate(stele_appends_total{outcome=\"ok\"}[1m]))" "" \
        "operator append rate held > 50/s during partition" || failed=$((failed+1))

    cmd_heal "$w"
    wait_for_scrape 15

    # Recovery: the partitioned witness has cosigned again since heal.
    # We compare absolute counter values before/after; "increased
    # within the last 30s" is the assertion.
    promql_assert GREATER 0 \
        "increase(stele_witness_cosign_total{outcome=\"ok\"}[30s])" \
        "witness=\"$w\"" \
        "$w resumed cosigning after heal" || failed=$((failed+1))

    return $failed
}

cmd_assert_all() {
    local total_failed=0
    local section_failed
    require_compose_up

    cmd_assert_baseline || total_failed=$((total_failed + $?))
    echo
    section_failed=0
    cmd_assert_latency witness-c 500 || section_failed=$((section_failed + $?))
    total_failed=$((total_failed + section_failed))
    echo
    section_failed=0
    cmd_assert_partition witness-c || section_failed=$((section_failed + $?))
    total_failed=$((total_failed + section_failed))

    echo
    if [ "$total_failed" -eq 0 ]; then
        echo "==========================================="
        echo "  ALL CHAOS ASSERTIONS PASSED"
        echo "==========================================="
        return 0
    fi
    echo "==========================================="
    echo "  CHAOS ASSERTIONS FAILED: $total_failed total" >&2
    echo "==========================================="
    return 1
}

main() {
    local sub="${1:-help}"
    shift || true
    case "$sub" in
        setup)      cmd_setup "$@" ;;
        baseline)   cmd_baseline "$@" ;;
        load)       cmd_load "$@" ;;
        latency)    cmd_latency "$@" ;;
        loss)       cmd_loss "$@" ;;
        partition)  cmd_partition "$@" ;;
        heal)       cmd_heal "$@" ;;
        show)       cmd_show "$@" ;;
        metrics)    cmd_metrics "$@" ;;
        logs)       cmd_logs "$@" ;;
        down)              cmd_down "$@" ;;
        assert-baseline)   cmd_assert_baseline "$@" ;;
        assert-latency)    cmd_assert_latency "$@" ;;
        assert-partition)  cmd_assert_partition "$@" ;;
        assert-all)        cmd_assert_all "$@" ;;
        help|-h|--help) usage ;;
        *)          echo "unknown subcommand: $sub" >&2; usage ;;
    esac
}
main "$@"
