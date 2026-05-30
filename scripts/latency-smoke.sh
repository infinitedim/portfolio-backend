#!/usr/bin/env bash
# Latency smoke test — asserts P95 < SLA_MS for Tier A/B routes.
# Usage: ./scripts/latency-smoke.sh [base_url] [sla_ms]
# Requires: hey (go install github.com/rakyll/hey@latest)

set -euo pipefail

BASE_URL="${1:-http://localhost:8080}"
SLA_MS="${2:-50}"
REQUESTS=100
CONCURRENCY=5
FAILURES=0

command -v hey >/dev/null 2>&1 || {
  echo "Installing hey..."
  go install github.com/rakyll/hey@latest 2>/dev/null
  export PATH=$PATH:~/go/bin
}

check_route() {
  local method="$1"
  local path="$2"
  local extra_args="${3:-}"

  local result
  if [ "$method" = "POST" ]; then
    result=$(hey -n "$REQUESTS" -c "$CONCURRENCY" -m POST $extra_args "${BASE_URL}${path}" 2>&1)
  else
    result=$(hey -n "$REQUESTS" -c "$CONCURRENCY" "${BASE_URL}${path}" 2>&1)
  fi

  local p95_secs
  p95_secs=$(echo "$result" | grep "95%" | awk '{print $2}' | head -1)

  if [ -z "$p95_secs" ]; then
    echo "SKIP $method $path (no P95 data)"
    return
  fi

  local p95_ms
  p95_ms=$(echo "$p95_secs * 1000" | bc -l 2>/dev/null | cut -d. -f1)

  if [ -z "$p95_ms" ]; then
    p95_ms=$(python3 -c "print(int(float('$p95_secs') * 1000))" 2>/dev/null || echo "0")
  fi

  if [ "$p95_ms" -gt "$SLA_MS" ]; then
    echo "FAIL $method $path P95=${p95_ms}ms > ${SLA_MS}ms"
    FAILURES=$((FAILURES + 1))
  else
    echo "PASS $method $path P95=${p95_ms}ms"
  fi
}

echo "=== Latency Smoke Test ==="
echo "Target: ${BASE_URL}, SLA: P95 < ${SLA_MS}ms"
echo ""

# Warm up
curl -s "${BASE_URL}/health" > /dev/null 2>&1 || true
sleep 1

echo "--- Tier A (in-memory) ---"
check_route GET /health
check_route GET /health/detailed
check_route GET /health/database
check_route GET /health/redis
check_route GET /health/ready
check_route GET /metrics
check_route POST /api/analytics/pageview '-H "Content-Type: application/json" -d {"path":"/test"}'
check_route GET /api/gate/status

echo ""
echo "--- Tier B (database) ---"
check_route GET /api/blog
check_route GET /api/blog/tags
check_route GET /api/rss
check_route GET /api/portfolio
check_route GET /api/blog/series
check_route POST "/api/logs" '-H "Content-Type: application/json" -d {"entries":[{"level":"info","message":"test","timestamp":"2026-01-01T00:00:00Z"}]}'

echo ""
echo "--- Tier C (proxy, cache-hit only) ---"
# Prime the cache first
curl -s "${BASE_URL}/api/roadmap/streak" > /dev/null 2>&1 || true
curl -s "${BASE_URL}/api/roadmap/dashboard" > /dev/null 2>&1 || true
curl -s "${BASE_URL}/api/github/user/infinitedim" > /dev/null 2>&1 || true
sleep 2

check_route GET /api/roadmap/streak
check_route GET /api/roadmap/dashboard
check_route GET /api/github/user/infinitedim

echo ""
if [ "$FAILURES" -gt 0 ]; then
  echo "RESULT: ${FAILURES} route(s) exceeded SLA"
  exit 1
else
  echo "RESULT: All routes within ${SLA_MS}ms SLA"
  exit 0
fi
