#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — MCP Docker Integration Tests
# Tests MCP server handler logic with Docker runtime checks
# Requires: Docker Engine running (tests skip gracefully if unavailable)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }

echo "============================================"
echo "DevSecOps AI Team — MCP Docker Integration Tests"
echo "============================================"
echo ""

# ═══════════════════════════════════════════
# Section 1: Docker Availability
# ═══════════════════════════════════════════
echo "--- Section 1: Docker Availability ---"

DOCKER_AVAILABLE=false
if command -v docker &>/dev/null; then
  pass "docker command available"
  if docker info &>/dev/null 2>&1; then
    pass "Docker daemon running"
    DOCKER_AVAILABLE=true
    DOCKER_VERSION=$(docker info --format '{{.ServerVersion}}' 2>/dev/null || echo "unknown")
    pass "Docker version: $DOCKER_VERSION"
  else
    fail "Docker daemon not running"
    pass "Docker version: skipped"
  fi
else
  fail "docker command not found"
  fail "Docker daemon: skipped"
  fail "Docker version: skipped"
fi

# ═══════════════════════════════════════════
# Section 2: Tool Images Check
# ═══════════════════════════════════════════
echo ""
echo "--- Section 2: Tool Images Check ---"

TOOL_IMAGES=(
  "semgrep:returntocorp/semgrep"
  "gitleaks:zricethezav/gitleaks"
  "grype:anchore/grype"
  "trivy:aquasec/trivy"
  "checkov:bridgecrew/checkov"
  "zap:ghcr.io/zaproxy/zaproxy"
  "syft:anchore/syft"
)

if [ "$DOCKER_AVAILABLE" = true ]; then
  IMAGES_LIST=$(docker images --format '{{.Repository}}' 2>/dev/null || echo "")
  INSTALLED_COUNT=0
  for entry in "${TOOL_IMAGES[@]}"; do
    TOOL_NAME="${entry%%:*}"
    IMAGE_PREFIX="${entry#*:}"
    if echo "$IMAGES_LIST" | grep -q "$IMAGE_PREFIX"; then
      pass "$TOOL_NAME image installed ($IMAGE_PREFIX)"
      INSTALLED_COUNT=$((INSTALLED_COUNT + 1))
    else
      echo "  [SKIP] $TOOL_NAME image not installed ($IMAGE_PREFIX) — pull to enable"
    fi
  done
  if [ "$INSTALLED_COUNT" -gt 0 ]; then
    pass "at least 1 tool image available ($INSTALLED_COUNT/7)"
  else
    echo "  [SKIP] no tool images installed — pull images to enable full testing"
    pass "image check completed (0 installed — optional)"
  fi
else
  echo "  [SKIP] Docker not available — skipping image checks"
  pass "image checks skipped (no Docker)"
fi

# ═══════════════════════════════════════════
# Section 3: MCP Status Handler Logic
# ═══════════════════════════════════════════
echo ""
echo "--- Section 3: MCP Status Handler Logic ---"

MCP_SERVER="$ROOT_DIR/mcp/server.mjs"

[ -f "$MCP_SERVER" ] && pass "server.mjs exists" || fail "server.mjs missing"

# Verify status handler checks Docker (uses runCommand("docker", ["info", ...]))
grep -q 'checkDockerTools' "$MCP_SERVER" && pass "status handler calls checkDockerTools" || fail "status handler should call checkDockerTools"
grep -q '"info"' "$MCP_SERVER" && pass "checkDockerTools runs docker info" || fail "checkDockerTools should run docker info"

# Verify all 7 tool images are defined
for entry in "${TOOL_IMAGES[@]}"; do
  IMAGE_PREFIX="${entry#*:}"
  grep -q "$IMAGE_PREFIX" "$MCP_SERVER" && pass "server.mjs defines $IMAGE_PREFIX" || fail "server.mjs should define $IMAGE_PREFIX"
done

# ═══════════════════════════════════════════
# Section 4: MCP Scan Handler Logic
# ═══════════════════════════════════════════
echo ""
echo "--- Section 4: MCP Scan Handler Logic ---"

# Verify scan handler calls job-dispatcher
grep -q 'job-dispatcher' "$MCP_SERVER" && pass "scan handler uses job-dispatcher.sh" || fail "scan handler should use job-dispatcher.sh"

# Verify scan handler reads normalized output
grep -q 'normalized.json' "$MCP_SERVER" && pass "scan handler reads normalized.json" || fail "scan handler should read normalized.json"

# Verify timeout is set
grep -q 'timeout' "$MCP_SERVER" && pass "scan handler has timeout" || fail "scan handler should have timeout"

# Verify execFileSync usage (not execSync — security)
grep -q 'execFileSync' "$MCP_SERVER" && pass "uses execFileSync (safe)" || fail "should use execFileSync not execSync"
! grep -q 'execSync(' "$MCP_SERVER" && pass "no execSync (command injection safe)" || fail "should not use execSync"

# ═══════════════════════════════════════════
# Section 5: Runner Infrastructure
# ═══════════════════════════════════════════
echo ""
echo "--- Section 5: Runner Infrastructure ---"

RUNNER_DIR="$ROOT_DIR/runner"
FORMATTER_DIR="$ROOT_DIR/formatters"

[ -f "$RUNNER_DIR/job-dispatcher.sh" ] && pass "job-dispatcher.sh exists" || fail "job-dispatcher.sh missing"
[ -f "$RUNNER_DIR/result-collector.sh" ] && pass "result-collector.sh exists" || fail "result-collector.sh missing"
[ -f "$RUNNER_DIR/Dockerfile" ] && pass "Dockerfile exists" || fail "Dockerfile missing"
[ -f "$RUNNER_DIR/docker-compose.yml" ] && pass "docker-compose.yml exists" || fail "docker-compose.yml missing"

# Verify formatter files
for f in json-normalizer.sh sarif-formatter.sh markdown-formatter.sh html-formatter.sh; do
  [ -f "$FORMATTER_DIR/$f" ] && pass "formatter $f exists" || fail "formatter $f missing"
done

# Verify compose defines all 7 tool profiles
COMPOSE="$RUNNER_DIR/docker-compose.yml"
for tool in semgrep gitleaks grype trivy checkov zap syft; do
  grep -q "$tool" "$COMPOSE" && pass "compose defines $tool" || fail "compose should define $tool"
done

# ═══════════════════════════════════════════
# Section 6: Docker Functional Test (conditional)
# ═══════════════════════════════════════════
echo ""
echo "--- Section 6: Docker Functional Test (conditional) ---"

if [ "$DOCKER_AVAILABLE" = true ]; then
  # Test: devsecops_status equivalent — Docker info + image check
  DOCKER_INFO_VERSION=$(docker info --format '{{.ServerVersion}}' 2>/dev/null || echo "")
  [ -n "$DOCKER_INFO_VERSION" ] && pass "docker info returns version: $DOCKER_INFO_VERSION" || fail "docker info failed"

  # Test: image listing format matches MCP handler expectation
  IMAGES_FORMATTED=$(docker images --format '{{.Repository}}:{{.Tag}}' 2>/dev/null | head -5 || echo "")
  [ -n "$IMAGES_FORMATTED" ] && pass "docker images --format works" || fail "docker images --format failed"

  # Test: MCP server syntax check
  if command -v node &>/dev/null; then
    (cd "$ROOT_DIR/mcp" && node --check server.mjs 2>/dev/null) && pass "server.mjs syntax valid" || fail "server.mjs syntax error"
  else
    echo "  [SKIP] node not available — skipping syntax check"
  fi
else
  echo "  [SKIP] Docker not available — skipping functional tests"
  pass "functional tests skipped (no Docker)"
fi

# ═══════════════════════════════════════════
# Summary
# ═══════════════════════════════════════════
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL))
echo "MCP Docker Integration Tests: $PASS/$TOTAL passed"
if [ "$FAIL" -gt 0 ]; then
  echo "FAILED: $FAIL tests failed"
  exit 1
else
  echo "ALL TESTS PASSED"
fi
