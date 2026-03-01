#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Prerequisites Checker
# Verifies Docker and tool availability
# Usage: check-prerequisites.sh [--tool <name>]

TOOL="${2:-}"
PASS=0
FAIL=0

pass() { ((PASS++)); echo "  [OK] $1"; }
fail() { ((FAIL++)); echo "  [FAIL] $1"; }

echo "DevSecOps AI Team — Prerequisites Check"
echo "========================================="

# Docker Engine
if command -v docker &>/dev/null; then
  DOCKER_VERSION=$(docker --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+' | head -1)
  pass "Docker Engine installed (v${DOCKER_VERSION})"
  if docker info &>/dev/null; then
    pass "Docker daemon running"
  else
    fail "Docker daemon not running — start Docker first"
  fi
else
  fail "Docker not installed — install Docker Engine 20.10+"
fi

# Docker Compose
if docker compose version &>/dev/null; then
  COMPOSE_VERSION=$(docker compose version --short 2>/dev/null)
  pass "Docker Compose available (v${COMPOSE_VERSION})"
elif command -v docker-compose &>/dev/null; then
  pass "docker-compose (legacy) available"
else
  fail "Docker Compose not available"
fi

# Disk space (need ~2GB for images)
AVAILABLE_GB=$(df -BG . 2>/dev/null | tail -1 | awk '{print $4}' | tr -d 'G' || echo "0")
if [ "${AVAILABLE_GB:-0}" -ge 2 ] 2>/dev/null; then
  pass "Disk space: ${AVAILABLE_GB}GB available (minimum 2GB)"
else
  # macOS fallback
  AVAILABLE_MB=$(df -m . 2>/dev/null | tail -1 | awk '{print $4}' || echo "0")
  if [ "${AVAILABLE_MB:-0}" -ge 2048 ] 2>/dev/null; then
    pass "Disk space: sufficient"
  else
    fail "Insufficient disk space (need 2GB+)"
  fi
fi

# Check specific tool if requested
if [ -n "$TOOL" ]; then
  echo ""
  echo "Tool-specific check: $TOOL"
  case "$TOOL" in
    semgrep)
      docker image inspect returntocorp/semgrep:latest &>/dev/null && pass "Semgrep image available" || fail "Semgrep image not pulled — run: docker pull returntocorp/semgrep:latest"
      ;;
    gitleaks)
      docker image inspect zricethezav/gitleaks:latest &>/dev/null && pass "GitLeaks image available" || fail "GitLeaks image not pulled — run: docker pull zricethezav/gitleaks:latest"
      ;;
    grype)
      docker image inspect anchore/grype:latest &>/dev/null && pass "Grype image available" || fail "Grype image not pulled — run: docker pull anchore/grype:latest"
      ;;
    trivy)
      docker image inspect aquasec/trivy:latest &>/dev/null && pass "Trivy image available" || fail "Trivy image not pulled — run: docker pull aquasec/trivy:latest"
      ;;
    checkov)
      docker image inspect bridgecrew/checkov:latest &>/dev/null && pass "Checkov image available" || fail "Checkov image not pulled — run: docker pull bridgecrew/checkov:latest"
      ;;
    zap)
      docker image inspect ghcr.io/zaproxy/zaproxy:stable &>/dev/null && pass "ZAP image available" || fail "ZAP image not pulled — run: docker pull ghcr.io/zaproxy/zaproxy:stable"
      ;;
    syft)
      docker image inspect anchore/syft:latest &>/dev/null && pass "Syft image available" || fail "Syft image not pulled — run: docker pull anchore/syft:latest"
      ;;
  esac
fi

echo ""
echo "Results: $PASS passed / $FAIL failed"
[ "$FAIL" -gt 0 ] && exit 1 || exit 0
