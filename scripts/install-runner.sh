#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Runner Installer
# Usage: install-runner.sh [--mode minimal|full]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
MODE="${2:-minimal}"

echo "DevSecOps AI Team — Runner Installation"
echo "========================================"
echo "Mode: $MODE"

# Check prerequisites
echo ""
echo "Checking prerequisites..."
bash "$ROOT_DIR/scripts/check-prerequisites.sh" || { echo "Prerequisites check failed"; exit 1; }

case "$MODE" in
  minimal)
    echo ""
    echo "Installing in minimal mode (oneshot containers)..."
    echo "No persistent containers will be started."
    echo "Tools will run via 'docker run --rm' on demand."
    echo ""
    echo "Pre-pulling essential images..."
    docker pull zricethezav/gitleaks:latest
    docker pull returntocorp/semgrep:latest
    echo ""
    echo "Minimal mode ready. Run scans using /sast-scan, /secret-scan, etc."
    ;;
  full)
    echo ""
    echo "Installing in full mode (persistent sidecar)..."
    echo "Building runner container..."
    docker compose -f "$ROOT_DIR/runner/docker-compose.yml" build runner
    echo ""
    echo "Starting runner..."
    docker compose -f "$ROOT_DIR/runner/docker-compose.yml" up -d runner
    echo ""
    echo "Pre-pulling tool images..."
    docker compose -f "$ROOT_DIR/runner/docker-compose.yml" pull
    echo ""
    echo "Full mode ready. Start tool profiles with:"
    echo "  docker compose -f runner/docker-compose.yml --profile sast up -d"
    echo "  docker compose -f runner/docker-compose.yml --profile all up -d"
    ;;
  *)
    echo "Unknown mode: $MODE"
    echo "Usage: $0 --mode [minimal|full]"
    exit 1
    ;;
esac

echo ""
echo "Installation complete."
