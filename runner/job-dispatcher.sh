#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Job Dispatcher
# Routes scan jobs to appropriate tool containers
#
# Usage: job-dispatcher.sh --tool <tool> --target <path> [--rules <rules>] [--format <format>] [--image <image>]
#
# Tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft

TOOL=""
TARGET=""
RULES=""
FORMAT="json"
IMAGE=""
JOB_ID="job-$(date +%Y%m%d-%H%M%S)-$$"
RESULTS_DIR="/results/${JOB_ID}"
RUNNER_MODE="${RUNNER_MODE:-minimal}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 --tool <tool> --target <path> [--rules <rules>] [--format <format>] [--image <image>]"
  echo ""
  echo "Tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft"
  echo "Formats: json (default), sarif, text"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --tool) TOOL="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --rules) RULES="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    *) usage ;;
  esac
done

[ -z "$TOOL" ] && usage
[ -z "$TARGET" ] && TARGET="/workspace"

mkdir -p "$RESULTS_DIR"

echo "[dispatcher] Job: $JOB_ID"
echo "[dispatcher] Tool: $TOOL"
echo "[dispatcher] Target: $TARGET"
echo "[dispatcher] Format: $FORMAT"

run_tool() {
  local EXIT_CODE=0

  case "$TOOL" in
    semgrep)
      local RULE_ARG="${RULES:-p/security-audit}"
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-semgrep semgrep \
          --config "$RULE_ARG" \
          --json --output "/results/${JOB_ID}/semgrep-results.json" \
          "$TARGET" 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "$(pwd):/workspace:ro" \
          -v "${RESULTS_DIR}:/results" \
          returntocorp/semgrep:latest \
          semgrep --config "$RULE_ARG" --json --output "/results/semgrep-results.json" \
          /workspace 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    gitleaks)
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-gitleaks gitleaks detect \
          --source "$TARGET" \
          --report-path "/results/${JOB_ID}/gitleaks-results.json" \
          --report-format json \
          --no-banner 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "$(pwd):/workspace:ro" \
          -v "${RESULTS_DIR}:/results" \
          zricethezav/gitleaks:latest detect \
          --source /workspace \
          --report-path /results/gitleaks-results.json \
          --report-format json \
          --no-banner 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    grype)
      local GRYPE_TARGET="${TARGET}"
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-grype grype \
          "dir:${GRYPE_TARGET}" \
          -o json --file "/results/${JOB_ID}/grype-results.json" 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "$(pwd):/workspace:ro" \
          -v "${RESULTS_DIR}:/results" \
          -v "${HOME}/.cache/grype:/cache" \
          anchore/grype:latest \
          dir:/workspace -o json --file /results/grype-results.json 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    trivy)
      local TRIVY_TARGET="${IMAGE:-$TARGET}"
      local TRIVY_CMD="fs"
      [ -n "$IMAGE" ] && TRIVY_CMD="image"
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-trivy trivy "$TRIVY_CMD" \
          --format json --output "/results/${JOB_ID}/trivy-results.json" \
          "$TRIVY_TARGET" 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "$(pwd):/workspace:ro" \
          -v "${RESULTS_DIR}:/results" \
          -v /var/run/docker.sock:/var/run/docker.sock:ro \
          -v "${HOME}/.cache/trivy:/root/.cache/" \
          aquasec/trivy:latest "$TRIVY_CMD" \
          --format json --output /results/trivy-results.json \
          "$TRIVY_TARGET" 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    checkov)
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-checkov checkov \
          -d "$TARGET" \
          --output json \
          --output-file-path "/results/${JOB_ID}/" 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "$(pwd):/workspace:ro" \
          -v "${RESULTS_DIR}:/results" \
          bridgecrew/checkov:latest \
          -d /workspace --output json \
          --output-file-path /results/ 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    zap)
      local ZAP_TARGET="${TARGET}"
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-zap zap-baseline.py \
          -t "$ZAP_TARGET" \
          -J "/results/${JOB_ID}/zap-results.json" \
          -r "/results/${JOB_ID}/zap-report.html" 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "${RESULTS_DIR}:/results" \
          --network host \
          ghcr.io/zaproxy/zaproxy:stable zap-baseline.py \
          -t "$ZAP_TARGET" \
          -J /results/zap-results.json 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    syft)
      local SYFT_TARGET="${IMAGE:-dir:$TARGET}"
      local SYFT_FORMAT="${FORMAT:-cyclonedx-json}"
      if [ "$RUNNER_MODE" = "full" ]; then
        docker exec devsecops-syft syft "$SYFT_TARGET" \
          -o "$SYFT_FORMAT" --file "/results/${JOB_ID}/sbom.json" 2>/dev/null || EXIT_CODE=$?
      else
        docker run --rm \
          -v "$(pwd):/workspace:ro" \
          -v "${RESULTS_DIR}:/results" \
          anchore/syft:latest "dir:/workspace" \
          -o "$SYFT_FORMAT" --file /results/sbom.json 2>/dev/null || EXIT_CODE=$?
      fi
      ;;

    *)
      echo "[dispatcher] ERROR: Unknown tool: $TOOL"
      exit 1
      ;;
  esac

  return $EXIT_CODE
}

# Record start time
START_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Run the tool
TOOL_EXIT=0
run_tool || TOOL_EXIT=$?

# Record end time
END_TIME=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Write job metadata
cat > "$RESULTS_DIR/job-metadata.json" << EOF
{
  "job_id": "$JOB_ID",
  "tool": "$TOOL",
  "target": "$TARGET",
  "rules": "$RULES",
  "format": "$FORMAT",
  "started_at": "$START_TIME",
  "finished_at": "$END_TIME",
  "exit_code": $TOOL_EXIT,
  "runner_mode": "$RUNNER_MODE"
}
EOF

echo "[dispatcher] Job complete: $JOB_ID (exit code: $TOOL_EXIT)"
echo "[dispatcher] Results: $RESULTS_DIR"

exit $TOOL_EXIT
