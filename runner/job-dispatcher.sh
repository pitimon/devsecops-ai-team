#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Job Dispatcher
# Routes scan jobs to appropriate tool containers
#
# Usage: job-dispatcher.sh --tool <tool> --target <path> [--rules <rules>] [--format <format>] [--image <image>]
#        ZAP options: [--mode baseline|full|api] [--auth-token <token>] [--api-spec <path>]
#
# Tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft

TOOL=""
TARGET=""
RULES=""
FORMAT="json"
IMAGE=""
ZAP_MODE="baseline"
AUTH_TOKEN=""
API_SPEC=""
JOB_ID="job-$(date +%Y%m%d-%H%M%S)-$$"
RESULTS_DIR="/results/${JOB_ID}"
RUNNER_MODE="${RUNNER_MODE:-minimal}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 --tool <tool> --target <path> [--rules <rules>] [--format <format>] [--image <image>]"
  echo "       ZAP: [--mode baseline|full|api] [--auth-token <token>] [--api-spec <path>]"
  echo ""
  echo "Tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft"
  echo "Formats: json (default), sarif, text"
  echo "ZAP modes: baseline (default, 120s), full (1800s), api (600s)"
  exit 1
}

while [[ $# -gt 0 ]]; do
  case $1 in
    --tool) TOOL="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --rules) RULES="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    --image) IMAGE="$2"; shift 2 ;;
    --mode) ZAP_MODE="$2"; shift 2 ;;
    --auth-token) AUTH_TOKEN="$2"; shift 2 ;;
    --api-spec) API_SPEC="$2"; shift 2 ;;
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

LOG="${RESULTS_DIR}/dispatcher.log"

run_semgrep() {
  local RULE_ARG="${RULES:-p/security-audit}"
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-semgrep semgrep \
      --config "$RULE_ARG" \
      --json --output "/results/${JOB_ID}/semgrep-results.json" \
      "$TARGET" 2>>"$LOG"
  else
    docker run --rm \
      -v "$(pwd):/workspace:ro" -v "${RESULTS_DIR}:/results" \
      returntocorp/semgrep:latest \
      semgrep --config "$RULE_ARG" --json --output "/results/semgrep-results.json" \
      /workspace 2>>"$LOG"
  fi
}

run_gitleaks() {
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-gitleaks gitleaks detect \
      --source "$TARGET" \
      --report-path "/results/${JOB_ID}/gitleaks-results.json" \
      --report-format json --no-banner 2>>"$LOG"
  else
    docker run --rm \
      -v "$(pwd):/workspace:ro" -v "${RESULTS_DIR}:/results" \
      zricethezav/gitleaks:latest detect \
      --source /workspace --report-path /results/gitleaks-results.json \
      --report-format json --no-banner 2>>"$LOG"
  fi
}

run_grype() {
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-grype grype \
      "dir:${TARGET}" \
      -o json --file "/results/${JOB_ID}/grype-results.json" 2>>"$LOG"
  else
    docker run --rm \
      -v "$(pwd):/workspace:ro" -v "${RESULTS_DIR}:/results" \
      -v "${HOME}/.cache/grype:/cache" \
      anchore/grype:latest \
      dir:/workspace -o json --file /results/grype-results.json 2>>"$LOG"
  fi
}

run_trivy() {
  local TRIVY_TARGET="${IMAGE:-$TARGET}"
  local TRIVY_CMD="fs"
  [ -n "$IMAGE" ] && TRIVY_CMD="image"
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-trivy trivy "$TRIVY_CMD" \
      --format json --output "/results/${JOB_ID}/trivy-results.json" \
      "$TRIVY_TARGET" 2>>"$LOG"
  else
    docker run --rm \
      -v "$(pwd):/workspace:ro" -v "${RESULTS_DIR}:/results" \
      -v /var/run/docker.sock:/var/run/docker.sock:ro \
      -v "${HOME}/.cache/trivy:/root/.cache/" \
      aquasec/trivy:latest "$TRIVY_CMD" \
      --format json --output /results/trivy-results.json \
      "$TRIVY_TARGET" 2>>"$LOG"
  fi
}

run_checkov() {
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-checkov checkov \
      -d "$TARGET" --output json \
      --output-file-path "/results/${JOB_ID}/" 2>>"$LOG"
  else
    docker run --rm \
      -v "$(pwd):/workspace:ro" -v "${RESULTS_DIR}:/results" \
      bridgecrew/checkov:latest \
      -d /workspace --output json \
      --output-file-path /results/ 2>>"$LOG"
  fi
}

run_zap() {
  # Determine ZAP scan script and timeout based on --mode
  local ZAP_SCRIPT="zap-baseline.py"
  local ZAP_TIMEOUT=120
  local ZAP_EXTRA_ARGS=""

  case "$ZAP_MODE" in
    baseline)
      ZAP_SCRIPT="zap-baseline.py"
      ZAP_TIMEOUT=120
      ;;
    full)
      ZAP_SCRIPT="zap-full-scan.py"
      ZAP_TIMEOUT=1800
      ZAP_EXTRA_ARGS="-a -j"
      ;;
    api)
      ZAP_SCRIPT="zap-api-scan.py"
      ZAP_TIMEOUT=600
      if [ -n "$API_SPEC" ]; then
        ZAP_EXTRA_ARGS="-f openapi"
        TARGET="$API_SPEC"
      fi
      ;;
    *)
      echo "[dispatcher] ERROR: Unknown ZAP mode: $ZAP_MODE (use baseline|full|api)"
      exit 1
      ;;
  esac

  # Add auth token if provided
  if [ -n "$AUTH_TOKEN" ]; then
    ZAP_EXTRA_ARGS="$ZAP_EXTRA_ARGS -z \"-config replacer.full_list(0).matchtype=REQ_HEADER -config replacer.full_list(0).matchstr=Authorization -config replacer.full_list(0).replacement='Bearer ${AUTH_TOKEN}'\""
  fi

  echo "[dispatcher] ZAP mode: $ZAP_MODE (script: $ZAP_SCRIPT, timeout: ${ZAP_TIMEOUT}s)" >>"$LOG"

  if [ "$RUNNER_MODE" = "full" ]; then
    timeout "$ZAP_TIMEOUT" docker exec devsecops-zap "$ZAP_SCRIPT" \
      -t "$TARGET" \
      -J "/results/${JOB_ID}/zap-results.json" \
      -r "/results/${JOB_ID}/zap-report.html" \
      $ZAP_EXTRA_ARGS 2>>"$LOG"
  else
    timeout "$ZAP_TIMEOUT" docker run --rm \
      -v "${RESULTS_DIR}:/results" --network host \
      ghcr.io/zaproxy/zaproxy:stable "$ZAP_SCRIPT" \
      -t "$TARGET" -J /results/zap-results.json \
      $ZAP_EXTRA_ARGS 2>>"$LOG"
  fi
}

run_syft() {
  local SYFT_TARGET="${IMAGE:-dir:$TARGET}"
  local SYFT_FORMAT="${FORMAT:-cyclonedx-json}"
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-syft syft "$SYFT_TARGET" \
      -o "$SYFT_FORMAT" --file "/results/${JOB_ID}/sbom.json" 2>>"$LOG"
  else
    docker run --rm \
      -v "$(pwd):/workspace:ro" -v "${RESULTS_DIR}:/results" \
      anchore/syft:latest "dir:/workspace" \
      -o "$SYFT_FORMAT" --file /results/sbom.json 2>>"$LOG"
  fi
}

run_tool() {
  case "$TOOL" in
    semgrep)  run_semgrep ;;
    gitleaks) run_gitleaks ;;
    grype)    run_grype ;;
    trivy)    run_trivy ;;
    checkov)  run_checkov ;;
    zap)      run_zap ;;
    syft)     run_syft ;;
    *)
      echo "[dispatcher] ERROR: Unknown tool: $TOOL"
      exit 1
      ;;
  esac
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
