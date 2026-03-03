#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Job Dispatcher
# Routes scan jobs to appropriate tool containers
#
# Usage: job-dispatcher.sh --tool <tool> --target <path> [--rules <rules>] [--format <format>] [--image <image>]
#        ZAP options: [--mode baseline|full|api] [--auth-token <token>] [--api-spec <path>]
#        Nuclei options: env NUCLEI_MODE=cve|full|custom [CUSTOM_TEMPLATES=<path>]
#
# Tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft, nuclei

TOOL=""
TARGET=""
RULES=""
FORMAT="json"
IMAGE=""
ZAP_MODE="baseline"
NUCLEI_MODE="${NUCLEI_MODE:-cve}"
CUSTOM_TEMPLATES="${CUSTOM_TEMPLATES:-}"
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
  echo "Tools: semgrep, gitleaks, grype, trivy, checkov, zap, syft, nuclei"
  echo "Formats: json (default), sarif, text"
  echo "ZAP modes: baseline (default, 120s), full (1800s), api (600s)"
  echo "Nuclei modes: cve (default, 120s), full (600s), custom (300s)"
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
  # Load A09 custom rules if available alongside primary rules
  local A09_RULES="${SCRIPT_DIR}/../rules/a09-logging-rules.yml"
  local A09_ARG=""
  if [ -f "$A09_RULES" ]; then
    A09_ARG="--config /rules/a09-logging-rules.yml"
    echo "[dispatcher] A09 custom rules detected: $A09_RULES" >>"$LOG"
  fi
  # Load A01 custom rules if available
  local A01_RULES="${SCRIPT_DIR}/../rules/a01-access-control-rules.yml"
  local A01_ARG=""
  if [ -f "$A01_RULES" ]; then
    A01_ARG="--config /rules/a01-access-control-rules.yml"
    echo "[dispatcher] A01 custom rules detected: $A01_RULES" >>"$LOG"
  fi
  # Load A03 custom rules if available
  local A03_RULES="${SCRIPT_DIR}/../rules/a03-injection-rules.yml"
  local A03_ARG=""
  if [ -f "$A03_RULES" ]; then
    A03_ARG="--config /rules/a03-injection-rules.yml"
    echo "[dispatcher] A03 custom rules detected: $A03_RULES" >>"$LOG"
  fi
  # Load A10 custom rules if available
  local A10_RULES="${SCRIPT_DIR}/../rules/a10-ssrf-rules.yml"
  local A10_ARG=""
  if [ -f "$A10_RULES" ]; then
    A10_ARG="--config /rules/a10-ssrf-rules.yml"
    echo "[dispatcher] A10 custom rules detected: $A10_RULES" >>"$LOG"
  fi
  if [ "$RUNNER_MODE" = "full" ]; then
    docker exec devsecops-semgrep semgrep \
      --config "$RULE_ARG" $A09_ARG $A01_ARG $A03_ARG $A10_ARG \
      --json --output "/results/${JOB_ID}/semgrep-results.json" \
      "$TARGET" 2>>"$LOG"
  else
    local VOLUME_ARGS="-v $(pwd):/workspace:ro -v ${RESULTS_DIR}:/results"
    if [ -n "$A09_ARG" ] || [ -n "$A01_ARG" ] || [ -n "$A03_ARG" ] || [ -n "$A10_ARG" ]; then
      VOLUME_ARGS="$VOLUME_ARGS -v $(cd "$SCRIPT_DIR/.." && pwd)/rules:/rules:ro"
    fi
    docker run --rm \
      $VOLUME_ARGS \
      returntocorp/semgrep:latest \
      semgrep --config "$RULE_ARG" $A09_ARG $A01_ARG $A03_ARG $A10_ARG --json --output "/results/semgrep-results.json" \
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

# ─── Nuclei DAST ───
run_nuclei() {
  local NUCLEI_TEMPLATES="cves"
  local NUCLEI_TIMEOUT=120
  local NUCLEI_EXTRA_ARGS=""

  case "$NUCLEI_MODE" in
    cve)
      NUCLEI_TEMPLATES="cves"
      NUCLEI_TIMEOUT=120
      ;;
    full)
      NUCLEI_TEMPLATES=""
      NUCLEI_TIMEOUT=600
      ;;
    custom)
      NUCLEI_TEMPLATES=""
      NUCLEI_TIMEOUT=300
      if [ -n "$CUSTOM_TEMPLATES" ]; then
        NUCLEI_EXTRA_ARGS="-t $CUSTOM_TEMPLATES"
      fi
      ;;
    *)
      echo "[dispatcher] ERROR: Unknown Nuclei mode: $NUCLEI_MODE (use cve|full|custom)"
      exit 1
      ;;
  esac

  # Add auth header if provided
  if [ -n "$AUTH_TOKEN" ]; then
    NUCLEI_EXTRA_ARGS="$NUCLEI_EXTRA_ARGS -H \"Authorization: Bearer ${AUTH_TOKEN}\""
  fi

  echo "[dispatcher] Nuclei mode: $NUCLEI_MODE, templates: ${NUCLEI_TEMPLATES:-all}..." >>"$LOG"

  local NUCLEI_ARGS="-u $TARGET -jsonl -o /results/${JOB_ID}/nuclei-results.jsonl -silent"
  [ -n "$NUCLEI_TEMPLATES" ] && NUCLEI_ARGS="$NUCLEI_ARGS -tags $NUCLEI_TEMPLATES"
  [ -n "$NUCLEI_EXTRA_ARGS" ] && NUCLEI_ARGS="$NUCLEI_ARGS $NUCLEI_EXTRA_ARGS"

  if [ "$RUNNER_MODE" = "full" ]; then
    timeout "$NUCLEI_TIMEOUT" docker exec devsecops-nuclei \
      nuclei $NUCLEI_ARGS 2>>"$LOG"
  else
    timeout "$NUCLEI_TIMEOUT" docker run --rm \
      -v "${RESULTS_DIR}:/results" --network host \
      projectdiscovery/nuclei:latest \
      nuclei $NUCLEI_ARGS 2>>"$LOG"
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
    nuclei)   run_nuclei ;;
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
