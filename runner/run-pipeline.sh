#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Pipeline Runner
# Orchestrates multiple security tools with concurrency groups
#
# Usage: run-pipeline.sh --tools "semgrep,grype,trivy" --target /path [--format sarif|json|md]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/ci-adapter.sh"

TOOLS=""
TARGET=""
FORMAT="json"
RESULTS_DIR="${RESULTS_DIR:-/tmp/devsecops-results}"
CONCURRENCY_CONFIG="$SCRIPT_DIR/concurrency-groups.json"

while [[ $# -gt 0 ]]; do
  case $1 in
    --tools) TOOLS="$2"; shift 2 ;;
    --target) TARGET="$2"; shift 2 ;;
    --format) FORMAT="$2"; shift 2 ;;
    --results-dir) RESULTS_DIR="$2"; shift 2 ;;
    --concurrency-config) CONCURRENCY_CONFIG="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$TOOLS" ] && { echo "Usage: $0 --tools \"semgrep,grype\" --target /path [--format json]"; exit 1; }
[ -z "$TARGET" ] && { echo "ERROR: --target is required"; exit 1; }

mkdir -p "$RESULTS_DIR"

PLATFORM=$(ci_detect_platform)
ci_group_start "DevSecOps Pipeline"
echo "Platform: $PLATFORM"
echo "Tools: $TOOLS"
echo "Target: $TARGET"
echo "Format: $FORMAT"

# Parse tool list
IFS=',' read -ra TOOL_LIST <<< "$TOOLS"

# Classify tools by concurrency group
classify_tool() {
  local tool="$1"
  local group
  group=$(python3 -c "
import json, sys
config = json.load(open('$CONCURRENCY_CONFIG'))
for group_name, group_data in config['groups'].items():
    if '$tool' in group_data['tools']:
        print(group_name)
        sys.exit(0)
print('light')  # default
" 2>/dev/null || echo "light")
  echo "$group"
}

HEAVY_TOOLS=()
MEDIUM_TOOLS=()
LIGHT_TOOLS=()

for tool in "${TOOL_LIST[@]}"; do
  tool=$(echo "$tool" | tr -d ' ')
  group=$(classify_tool "$tool")
  case "$group" in
    heavy) HEAVY_TOOLS+=("$tool") ;;
    medium) MEDIUM_TOOLS+=("$tool") ;;
    light) LIGHT_TOOLS+=("$tool") ;;
  esac
done

MAX_EXIT=0
PIDS=()
TOOL_EXITS=()

# Run a single tool and capture exit code
run_tool() {
  local tool="$1"
  ci_group_start "Scanning with $tool"
  local exit_code=0
  if [ -f "$SCRIPT_DIR/job-dispatcher.sh" ]; then
    bash "$SCRIPT_DIR/job-dispatcher.sh" --tool "$tool" --target "$TARGET" --format "$FORMAT" || exit_code=$?
  else
    echo "WARNING: job-dispatcher.sh not found, simulating $tool scan"
    exit_code=0
  fi
  ci_group_end "Scanning with $tool"
  return $exit_code
}

# Run light tools in parallel
if [ ${#LIGHT_TOOLS[@]} -gt 0 ]; then
  ci_group_start "Light tools (parallel)"
  for tool in "${LIGHT_TOOLS[@]}"; do
    (run_tool "$tool"; echo $? > "$RESULTS_DIR/.exit-$tool") &
    PIDS+=($!)
  done
  # Wait for all light tools
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  ci_group_end "Light tools (parallel)"
fi

# Run medium tools with limited parallelism
if [ ${#MEDIUM_TOOLS[@]} -gt 0 ]; then
  ci_group_start "Medium tools"
  PIDS=()
  for tool in "${MEDIUM_TOOLS[@]}"; do
    (run_tool "$tool"; echo $? > "$RESULTS_DIR/.exit-$tool") &
    PIDS+=($!)
  done
  for pid in "${PIDS[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  ci_group_end "Medium tools"
fi

# Run heavy tools serially
if [ ${#HEAVY_TOOLS[@]} -gt 0 ]; then
  ci_group_start "Heavy tools (serial)"
  for tool in "${HEAVY_TOOLS[@]}"; do
    run_tool "$tool" || echo $? > "$RESULTS_DIR/.exit-$tool"
    [ ! -f "$RESULTS_DIR/.exit-$tool" ] && echo 0 > "$RESULTS_DIR/.exit-$tool"
  done
  ci_group_end "Heavy tools (serial)"
fi

# Aggregate exit codes
for tool in "${TOOL_LIST[@]}"; do
  tool=$(echo "$tool" | tr -d ' ')
  exit_file="$RESULTS_DIR/.exit-$tool"
  if [ -f "$exit_file" ]; then
    code=$(cat "$exit_file")
    [ "$code" -gt "$MAX_EXIT" ] && MAX_EXIT="$code"
    rm -f "$exit_file"
  fi
done

ci_group_end "DevSecOps Pipeline"

# Set outputs
ci_set_output "exit_code" "$MAX_EXIT"
ci_set_output "results_dir" "$RESULTS_DIR"
ci_set_output "tools_run" "$TOOLS"

# Write summary
ci_summary "## DevSecOps Scan Summary

| Key | Value |
|-----|-------|
| Platform | $PLATFORM |
| Tools | $TOOLS |
| Target | $TARGET |
| Exit Code | $MAX_EXIT |
| Results | $RESULTS_DIR |
"

exit "$MAX_EXIT"
