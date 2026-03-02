#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Result Collector
# Collects, normalizes, and formats scan results
#
# Usage: result-collector.sh --job-id <id> [--format sarif|json|markdown|html|pdf|csv]

JOB_ID=""
OUTPUT_FORMAT="json"
RESULTS_DIR=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FORMATTER_DIR="$(cd "$SCRIPT_DIR/../formatters" 2>/dev/null && pwd || echo "")"

while [[ $# -gt 0 ]]; do
  case $1 in
    --job-id) JOB_ID="$2"; shift 2 ;;
    --format) OUTPUT_FORMAT="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

[ -z "$JOB_ID" ] && { echo "Usage: $0 --job-id <id> [--format sarif|json|markdown|html|pdf|csv]"; exit 1; }

RESULTS_DIR="/results/${JOB_ID}"

if [ ! -d "$RESULTS_DIR" ]; then
  echo "[collector] ERROR: Results directory not found: $RESULTS_DIR"
  exit 1
fi

# Read job metadata
if [ -f "$RESULTS_DIR/job-metadata.json" ]; then
  TOOL=$(jq -r '.tool' "$RESULTS_DIR/job-metadata.json")
  echo "[collector] Processing results for: $TOOL (job: $JOB_ID)"
else
  echo "[collector] WARNING: No metadata found, attempting raw collection"
  TOOL="unknown"
fi

# Find result files
RESULT_FILES=$(find "$RESULTS_DIR" -name "*.json" ! -name "job-metadata.json" ! -name "normalized.json" 2>/dev/null)

if [ -z "$RESULT_FILES" ]; then
  echo "[collector] No result files found"
  exit 0
fi

# Normalize results to unified format
normalize() {
  local INPUT_FILE="$1"
  local NORMALIZED="$RESULTS_DIR/normalized.json"

  if [ -n "$FORMATTER_DIR" ] && [ -f "$FORMATTER_DIR/json-normalizer.sh" ]; then
    bash "$FORMATTER_DIR/json-normalizer.sh" --tool "$TOOL" --input "$INPUT_FILE" --output "$NORMALIZED"
  else
    # Fallback: copy raw results
    cp "$INPUT_FILE" "$NORMALIZED"
  fi

  echo "$NORMALIZED"
}

# Format output
format_output() {
  local NORMALIZED="$1"

  case "$OUTPUT_FORMAT" in
    sarif)
      if [ -n "$FORMATTER_DIR" ] && [ -f "$FORMATTER_DIR/sarif-formatter.sh" ]; then
        bash "$FORMATTER_DIR/sarif-formatter.sh" --input "$NORMALIZED" --output "$RESULTS_DIR/results.sarif"
        echo "[collector] SARIF output: $RESULTS_DIR/results.sarif"
      fi
      ;;
    markdown)
      if [ -n "$FORMATTER_DIR" ] && [ -f "$FORMATTER_DIR/markdown-formatter.sh" ]; then
        bash "$FORMATTER_DIR/markdown-formatter.sh" --input "$NORMALIZED" --output "$RESULTS_DIR/results.md"
        echo "[collector] Markdown output: $RESULTS_DIR/results.md"
      fi
      ;;
    html)
      if [ -n "$FORMATTER_DIR" ] && [ -f "$FORMATTER_DIR/html-formatter.sh" ]; then
        bash "$FORMATTER_DIR/html-formatter.sh" --input "$NORMALIZED" --output "$RESULTS_DIR/results.html"
        echo "[collector] HTML output: $RESULTS_DIR/results.html"
      fi
      ;;
    pdf)
      if [ -n "$FORMATTER_DIR" ] && [ -f "$FORMATTER_DIR/pdf-formatter.sh" ]; then
        bash "$FORMATTER_DIR/pdf-formatter.sh" --input "$NORMALIZED" --output "$RESULTS_DIR/results.pdf"
        echo "[collector] PDF output: $RESULTS_DIR/results.pdf"
      fi
      ;;
    csv)
      if [ -n "$FORMATTER_DIR" ] && [ -f "$FORMATTER_DIR/csv-formatter.sh" ]; then
        bash "$FORMATTER_DIR/csv-formatter.sh" --input "$NORMALIZED" --output "$RESULTS_DIR/results.csv"
        echo "[collector] CSV output: $RESULTS_DIR/results.csv"
      fi
      ;;
    json)
      echo "[collector] JSON output: $NORMALIZED"
      ;;
  esac
}

# Process each result file
for FILE in $RESULT_FILES; do
  echo "[collector] Normalizing: $(basename "$FILE")"
  NORMALIZED=$(normalize "$FILE")
  format_output "$NORMALIZED"
done

echo "[collector] Collection complete for job: $JOB_ID"
