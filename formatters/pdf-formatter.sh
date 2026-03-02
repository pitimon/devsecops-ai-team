#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — PDF Formatter
# Converts normalized JSON scan results to PDF via markdown + pandoc
#
# Usage: pdf-formatter.sh --input <json> --output <pdf>
# Requires: pandoc (host or Docker pandoc/latex:latest)

INPUT=""
OUTPUT=""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

while [[ $# -gt 0 ]]; do
  case $1 in
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    *) echo "Usage: $0 --input <json> --output <pdf>"; exit 1 ;;
  esac
done

[ -z "$INPUT" ] || [ -z "$OUTPUT" ] && { echo "Usage: $0 --input <json> --output <pdf>"; exit 1; }
[ ! -f "$INPUT" ] && { echo "[pdf-formatter] ERROR: Input file not found: $INPUT"; exit 1; }

# Step 1: Generate markdown intermediate
MD_TEMP=$(mktemp /tmp/devsecops-pdf-XXXXXX.md)
trap "rm -f $MD_TEMP" EXIT

if [ -f "$SCRIPT_DIR/markdown-formatter.sh" ]; then
  bash "$SCRIPT_DIR/markdown-formatter.sh" --input "$INPUT" --output "$MD_TEMP"
else
  echo "[pdf-formatter] ERROR: markdown-formatter.sh not found"
  exit 1
fi

# Step 2: Convert markdown to PDF
if command -v pandoc &>/dev/null; then
  # Host pandoc available
  pandoc "$MD_TEMP" -o "$OUTPUT" \
    --pdf-engine=xelatex \
    -V geometry:margin=1in \
    -V fontsize=10pt \
    --metadata title="DevSecOps Security Scan Report" 2>/dev/null \
  || pandoc "$MD_TEMP" -o "$OUTPUT" 2>/dev/null \
  || { echo "[pdf-formatter] ERROR: pandoc PDF conversion failed"; exit 1; }
elif command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
  # Docker pandoc
  local_dir=$(dirname "$(realpath "$MD_TEMP")")
  local_name=$(basename "$MD_TEMP")
  out_dir=$(dirname "$(realpath "$OUTPUT")")
  out_name=$(basename "$OUTPUT")
  docker run --rm \
    -v "$local_dir:/data:ro" \
    -v "$out_dir:/output" \
    pandoc/latex:latest \
    "/data/$local_name" -o "/output/$out_name" \
    -V geometry:margin=1in 2>/dev/null \
  || { echo "[pdf-formatter] ERROR: Docker pandoc conversion failed"; exit 1; }
else
  echo "[pdf-formatter] ERROR: Neither pandoc nor Docker available"
  echo "[pdf-formatter] Install pandoc: https://pandoc.org/installing.html"
  echo "[pdf-formatter] Or install Docker for containerized conversion"
  exit 1
fi

echo "[pdf-formatter] PDF output: $OUTPUT"
