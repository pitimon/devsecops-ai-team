#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Ensure esbuild is available
if ! command -v npx &>/dev/null; then
  echo "ERROR: npx required. Install Node.js 18+" >&2
  exit 1
fi

mkdir -p dist

echo "Building MCP server bundle..."
npx esbuild server.mjs --bundle --platform=node --target=node18 \
  --format=esm --outfile=dist/server.js \
  --external:node:child_process --external:node:fs --external:node:path \
  --external:node:url --external:node:crypto

echo "Bundle created: dist/server.js ($(wc -c < dist/server.js | tr -d ' ') bytes)"
