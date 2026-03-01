#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Framework Staleness Checker
# Checks frameworks.json for entries that haven't been verified recently
# Usage: check-framework-updates.sh [--json] [--max-age-days N]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
FRAMEWORKS_FILE="$ROOT_DIR/frameworks.json"

JSON_OUTPUT=false
MAX_AGE_DAYS=90
PASS=0
STALE=0
WARN=0

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) JSON_OUTPUT=true; shift ;;
    --max-age-days) MAX_AGE_DAYS="$2"; shift 2 ;;
    *) shift ;;
  esac
done

if [ ! -f "$FRAMEWORKS_FILE" ]; then
  echo "ERROR: frameworks.json not found at $FRAMEWORKS_FILE"
  exit 1
fi

echo "DevSecOps AI Team — Framework Staleness Check"
echo "=============================================="
echo "Max age: ${MAX_AGE_DAYS} days"
echo ""

# Process each framework
export _FW_MAX_AGE="$MAX_AGE_DAYS"
export _FW_JSON_OUTPUT="$JSON_OUTPUT"
export _FW_FILE="$FRAMEWORKS_FILE"

RESULTS=$(python3 << 'PYEOF'
import json
import os
import sys
from datetime import datetime, timezone

max_age_days = int(os.environ.get("_FW_MAX_AGE", "90"))
json_output = os.environ.get("_FW_JSON_OUTPUT", "false") == "true"
fw_file = os.environ.get("_FW_FILE", "frameworks.json")

with open(fw_file) as f:
    frameworks = json.load(f)

now = datetime.now(timezone.utc)
results = []
pass_count = 0
stale_count = 0
warn_count = 0

for fw in frameworks:
    fw_id = fw.get("id", "unknown")
    name = fw.get("name", fw_id)
    version = fw.get("version", "unknown")
    last_checked = fw.get("last_checked", "")
    update_freq = fw.get("update_frequency", "unknown")

    if not last_checked:
        status = "STALE"
        age_days = 999
        stale_count += 1
    else:
        try:
            checked_date = datetime.strptime(last_checked, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            age_days = (now - checked_date).days
        except ValueError:
            age_days = 999

        # Adjust threshold based on update frequency
        threshold = max_age_days
        if update_freq == "rare":
            threshold = max_age_days * 2  # 180 days for rare updates
        elif update_freq == "annual":
            threshold = max_age_days * 4  # 360 days for annual
        elif update_freq == "quarterly":
            threshold = max_age_days      # 90 days for quarterly
        elif update_freq == "monthly":
            threshold = 45                # 45 days for monthly

        if age_days > threshold:
            status = "STALE"
            stale_count += 1
        elif age_days > threshold * 0.75:
            status = "WARN"
            warn_count += 1
        else:
            status = "OK"
            pass_count += 1

    result = {
        "id": fw_id,
        "name": name,
        "version": version,
        "last_checked": last_checked,
        "age_days": age_days,
        "update_frequency": update_freq,
        "status": status
    }
    results.append(result)

    if not json_output:
        status_tag = f"[{status}]"
        if status == "OK":
            print(f"  {status_tag:8s} {name} v{version} (checked {age_days}d ago, freq={update_freq})")
        elif status == "WARN":
            print(f"  {status_tag:8s} {name} v{version} (checked {age_days}d ago — approaching threshold)")
        else:
            print(f"  {status_tag:8s} {name} v{version} (checked {age_days}d ago — NEEDS REVIEW)")

if json_output:
    output = {
        "check_date": now.isoformat(),
        "max_age_days": max_age_days,
        "summary": {
            "total": len(results),
            "ok": pass_count,
            "warn": warn_count,
            "stale": stale_count
        },
        "frameworks": results
    }
    print(json.dumps(output, indent=2))
else:
    print("")
    print(f"Results: {pass_count} OK / {warn_count} warnings / {stale_count} stale")

    if stale_count > 0:
        print("")
        print("Action required:")
        print("  1. Check upstream sources for new versions")
        print("  2. Follow docs/FRAMEWORK-UPDATE-RUNBOOK.md")
        print("  3. Update frameworks.json with new last_checked date")

sys.exit(1 if stale_count > 0 else 0)
PYEOF
)

echo "$RESULTS"
