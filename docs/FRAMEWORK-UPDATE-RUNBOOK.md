# Framework Update Runbook

Step-by-step procedure for updating framework versions in the DevSecOps AI Team plugin.

## When to Update

- Quarterly review identifies stale framework (via `framework-review.yml`)
- New major version released by framework maintainer
- Security advisory requires immediate update

## Update Procedure

### Step 1: Update frameworks.json

```bash
# Edit frameworks.json — update these fields:
# - version: new version string
# - released: release date (YYYY-MM)
# - last_checked: today's date (YYYY-MM-DD)
# - notes: any relevant notes about the update
```

### Step 2: Find All References

```bash
# Use grep_patterns from the framework entry
PATTERNS=$(python3 -c "
import json
fw = [f for f in json.load(open('frameworks.json')) if f['id'] == 'TARGET_ID'][0]
print(' '.join(fw['grep_patterns']))
")

# Search all files
for p in $PATTERNS; do
  grep -rn "$p" --include='*.md' --include='*.json' --include='*.sh' --include='*.yml'
done
```

### Step 3: Update References

Update version strings in all files listed in `used_in` field of the framework entry.

### Step 4: Verify

```bash
# Run framework consistency check
bash tests/check-framework-updates.sh

# Run plugin validation
bash tests/validate-plugin.sh
```

### Step 5: Commit

```bash
git add -A
git commit -m "chore: update <framework-name> to <new-version>"
```

## Quarterly Review Process

1. GitHub Actions `framework-review.yml` runs on 1st Monday of Jan/Apr/Jul/Oct
2. Creates GitHub Issue with checklist of frameworks to review
3. Team reviews each framework, updates as needed
4. Close issue when all frameworks are current

## Ad-hoc Check

```bash
bash tests/check-framework-updates.sh        # show stale only
bash tests/check-framework-updates.sh --all  # show all frameworks
```
