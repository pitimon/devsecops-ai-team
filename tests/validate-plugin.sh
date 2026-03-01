#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Plugin Structure Validation
# 80+ structural integrity checks
# Usage: bash tests/validate-plugin.sh [--skip-install-check]

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PASS=0
FAIL=0
WARN=0
SKIP_INSTALL=${1:-""}

pass() { PASS=$((PASS + 1)); echo "  [PASS] $1"; }
fail() { FAIL=$((FAIL + 1)); echo "  [FAIL] $1"; }
warn() { WARN=$((WARN + 1)); echo "  [WARN] $1"; }

echo "============================================"
echo "DevSecOps AI Team — Plugin Validation"
echo "============================================"
echo ""

# ─── Section 1: Plugin Metadata ───
echo "--- Section 1: Plugin Metadata ---"

[ -f "$ROOT_DIR/.claude-plugin/plugin.json" ] && pass "plugin.json exists" || fail "plugin.json missing"
[ -f "$ROOT_DIR/.claude-plugin/marketplace.json" ] && pass "marketplace.json exists" || fail "marketplace.json missing"

if [ -f "$ROOT_DIR/.claude-plugin/plugin.json" ]; then
  grep -q '"name": "devsecops-ai-team"' "$ROOT_DIR/.claude-plugin/plugin.json" && pass "plugin name correct" || fail "plugin name mismatch"
  grep -q '"version"' "$ROOT_DIR/.claude-plugin/plugin.json" && pass "plugin has version" || fail "plugin missing version"
  grep -q '"skills": "./skills/"' "$ROOT_DIR/.claude-plugin/plugin.json" && pass "skills path correct" || fail "skills path wrong"
  grep -q '"author"' "$ROOT_DIR/.claude-plugin/plugin.json" && pass "plugin has author" || fail "plugin missing author"
  grep -q '"repository"' "$ROOT_DIR/.claude-plugin/plugin.json" && pass "plugin has repository" || fail "plugin missing repository"
fi

if [ -f "$ROOT_DIR/.claude-plugin/marketplace.json" ]; then
  grep -q '"pitimon-devsecops"' "$ROOT_DIR/.claude-plugin/marketplace.json" && pass "marketplace name correct" || fail "marketplace name mismatch"
  grep -q 'devsecops-ai-team' "$ROOT_DIR/.claude-plugin/marketplace.json" && pass "marketplace references plugin" || fail "marketplace missing plugin ref"
fi

# ─── Section 2: Required Files ───
echo ""
echo "--- Section 2: Required Files ---"

for f in README.md CLAUDE.md CHANGELOG.md LICENSE SECURITY.md frameworks.json .gitignore; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 3: Skills ───
echo ""
echo "--- Section 3: Skills (12 expected) ---"

EXPECTED_SKILLS="devsecops-setup sast-scan dast-scan sca-scan container-scan iac-scan secret-scan sbom-generate full-pipeline compliance-report incident-response security-gate"
SKILL_COUNT=0
for skill in $EXPECTED_SKILLS; do
  if [ -f "$ROOT_DIR/skills/$skill/SKILL.md" ]; then
    pass "skill $skill exists"
    ((SKILL_COUNT++))
    # Check YAML frontmatter
    head -1 "$ROOT_DIR/skills/$skill/SKILL.md" | grep -q "^---" && pass "  $skill has frontmatter" || fail "  $skill missing frontmatter"
    grep -q "^name:" "$ROOT_DIR/skills/$skill/SKILL.md" && pass "  $skill has name field" || fail "  $skill missing name"
    grep -q "^user-invocable:" "$ROOT_DIR/skills/$skill/SKILL.md" && pass "  $skill has user-invocable" || fail "  $skill missing user-invocable"
    grep -q "^allowed-tools:" "$ROOT_DIR/skills/$skill/SKILL.md" && pass "  $skill has allowed-tools" || fail "  $skill missing allowed-tools"
  else
    fail "skill $skill missing"
  fi
done
[ "$SKILL_COUNT" -eq 12 ] && pass "all 12 skills present" || fail "expected 12 skills, found $SKILL_COUNT"

# ─── Section 4: Agents ───
echo ""
echo "--- Section 4: Agents (18 expected) ---"

AGENT_COUNT=0
for group in orchestrators specialists experts core-team; do
  if [ -d "$ROOT_DIR/agents/$group" ]; then
    pass "agent group $group exists"
    for agent_file in "$ROOT_DIR/agents/$group"/*.md; do
      if [ -f "$agent_file" ]; then
        ((AGENT_COUNT++))
        BASENAME=$(basename "$agent_file")
        head -1 "$agent_file" | grep -q "^---" && pass "  $BASENAME has frontmatter" || fail "  $BASENAME missing frontmatter"
        grep -q "^model:" "$agent_file" && pass "  $BASENAME has model" || fail "  $BASENAME missing model"
        grep -q "^tools:" "$agent_file" && pass "  $BASENAME has tools" || fail "  $BASENAME missing tools"
      fi
    done
  else
    fail "agent group $group missing"
  fi
done
[ "$AGENT_COUNT" -eq 18 ] && pass "all 18 agents present" || fail "expected 18 agents, found $AGENT_COUNT"

# ─── Section 5: Hooks ───
echo ""
echo "--- Section 5: Hooks ---"

[ -f "$ROOT_DIR/hooks/hooks.json" ] && pass "hooks.json exists" || fail "hooks.json missing"
[ -f "$ROOT_DIR/hooks/session-start.sh" ] && pass "session-start.sh exists" || fail "session-start.sh missing"
[ -f "$ROOT_DIR/hooks/scan-on-write.sh" ] && pass "scan-on-write.sh exists" || fail "scan-on-write.sh missing"
[ -f "$ROOT_DIR/hooks/pre-commit-gate.sh" ] && pass "pre-commit-gate.sh exists" || fail "pre-commit-gate.sh missing"

if [ -f "$ROOT_DIR/hooks/hooks.json" ]; then
  grep -q "SessionStart" "$ROOT_DIR/hooks/hooks.json" && pass "SessionStart hook registered" || fail "SessionStart hook missing"
  grep -q "PreToolUse" "$ROOT_DIR/hooks/hooks.json" && pass "PreToolUse hook registered" || fail "PreToolUse hook missing"
  grep -q "session-start.sh" "$ROOT_DIR/hooks/hooks.json" && pass "session-start.sh referenced" || fail "session-start.sh not referenced"
fi

for f in "$ROOT_DIR/hooks/"*.sh; do
  [ -x "$f" ] && pass "$(basename "$f") is executable" || warn "$(basename "$f") not executable"
done

# ─── Section 6: Runner ───
echo ""
echo "--- Section 6: Runner ---"

for f in Dockerfile docker-compose.yml entrypoint.sh job-dispatcher.sh result-collector.sh healthcheck.sh; do
  [ -f "$ROOT_DIR/runner/$f" ] && pass "runner/$f exists" || fail "runner/$f missing"
done

if [ -f "$ROOT_DIR/runner/Dockerfile" ]; then
  grep -q "tini" "$ROOT_DIR/runner/Dockerfile" && pass "Dockerfile uses tini" || warn "Dockerfile missing tini"
  grep -q "USER" "$ROOT_DIR/runner/Dockerfile" && pass "Dockerfile has non-root user" || warn "Dockerfile missing non-root user"
fi

if [ -f "$ROOT_DIR/runner/docker-compose.yml" ]; then
  grep -q "semgrep" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has semgrep" || fail "compose missing semgrep"
  grep -q "grype" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has grype" || fail "compose missing grype"
  grep -q "trivy" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has trivy" || fail "compose missing trivy"
  grep -q "checkov" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has checkov" || fail "compose missing checkov"
  grep -q "gitleaks" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has gitleaks" || fail "compose missing gitleaks"
  grep -q "zap" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has zap" || fail "compose missing zap"
  grep -q "syft" "$ROOT_DIR/runner/docker-compose.yml" && pass "compose has syft" || fail "compose missing syft"
fi

# ─── Section 7: Formatters ───
echo ""
echo "--- Section 7: Formatters ---"

for f in sarif-formatter.sh markdown-formatter.sh html-formatter.sh json-normalizer.sh; do
  [ -f "$ROOT_DIR/formatters/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 8: Mappings ───
echo ""
echo "--- Section 8: Compliance Mappings ---"

for f in cwe-to-owasp.json cwe-to-nist.json cwe-to-mitre.json severity-policy.json; do
  [ -f "$ROOT_DIR/mappings/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 9: References ───
echo ""
echo "--- Section 9: Reference Files ---"

EXPECTED_REFS="sast-patterns.md dast-methodology.md sca-supply-chain.md container-hardening.md iac-security-patterns.md secret-management.md compliance-frameworks.md threat-modeling.md incident-response.md remediation-patterns.md"
REF_COUNT=0
for ref in $EXPECTED_REFS; do
  if [ -f "$ROOT_DIR/skills/references/$ref" ]; then
    pass "reference $ref exists"
    ((REF_COUNT++))
  else
    fail "reference $ref missing"
  fi
done
[ "$REF_COUNT" -eq 10 ] && pass "all 10 reference files present" || fail "expected 10 references, found $REF_COUNT"

# ─── Section 10: Templates & Examples ───
echo ""
echo "--- Section 10: Templates & Examples ---"

for f in templates/compliance-report.html.template templates/pr-comment.md.template templates/incident-playbook.md.template templates/security-gate.md.template; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

[ -f "$ROOT_DIR/examples/DOMAIN.md.example" ] && pass "DOMAIN.md.example exists" || fail "DOMAIN.md.example missing"
[ -d "$ROOT_DIR/examples/rules" ] && pass "examples/rules/ exists" || fail "examples/rules/ missing"
[ -d "$ROOT_DIR/examples/policies" ] && pass "examples/policies/ exists" || fail "examples/policies/ missing"

# ─── Section 11: Scripts ───
echo ""
echo "--- Section 11: Scripts ---"

for f in scripts/install-runner.sh scripts/install-rules.sh scripts/check-prerequisites.sh; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 12: Tests ───
echo ""
echo "--- Section 12: Tests ---"

for f in tests/validate-plugin.sh tests/test-runner.sh tests/test-formatters.sh tests/check-framework-updates.sh tests/smoke-test-prompts.md; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

[ -d "$ROOT_DIR/tests/fixtures" ] && pass "test fixtures directory exists" || fail "test fixtures directory missing"

# ─── Section 13: Framework Consistency ───
echo ""
echo "--- Section 13: Framework Consistency ---"

if [ -f "$ROOT_DIR/frameworks.json" ]; then
  python3 -c "import json; json.load(open('$ROOT_DIR/frameworks.json'))" 2>/dev/null && pass "frameworks.json is valid JSON" || fail "frameworks.json invalid JSON"
  FW_COUNT=$(python3 -c "import json; print(len(json.load(open('$ROOT_DIR/frameworks.json'))))" 2>/dev/null || echo 0)
  [ "$FW_COUNT" -gt 0 ] && pass "frameworks.json has $FW_COUNT entries" || fail "frameworks.json empty"
fi

# ─── Section 14: Docs ───
echo ""
echo "--- Section 14: Documentation ---"

for f in docs/INSTALL.md docs/TROUBLESHOOTING.md docs/AGENT-CATALOG.md docs/FRAMEWORK-UPDATE-RUNBOOK.md docs/MANDAY-ESTIMATION.md; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 15: CI/CD ───
echo ""
echo "--- Section 15: CI/CD Workflows ---"

for f in .github/workflows/validate.yml .github/workflows/security-scan.yml .github/workflows/framework-review.yml .github/workflows/release.yml; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 16: MCP Server ───
echo ""
echo "--- Section 16: MCP Server ---"

[ -f "$ROOT_DIR/.mcp.json" ] && pass ".mcp.json exists" || fail ".mcp.json missing"
[ -f "$ROOT_DIR/mcp/server.mjs" ] && pass "mcp/server.mjs exists" || fail "mcp/server.mjs missing"
[ -f "$ROOT_DIR/mcp/package.json" ] && pass "mcp/package.json exists" || fail "mcp/package.json missing"

if [ -f "$ROOT_DIR/.mcp.json" ]; then
  python3 -c "import json; json.load(open('$ROOT_DIR/.mcp.json'))" 2>/dev/null && pass ".mcp.json is valid JSON" || fail ".mcp.json invalid"
  python3 -c "import json; d=json.load(open('$ROOT_DIR/.mcp.json')); assert 'devsecops' in d.get('mcpServers',{})" 2>/dev/null && pass ".mcp.json has devsecops server" || fail ".mcp.json missing devsecops"
fi

if [ -f "$ROOT_DIR/mcp/package.json" ]; then
  python3 -c "import json; d=json.load(open('$ROOT_DIR/mcp/package.json')); assert d['type']=='module'" 2>/dev/null && pass "package.json is ESM module" || fail "package.json not ESM"
  python3 -c "import json; d=json.load(open('$ROOT_DIR/mcp/package.json')); assert '@modelcontextprotocol/sdk' in d.get('dependencies',{})" 2>/dev/null && pass "MCP SDK dependency declared" || fail "MCP SDK missing"
fi

if [ -f "$ROOT_DIR/mcp/server.mjs" ]; then
  TOOL_COUNT=$(python3 -c "import re; c=open('$ROOT_DIR/mcp/server.mjs').read(); print(len(set(re.findall(r'name:\s*\"(devsecops_\w+)\"', c))))" 2>/dev/null || echo 0)
  [ "$TOOL_COUNT" -eq 5 ] && pass "MCP server defines 5 tools" || fail "MCP server has $TOOL_COUNT tools (expected 5)"
  grep -q "StdioServerTransport" "$ROOT_DIR/mcp/server.mjs" && pass "Uses stdio transport" || fail "Missing stdio transport"
fi

# ─── Section 17: Normalizer Tests ───
echo ""
echo "--- Section 17: Normalizer Tests ---"

[ -f "$ROOT_DIR/tests/test-normalizer.sh" ] && pass "test-normalizer.sh exists" || fail "test-normalizer.sh missing"
[ -f "$ROOT_DIR/tests/test-mcp-server.sh" ] && pass "test-mcp-server.sh exists" || fail "test-mcp-server.sh missing"
[ -f "$ROOT_DIR/formatters/dedup-findings.sh" ] && pass "dedup-findings.sh exists" || fail "dedup-findings.sh missing"
[ -f "$ROOT_DIR/tests/fixtures/sample-checkov-multi.json" ] && pass "sample-checkov-multi.json fixture exists" || fail "sample-checkov-multi.json missing"
[ -f "$ROOT_DIR/tests/fixtures/sample-trivy-misconfig.json" ] && pass "sample-trivy-misconfig.json fixture exists" || fail "sample-trivy-misconfig.json missing"

if [ -f "$ROOT_DIR/tests/fixtures/sample-checkov-multi.json" ]; then
  python3 -c "import json; d=json.load(open('$ROOT_DIR/tests/fixtures/sample-checkov-multi.json')); assert isinstance(d, list) and len(d)>=2" 2>/dev/null && pass "checkov-multi fixture has 2+ check types" || fail "checkov-multi fixture invalid"
fi

if [ -f "$ROOT_DIR/tests/fixtures/sample-trivy-misconfig.json" ]; then
  python3 -c "
import json
d=json.load(open('$ROOT_DIR/tests/fixtures/sample-trivy-misconfig.json'))
has_vulns = any(r.get('Vulnerabilities') for r in d.get('Results',[]))
has_misconf = any(r.get('Misconfigurations') for r in d.get('Results',[]))
assert has_vulns and has_misconf
" 2>/dev/null && pass "trivy-misconfig fixture has both Vulnerabilities and Misconfigurations" || fail "trivy-misconfig fixture incomplete"
fi

# ─── Summary ───
echo ""
echo "============================================"
TOTAL=$((PASS + FAIL + WARN))
echo "Results: $PASS passed / $FAIL failed / $WARN warnings (total $TOTAL checks)"
echo "============================================"

if [ "$FAIL" -gt 0 ]; then
  echo "STATUS: FAILED"
  exit 1
else
  echo "STATUS: PASSED"
  exit 0
fi
