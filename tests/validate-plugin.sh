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
EXPECTED_SKILLS="devsecops-setup sast-scan dast-scan sca-scan container-scan iac-scan secret-scan sbom-generate full-pipeline compliance-report incident-response security-gate auto-fix slsa-assess k8s-scan graphql-scan"
EXPECTED_SKILL_COUNT=$(echo $EXPECTED_SKILLS | wc -w | tr -d ' ')
echo "--- Section 3: Skills ($EXPECTED_SKILL_COUNT expected) ---"
SKILL_COUNT=0
for skill in $EXPECTED_SKILLS; do
  if [ -f "$ROOT_DIR/skills/$skill/SKILL.md" ]; then
    pass "skill $skill exists"
    SKILL_COUNT=$((SKILL_COUNT + 1))
    # Check YAML frontmatter
    head -1 "$ROOT_DIR/skills/$skill/SKILL.md" | grep -q "^---" && pass "  $skill has frontmatter" || fail "  $skill missing frontmatter"
    grep -q "^name:" "$ROOT_DIR/skills/$skill/SKILL.md" && pass "  $skill has name field" || fail "  $skill missing name"
    grep -q "^user-invocable:" "$ROOT_DIR/skills/$skill/SKILL.md" && pass "  $skill has user-invocable" || fail "  $skill missing user-invocable"
    grep -q "^allowed-tools:" "$ROOT_DIR/skills/$skill/SKILL.md" && pass "  $skill has allowed-tools" || fail "  $skill missing allowed-tools"
  else
    fail "skill $skill missing"
  fi
done
[ "$SKILL_COUNT" -eq "$EXPECTED_SKILL_COUNT" ] && pass "all $EXPECTED_SKILL_COUNT skills present" || fail "expected $EXPECTED_SKILL_COUNT skills, found $SKILL_COUNT"

# ─── Section 4: Agents ───
echo ""
EXPECTED_AGENT_COUNT=$(find "$ROOT_DIR/agents" -name '*.md' -type f | wc -l | tr -d ' ')
echo "--- Section 4: Agents ($EXPECTED_AGENT_COUNT expected) ---"

AGENT_COUNT=0
for group in orchestrators specialists experts core-team; do
  if [ -d "$ROOT_DIR/agents/$group" ]; then
    pass "agent group $group exists"
    for agent_file in "$ROOT_DIR/agents/$group"/*.md; do
      if [ -f "$agent_file" ]; then
        AGENT_COUNT=$((AGENT_COUNT + 1))
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
[ "$AGENT_COUNT" -eq "$EXPECTED_AGENT_COUNT" ] && pass "all $EXPECTED_AGENT_COUNT agents present" || fail "expected $EXPECTED_AGENT_COUNT agents, found $AGENT_COUNT"

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

[ -f "$ROOT_DIR/formatters/pdf-formatter.sh" ] && pass "pdf-formatter.sh exists" || fail "pdf-formatter.sh missing"
[ -f "$ROOT_DIR/formatters/csv-formatter.sh" ] && pass "csv-formatter.sh exists" || fail "csv-formatter.sh missing"

# ─── Section 8: Mappings ───
echo ""
echo "--- Section 8: Compliance Mappings ---"

for f in cwe-to-owasp.json cwe-to-nist.json cwe-to-mitre.json severity-policy.json; do
  [ -f "$ROOT_DIR/mappings/$f" ] && pass "$f exists" || fail "$f missing"
done

# ─── Section 9: References ───
echo ""
EXPECTED_REFS="sast-patterns.md dast-methodology.md sca-supply-chain.md container-hardening.md iac-security-patterns.md secret-management.md compliance-frameworks.md threat-modeling.md incident-response.md remediation-patterns.md software-integrity.md logging-monitoring.md remediation-django.md remediation-react-nextjs.md remediation-express-node.md remediation-spring.md slsa-reference.md k8s-security-reference.md graphql-security-reference.md"
EXPECTED_REF_COUNT=$(echo $EXPECTED_REFS | wc -w | tr -d ' ')
echo "--- Section 9: Reference Files ($EXPECTED_REF_COUNT expected) ---"

REF_COUNT=0
for ref in $EXPECTED_REFS; do
  if [ -f "$ROOT_DIR/skills/references/$ref" ]; then
    pass "reference $ref exists"
    REF_COUNT=$((REF_COUNT + 1))
  else
    fail "reference $ref missing"
  fi
done
[ "$REF_COUNT" -eq "$EXPECTED_REF_COUNT" ] && pass "all $EXPECTED_REF_COUNT reference files present" || fail "expected $EXPECTED_REF_COUNT references, found $REF_COUNT"

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

# Reusable workflow templates
for f in .github/workflows/templates/devsecops-sast.yml .github/workflows/templates/devsecops-sca.yml .github/workflows/templates/devsecops-container-scan.yml .github/workflows/templates/devsecops-full-pipeline.yml; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# GitLab CI templates
for f in ci-templates/devsecops.gitlab-ci.yml ci-templates/sast.gitlab-ci.yml ci-templates/sca.gitlab-ci.yml ci-templates/container-scan.gitlab-ci.yml; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# GitHub Actions copy-paste templates (ci-templates/github/)
for f in ci-templates/github/devsecops-sast.yml ci-templates/github/devsecops-sca.yml ci-templates/github/devsecops-container-scan.yml ci-templates/github/devsecops-full-pipeline.yml; do
  [ -f "$ROOT_DIR/$f" ] && pass "$f exists" || fail "$f missing"
done

# CI adapter and pipeline runner
[ -f "$ROOT_DIR/runner/ci-adapter.sh" ] && pass "ci-adapter.sh exists" || fail "ci-adapter.sh missing"
[ -f "$ROOT_DIR/runner/run-pipeline.sh" ] && pass "run-pipeline.sh exists" || fail "run-pipeline.sh missing"
[ -f "$ROOT_DIR/runner/concurrency-groups.json" ] && pass "concurrency-groups.json exists" || fail "concurrency-groups.json missing"
[ -f "$ROOT_DIR/docs/CI-INTEGRATION.md" ] && pass "CI-INTEGRATION.md exists" || fail "CI-INTEGRATION.md missing"

# ─── Section 16: MCP Server ───
echo ""
echo "--- Section 16: MCP Server ---"

[ -f "$ROOT_DIR/.mcp.json" ] && pass ".mcp.json exists" || fail ".mcp.json missing"
[ -f "$ROOT_DIR/mcp/server.mjs" ] && pass "mcp/server.mjs exists" || fail "mcp/server.mjs missing"
[ -f "$ROOT_DIR/mcp/package.json" ] && pass "mcp/package.json exists" || fail "mcp/package.json missing"
[ -f "$ROOT_DIR/mcp/dist/server.js" ] && pass "mcp/dist/server.js bundle exists" || fail "mcp/dist/server.js bundle missing"

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
  [ "$TOOL_COUNT" -eq 10 ] && pass "MCP server defines 10 tools" || fail "MCP server has $TOOL_COUNT tools (expected 10)"
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

# ─── Section 18: Release Documentation ───
echo ""
echo "--- Section 18: Release Documentation ---"

PLUGIN_VERSION=$(python3 -c "import json; print(json.load(open('$ROOT_DIR/.claude-plugin/plugin.json'))['version'])" 2>/dev/null || echo "unknown")

# CHANGELOG latest version matches plugin.json
CHANGELOG_VERSION=$(grep -m1 -oE '\[([0-9]+\.[0-9]+\.[0-9]+)\]' "$ROOT_DIR/CHANGELOG.md" | tr -d '[]' || echo "none")
[ "$CHANGELOG_VERSION" = "$PLUGIN_VERSION" ] \
  && pass "CHANGELOG latest version ($CHANGELOG_VERSION) matches plugin.json ($PLUGIN_VERSION)" \
  || fail "CHANGELOG latest version ($CHANGELOG_VERSION) != plugin.json ($PLUGIN_VERSION)"

# README badge matches plugin.json
grep -q "Version-$PLUGIN_VERSION" "$ROOT_DIR/README.md" \
  && pass "README badge matches plugin.json version ($PLUGIN_VERSION)" \
  || fail "README badge does not match plugin.json version ($PLUGIN_VERSION)"

# MCP bundle version matches plugin.json
if [ -f "$ROOT_DIR/mcp/dist/server.js" ]; then
  grep -q "$PLUGIN_VERSION" "$ROOT_DIR/mcp/dist/server.js" \
    && pass "MCP bundle contains plugin.json version ($PLUGIN_VERSION)" \
    || warn "MCP bundle does not contain version $PLUGIN_VERSION"
fi

# release.sh exists and is executable
[ -f "$ROOT_DIR/scripts/release.sh" ] && [ -x "$ROOT_DIR/scripts/release.sh" ] \
  && pass "scripts/release.sh exists and is executable" \
  || fail "scripts/release.sh missing or not executable"

# release-checklist.sh exists and is executable
[ -f "$ROOT_DIR/scripts/release-checklist.sh" ] && [ -x "$ROOT_DIR/scripts/release-checklist.sh" ] \
  && pass "scripts/release-checklist.sh exists and is executable" \
  || fail "scripts/release-checklist.sh missing or not executable"

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
