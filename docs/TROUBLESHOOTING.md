# Troubleshooting Guide

## Common Issues

### Docker not running

**Symptom**: `/devsecops-setup` reports "Docker not available"

**Cause**: Docker daemon is not running

**Solution**:

```bash
# macOS
open -a Docker
# Linux
sudo systemctl start docker
```

### Permission denied on Docker socket

**Symptom**: `permission denied while trying to connect to the Docker daemon socket`

**Cause**: Current user not in docker group

**Solution**:

```bash
sudo usermod -aG docker $USER
# Log out and back in
```

### Container image pull fails

**Symptom**: `Error response from daemon: pull access denied`

**Cause**: Network issue or registry unavailable

**Solution**:

```bash
# Check connectivity
docker pull hello-world
# Use specific image tags instead of :latest
```

### Scan timeout

**Symptom**: Scan takes too long and times out

**Cause**: Large codebase or slow container startup

**Solution**:

- Use `--target` to scan specific directories
- Pre-pull images: `docker compose -f runner/docker-compose.yml pull`
- Increase timeout in `.devsecops.yml`

### GitLeaks false positives

**Symptom**: GitLeaks flags test fixtures or example configs

**Cause**: Default rules match test data

**Solution**:

- Create `.gitleaksignore` in project root
- Add paths: `tests/fixtures/*`
- Use `--no-git` flag for directory-only scanning

### Runner healthcheck fails

**Symptom**: `healthcheck.sh` reports unhealthy status

**Cause**: Runner container not started or crashed

**Solution**:

```bash
docker compose -f runner/docker-compose.yml logs devsecops-runner
docker compose -f runner/docker-compose.yml restart devsecops-runner
```

### Hooks not firing

**Symptom**: Session start doesn't show DevSecOps context

**Cause**: Plugin not properly installed or hooks.json malformed

**Solution**:

```bash
claude doctor
claude plugin list
# Reinstall if needed
claude plugin remove devsecops-ai-team
claude plugin add pitimon/devsecops-ai-team
```

### ZAP container killed (OOM)

**Symptom**: ZAP scan exits with code 137, or `docker inspect` shows `OOMKilled: true`

**Cause**: ZAP's spider/active scan consumes more memory than available. Default Java heap can grow unbounded.

**Solution**:

The `docker-compose.yml` now sets `mem_limit: 2g` for ZAP. If you still hit OOM:

```bash
# Check if OOM killed
docker inspect devsecops-zap --format '{{.State.OOMKilled}}'

# Increase limit in docker-compose.yml
mem_limit: 4g
memswap_limit: 4g
```

**Workaround**: Use baseline scan instead of full scan for large targets:

```bash
# Baseline scan (faster, less memory)
zap-baseline.py -t https://target.com

# Instead of full scan
# zap-full-scan.py -t https://target.com
```

### SARIF upload fails

**Symptom**: GitHub Security tab doesn't show results

**Cause**: SARIF file exceeds size limit or schema mismatch

**Solution**:

- Check file size < 10MB
- Validate schema: `python3 -c "import json; json.load(open('results.sarif'))"`
- Use `--max-results 1000` flag

### MCP Server Connection Errors

**Symptom**: MCP tools (`devsecops_scan`, `devsecops_gate`, etc.) not responding or showing connection errors

**Cause**: Node.js version incompatible, server syntax error, or missing dependencies

**Solution**:

```bash
# Check syntax
node --check mcp/server.mjs

# Check Node.js version (requires 18+)
node --version

# Reinstall dependencies
cd mcp && npm install

# Check stderr output
node mcp/server.mjs 2>&1 | head -20
```

**Common issues**:

- Node.js < 18 — MCP SDK requires ESM support
- Missing `node_modules/` — run `npm install` in `mcp/` directory
- Port conflict — MCP uses stdio transport, not ports

### RBAC Policy Misconfiguration

**Symptom**: `devsecops_gate` returns "Unknown role" or unexpected PASS/FAIL

**Cause**: Missing or malformed severity policy file, or invalid role name

**Solution**:

```bash
# Verify policy file exists and is valid JSON
python3 -c "import json; json.load(open('mappings/severity-policy.json'))"

# Check available roles
python3 -c "
import json
p = json.load(open('mappings/severity-policy.json'))
print('Roles:', list(p['roles'].keys()))
print('Default:', p.get('default_role'))
"
```

**Valid roles**: `developer`, `security-lead`, `release-manager`

**Default behavior**: If no `role` parameter is provided, the gate uses `default_role` from the policy file (typically `developer`, which only blocks CRITICAL findings).

### Zod Validation Errors

**Symptom**: MCP tool returns "Input validation failed" with structured error details

**Cause**: Invalid or missing required parameters in tool input

**Solution**:

Read the error message carefully — it shows exactly which field failed:

```
Input validation failed:
tool: Invalid enum value. Expected 'semgrep' | 'gitleaks' | ..., received 'invalid'
```

**Common mistakes**:

| Error                                         | Cause                      | Fix                        |
| --------------------------------------------- | -------------------------- | -------------------------- |
| `tool: Required`                              | Missing `tool` parameter   | Add `tool: "semgrep"`      |
| `Invalid enum value`                          | Typo in tool/role name     | Check exact enum values    |
| `String must contain at least 1 character(s)` | Empty string passed        | Provide non-empty value    |
| `Expected array, received string`             | Single framework as string | Wrap in array: `["owasp"]` |

### CI/CD Integration

**Symptom**: GitHub Actions workflow fails or SARIF upload rejected

**Cause**: Exit code handling, file path issues, or SARIF size limits

**Solution**:

```yaml
# GitHub Actions example
- name: Run DevSecOps scan
  run: |
    bash runner/job-dispatcher.sh --tool semgrep --target . --format sarif
  continue-on-error: true # Don't fail pipeline on findings

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results/results.sarif
  if: always() # Upload even if scan found issues

- name: Security gate check
  run: |
    # Gate returns exit code 0 (PASS) or 1 (FAIL)
    node mcp/server.mjs gate --results results/normalized.json --role developer
```

**Gate exit codes**: `0` = PASS (no blocking findings), `1` = FAIL (violations found)

**SARIF size limit**: GitHub accepts max 10MB. Use `--max-results 1000` to limit findings.

### Dedup Script Failures

**Symptom**: `dedup-findings.sh` produces empty output or permission error

**Cause**: Missing execute permission, python3 not found, or malformed input files

**Solution**:

```bash
# Ensure execute permission
chmod +x formatters/dedup-findings.sh

# Check python3 is available
python3 --version

# Test with valid input
echo '{"findings": []}' > /tmp/test-input.json
bash formatters/dedup-findings.sh --inputs /tmp/test-input.json --output /tmp/test-output.json

# Check output
cat /tmp/test-output.json
```

**Empty output symptoms**:

- All input files malformed JSON — dedup skips them with warnings on stderr
- Missing `findings` key in input — produces 0 findings (not an error)
- Input file path not found — check comma-separated paths have no spaces

## Getting Help

1. Check [docs/INSTALL.md](INSTALL.md) for setup requirements
2. Run `bash scripts/check-prerequisites.sh` to verify environment
3. Open an issue at https://github.com/pitimon/devsecops-ai-team/issues
