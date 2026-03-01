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

### SARIF upload fails

**Symptom**: GitHub Security tab doesn't show results

**Cause**: SARIF file exceeds size limit or schema mismatch

**Solution**:

- Check file size < 10MB
- Validate schema: `python3 -c "import json; json.load(open('results.sarif'))"`
- Use `--max-results 1000` flag

## Getting Help

1. Check [docs/INSTALL.md](INSTALL.md) for setup requirements
2. Run `bash scripts/check-prerequisites.sh` to verify environment
3. Open an issue at https://github.com/pitimon/devsecops-ai-team/issues
