#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Runner Entrypoint
# Bootstraps the sidecar runner and waits for jobs

echo "[runner] DevSecOps AI Team Sidecar Runner starting..."
echo "[runner] Mode: ${RUNNER_MODE:-minimal}"
echo "[runner] PID: $$"

# Ensure directories exist
mkdir -p /results /cache

# Verify Docker socket access
if [ -S /var/run/docker.sock ]; then
  echo "[runner] Docker socket: available"
  docker info --format '{{.ServerVersion}}' 2>/dev/null && echo "[runner] Docker Engine connected" || echo "[runner] WARNING: Cannot connect to Docker"
else
  echo "[runner] WARNING: Docker socket not mounted"
fi

# Create marker for healthcheck
echo "ready" > /tmp/runner-status

echo "[runner] Ready for scan jobs"

# Keep running (tini handles signals)
exec tail -f /dev/null
