#!/usr/bin/env bash

# DevSecOps AI Team — Runner Health Check

if [ -f /tmp/runner-status ] && [ "$(cat /tmp/runner-status)" = "ready" ]; then
  echo "healthy"
  exit 0
else
  echo "unhealthy"
  exit 1
fi
