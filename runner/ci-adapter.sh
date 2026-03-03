#!/usr/bin/env bash
# DevSecOps AI Team — CI Platform Adapter
# Provides platform-agnostic CI/CD functions
# Supports: GitHub Actions, GitLab CI, local execution

# Detect CI platform from environment variables
ci_detect_platform() {
  if [ -n "${GITHUB_ACTIONS:-}" ]; then
    echo "github"
  elif [ -n "${GITLAB_CI:-}" ]; then
    echo "gitlab"
  else
    echo "local"
  fi
}

# Set output variable (key=value) for the CI platform
ci_set_output() {
  local key="$1" value="$2"
  local platform
  platform=$(ci_detect_platform)
  case "$platform" in
    github)
      echo "${key}=${value}" >> "${GITHUB_OUTPUT:-/dev/null}"
      ;;
    gitlab)
      echo "export ${key}=\"${value}\"" >> "${CI_PROJECT_DIR:-.}/ci_outputs.env"
      ;;
    local)
      echo "[output] ${key}=${value}"
      ;;
  esac
}

# Upload artifact
ci_upload_artifact() {
  local name="$1" path="$2"
  local platform
  platform=$(ci_detect_platform)
  case "$platform" in
    github)
      # GitHub uses actions/upload-artifact — just report path
      echo "::notice::Artifact '${name}' available at: ${path}"
      ;;
    gitlab)
      # GitLab uses artifacts: in .gitlab-ci.yml — just report path
      echo "Artifact '${name}': ${path}"
      ;;
    local)
      echo "[artifact] ${name}: ${path}"
      ;;
  esac
}

# Fail the current step with a message
ci_fail_step() {
  local message="$1"
  local platform
  platform=$(ci_detect_platform)
  case "$platform" in
    github)
      echo "::error::${message}"
      ;;
    gitlab)
      echo "ERROR: ${message}" >&2
      ;;
    local)
      echo "[FAIL] ${message}" >&2
      ;;
  esac
  return 1
}

# Start a log group
ci_group_start() {
  local name="$1"
  local platform
  platform=$(ci_detect_platform)
  case "$platform" in
    github)
      echo "::group::${name}"
      ;;
    gitlab)
      echo -e "\e[0Ksection_start:$(date +%s):${name//[^a-zA-Z0-9_]/_}\r\e[0K${name}"
      ;;
    local)
      echo "=== ${name} ==="
      ;;
  esac
}

# End a log group
ci_group_end() {
  local name="${1:-}"
  local platform
  platform=$(ci_detect_platform)
  case "$platform" in
    github)
      echo "::endgroup::"
      ;;
    gitlab)
      echo -e "\e[0Ksection_end:$(date +%s):${name//[^a-zA-Z0-9_]/_}\r\e[0K"
      ;;
    local)
      echo "=== end ==="
      ;;
  esac
}

# Write job summary (markdown)
ci_summary() {
  local markdown="$1"
  local platform
  platform=$(ci_detect_platform)
  case "$platform" in
    github)
      echo "$markdown" >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
      ;;
    gitlab)
      # GitLab doesn't have native step summary — write to artifact
      local summary_file="${CI_PROJECT_DIR:-.}/devsecops-summary.md"
      echo "$markdown" >> "$summary_file"
      echo "Summary written to: $summary_file"
      ;;
    local)
      echo "$markdown"
      ;;
  esac
}
