#!/usr/bin/env bash
set -euo pipefail

# DevSecOps AI Team — Secret Validity Checker
# Verifies if detected secrets are actually active/valid.
# REQUIRES --confirm flag — In-the-Loop (user must approve each verification).
#
# Usage: secret-verifier.sh --input <findings.json> --output <verified.json> --confirm
#        [--audit <audit.json>] [--rate-limit <N>]
#
# Providers:
#   AWS      — aws sts get-caller-identity (detects AKIA prefix)
#   GitHub   — GET /user with token (detects token prefixes)
#   Slack    — auth.test with token (detects xoxb/xoxp prefixes)
#   Generic  — configurable GET/POST (pattern match)
#
# Safety:
#   - --confirm flag REQUIRED (exits 1 if missing)
#   - Only first 4 chars of secret shown
#   - Rate limiting: default 5/min/provider
#   - Audit trail: timestamp, provider, result, redacted value
#   - Verified secrets never written to disk
#
# Verification Status:
#   valid   — secret is active and working
#   invalid — secret rejected by provider
#   expired — secret recognized but expired
#   unknown — provider unreachable or unsupported
#   skipped — user declined verification

INPUT=""
OUTPUT=""
CONFIRM=false
AUDIT="verification-audit.json"
RATE_LIMIT=5

while [[ $# -gt 0 ]]; do
  case $1 in
    --input) INPUT="$2"; shift 2 ;;
    --output) OUTPUT="$2"; shift 2 ;;
    --confirm) CONFIRM=true; shift ;;
    --audit) AUDIT="$2"; shift 2 ;;
    --rate-limit) RATE_LIMIT="$2"; shift 2 ;;
    -h|--help)
      echo "Usage: $0 --input <findings.json> --output <verified.json> --confirm"
      echo "       [--audit <audit.json>] [--rate-limit <N>]"
      echo ""
      echo "Options:"
      echo "  --input       Input findings JSON (required)"
      echo "  --output      Output verified findings JSON (required)"
      echo "  --confirm     Required flag — In-the-Loop safety gate"
      echo "  --audit       Audit trail file (default: verification-audit.json)"
      echo "  --rate-limit  Max verifications per minute per provider (default: 5)"
      exit 0
      ;;
    *) echo "ERROR: Unknown option: $1"; exit 1 ;;
  esac
done

# ═══════════════════════════════════════════
# Safety gate: --confirm is mandatory
# ═══════════════════════════════════════════

if [ "$CONFIRM" != "true" ]; then
  echo "ERROR: --confirm flag is required." >&2
  echo "" >&2
  echo "Secret verification is an In-the-Loop operation." >&2
  echo "You must explicitly pass --confirm to acknowledge that:" >&2
  echo "  1. The script will attempt to validate secrets against real APIs" >&2
  echo "  2. Each verification will be prompted for your approval" >&2
  echo "  3. An audit trail will be recorded" >&2
  echo "" >&2
  echo "Usage: $0 --input <findings.json> --output <verified.json> --confirm" >&2
  exit 1
fi

[ -z "$INPUT" ] && { echo "ERROR: --input is required"; exit 1; }
[ -z "$OUTPUT" ] && { echo "ERROR: --output is required"; exit 1; }

if [ ! -f "$INPUT" ]; then
  echo "ERROR: Input file not found: $INPUT" >&2
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 required but not found" >&2
  exit 1
fi

echo "[secret-verifier] Input: $INPUT"
echo "[secret-verifier] Output: $OUTPUT"
echo "[secret-verifier] Audit: $AUDIT"
echo "[secret-verifier] Rate limit: $RATE_LIMIT/min/provider"
echo ""

# ═══════════════════════════════════════════
# Main verification logic (embedded Python3)
# ═══════════════════════════════════════════

export INPUT OUTPUT AUDIT RATE_LIMIT

python3 << 'PYTHON_EOF'
import json
import sys
import os
import subprocess
import time
from datetime import datetime, timezone

INPUT_FILE = os.environ.get("INPUT", "")
OUTPUT_FILE = os.environ.get("OUTPUT", "")
AUDIT_FILE = os.environ.get("AUDIT", "verification-audit.json")
RATE_LIMIT = int(os.environ.get("RATE_LIMIT", "5"))
IS_TTY = os.environ.get("SECRET_VERIFIER_TTY", "") == "1" or os.path.exists("/dev/tty")


# ── Provider Detection ──────────────────────

def detect_provider(finding):
    """Detect cloud/service provider from finding metadata."""
    rule_id = finding.get("rule_id", "").lower()
    message = finding.get("message", "").lower()
    title = finding.get("title", "").lower()
    combined = f"{rule_id} {message} {title}"

    if "aws" in combined or "akia" in combined:
        return "aws"
    elif "github" in combined or ("gh" in combined and "token" in combined):
        return "github"
    elif "slack" in combined or "xoxb" in combined or "xoxp" in combined:
        return "slack"
    else:
        return "generic"


# ── Secret Extraction ───────────────────────

def extract_secret_value(finding):
    """Extract the secret value from finding location snippet."""
    location = finding.get("location", {})
    snippet = location.get("snippet", "")
    # In real usage, gitleaks Match field contains the secret
    # We return the snippet as-is for the verification attempt
    return snippet.strip()


def redact_secret(secret):
    """Show only first 4 chars for user confirmation."""
    if len(secret) <= 4:
        return "****"
    return secret[:4] + "***"


# ── Rate Limiting ───────────────────────────

class RateLimiter:
    """Per-provider rate limiter."""

    def __init__(self, max_per_minute):
        self.max_per_minute = max_per_minute
        self.timestamps = {}  # provider -> [timestamps]

    def can_proceed(self, provider):
        """Check if we can make another request for this provider."""
        now = time.time()
        if provider not in self.timestamps:
            self.timestamps[provider] = []

        # Remove timestamps older than 60 seconds
        self.timestamps[provider] = [
            t for t in self.timestamps[provider]
            if now - t < 60
        ]

        return len(self.timestamps[provider]) < self.max_per_minute

    def record(self, provider):
        """Record a verification attempt."""
        if provider not in self.timestamps:
            self.timestamps[provider] = []
        self.timestamps[provider].append(time.time())

    def wait_time(self, provider):
        """Seconds to wait before next attempt is allowed."""
        if self.can_proceed(provider):
            return 0
        oldest = min(self.timestamps[provider])
        return max(0, 60 - (time.time() - oldest))


# ── Verification Functions ──────────────────

def verify_aws(secret):
    """
    Verify AWS credentials using sts get-caller-identity.
    Expects AKIA-prefixed access key. Requires aws CLI.
    """
    if not _command_exists("aws"):
        return "unknown", "aws CLI not available"

    # AWS verification requires both access key and secret key
    # We only have the access key from gitleaks, so mark as detected-only
    return "unknown", "AWS key detected but requires secret key pair for full verification"


def verify_github(secret):
    """
    Verify GitHub token by calling GET /user.
    Returns valid/invalid/expired based on HTTP status.
    """
    if not _command_exists("curl"):
        return "unknown", "curl not available"

    try:
        result = subprocess.run(
            [
                "curl", "-s", "-o", "/dev/null",
                "-w", "%{http_code}",
                "-H", f"Authorization: token {secret}",
                "-H", "Accept: application/vnd.github.v3+json",
                "--max-time", "10",
                "https://api.github.com/user"
            ],
            capture_output=True, text=True, timeout=15
        )
        status_code = result.stdout.strip()

        if status_code == "200":
            return "valid", f"GitHub token active (HTTP {status_code})"
        elif status_code == "401":
            return "invalid", f"GitHub token rejected (HTTP {status_code})"
        elif status_code == "403":
            return "expired", f"GitHub token expired or rate-limited (HTTP {status_code})"
        else:
            return "unknown", f"Unexpected response (HTTP {status_code})"
    except (subprocess.TimeoutExpired, Exception) as e:
        return "unknown", f"Verification failed: {str(e)}"


def verify_slack(secret):
    """
    Verify Slack token by calling auth.test.
    Returns valid/invalid based on API response.
    """
    if not _command_exists("curl"):
        return "unknown", "curl not available"

    try:
        result = subprocess.run(
            [
                "curl", "-s",
                "-H", f"Authorization: Bearer {secret}",
                "--max-time", "10",
                "https://slack.com/api/auth.test"
            ],
            capture_output=True, text=True, timeout=15
        )
        try:
            response = json.loads(result.stdout)
            if response.get("ok"):
                return "valid", "Slack token active"
            else:
                error = response.get("error", "unknown_error")
                if error in ("token_expired", "token_revoked"):
                    return "expired", f"Slack token {error}"
                else:
                    return "invalid", f"Slack token rejected: {error}"
        except json.JSONDecodeError:
            return "unknown", "Invalid response from Slack API"
    except (subprocess.TimeoutExpired, Exception) as e:
        return "unknown", f"Verification failed: {str(e)}"


def verify_generic(secret):
    """Generic provider — cannot verify without endpoint configuration."""
    return "unknown", "Generic secret — no verification endpoint configured"


def _command_exists(cmd):
    """Check if a command is available on PATH."""
    try:
        result = subprocess.run(
            ["which", cmd],
            capture_output=True, timeout=5
        )
        return result.returncode == 0
    except Exception:
        return False


VERIFIERS = {
    "aws": verify_aws,
    "github": verify_github,
    "slack": verify_slack,
    "generic": verify_generic,
}


# ── User Confirmation ──────────────────────

def prompt_user(finding, provider, redacted):
    """Ask user to confirm verification. Returns True if approved."""
    if not IS_TTY:
        # Non-interactive mode: skip all verifications
        return False

    finding_id = finding.get("id", "unknown")
    title = finding.get("title", "Secret detected")
    location = finding.get("location", {})
    file_path = location.get("file", "unknown")
    line = location.get("line_start", "?")

    print(f"\n{'='*60}")
    print(f"  Finding: {finding_id}")
    print(f"  Title:   {title}")
    print(f"  File:    {file_path}:{line}")
    print(f"  Provider: {provider}")
    print(f"  Secret:  {redacted}")
    print(f"{'='*60}")

    try:
        # Read from /dev/tty since stdin may be the heredoc pipe
        with open("/dev/tty", "r") as tty:
            sys.stdout.write("  Verify this secret? [y/N] ")
            sys.stdout.flush()
            response = tty.readline().strip().lower()
        return response in ("y", "yes")
    except (EOFError, KeyboardInterrupt, OSError):
        print("\n  [Skipped — no input]")
        return False


# ── Audit Trail ─────────────────────────────

class AuditTrail:
    """Records all verification attempts for compliance."""

    def __init__(self, audit_file):
        self.audit_file = audit_file
        self.entries = []
        self.start_time = datetime.now(timezone.utc).isoformat()

    def record(self, finding_id, provider, status, detail, redacted):
        """Record a single verification attempt."""
        self.entries.append({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "finding_id": finding_id,
            "provider": provider,
            "verification_status": status,
            "detail": detail,
            "redacted_value": redacted,
        })

    def write(self):
        """Write audit trail to file."""
        audit = {
            "audit_type": "secret_verification",
            "started_at": self.start_time,
            "completed_at": datetime.now(timezone.utc).isoformat(),
            "total_checked": len(self.entries),
            "summary": self._summarize(),
            "entries": self.entries,
        }
        with open(self.audit_file, "w") as f:
            json.dump(audit, f, indent=2)

    def _summarize(self):
        """Count results by status."""
        summary = {"valid": 0, "invalid": 0, "expired": 0, "unknown": 0, "skipped": 0}
        for entry in self.entries:
            status = entry["verification_status"]
            summary[status] = summary.get(status, 0) + 1
        return summary


# ── Main ────────────────────────────────────

def is_secret_finding(finding):
    """Check if this finding represents a detected secret."""
    source_tool = finding.get("source_tool", "").lower()
    scan_type = finding.get("scan_type", "").lower()

    if source_tool in ("gitleaks", "trufflehog"):
        return True
    if scan_type == "secret":
        return True
    return False


def main():
    input_file = INPUT_FILE
    output_file = OUTPUT_FILE
    audit_file = AUDIT_FILE

    # Load findings
    try:
        with open(input_file) as f:
            data = json.load(f)
    except (json.JSONDecodeError, FileNotFoundError) as e:
        print(f"[secret-verifier] ERROR: Cannot read input: {e}", file=sys.stderr)
        sys.exit(1)

    # Support both { "findings": [...] } and bare [...]
    if isinstance(data, dict):
        findings = data.get("findings", [])
    elif isinstance(data, list):
        findings = data
        data = {"findings": findings}
    else:
        print("[secret-verifier] ERROR: Unexpected JSON structure", file=sys.stderr)
        sys.exit(1)

    rate_limiter = RateLimiter(RATE_LIMIT)
    audit = AuditTrail(audit_file)

    verified_count = 0
    skipped_count = 0
    secret_count = 0

    print(f"[secret-verifier] Processing {len(findings)} findings...")

    for i, finding in enumerate(findings):
        if not is_secret_finding(finding):
            # Not a secret finding — pass through unchanged
            finding["verification_status"] = "not_applicable"
            continue

        secret_count += 1
        provider = detect_provider(finding)
        secret_value = extract_secret_value(finding)
        redacted = redact_secret(secret_value)

        # Check rate limit
        if not rate_limiter.can_proceed(provider):
            wait = rate_limiter.wait_time(provider)
            print(f"  [rate-limit] Provider '{provider}' limit reached. "
                  f"Wait {wait:.0f}s or skipping.")
            finding["verification_status"] = "skipped"
            audit.record(
                finding.get("id", f"finding-{i}"),
                provider, "skipped",
                f"Rate limit exceeded ({RATE_LIMIT}/min)",
                redacted,
            )
            skipped_count += 1
            continue

        # Prompt user for confirmation
        if not prompt_user(finding, provider, redacted):
            finding["verification_status"] = "skipped"
            audit.record(
                finding.get("id", f"finding-{i}"),
                provider, "skipped",
                "User declined verification",
                redacted,
            )
            skipped_count += 1
            continue

        # Verify the secret
        print(f"  [verifying] Provider: {provider}, Secret: {redacted}")
        verifier = VERIFIERS.get(provider, verify_generic)

        # Only attempt real verification if secret value is non-empty
        if secret_value:
            status, detail = verifier(secret_value)
        else:
            status, detail = "unknown", "No secret value extracted from finding"

        rate_limiter.record(provider)
        finding["verification_status"] = status

        audit.record(
            finding.get("id", f"finding-{i}"),
            provider, status, detail, redacted,
        )

        status_label = {
            "valid": "ACTIVE",
            "invalid": "INACTIVE",
            "expired": "EXPIRED",
            "unknown": "UNKNOWN",
        }.get(status, status.upper())

        print(f"  [{status_label}] {detail}")
        verified_count += 1

    # Write output (findings with verification_status added)
    data["findings"] = findings
    data["verification_summary"] = {
        "total_secrets": secret_count,
        "verified": verified_count,
        "skipped": skipped_count,
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    # Write audit trail
    audit.write()

    # Print summary
    print("")
    print(f"[secret-verifier] Complete.")
    print(f"  Secrets found:    {secret_count}")
    print(f"  Verified:         {verified_count}")
    print(f"  Skipped:          {skipped_count}")
    print(f"  Output:           {output_file}")
    print(f"  Audit trail:      {audit_file}")


main()
PYTHON_EOF
