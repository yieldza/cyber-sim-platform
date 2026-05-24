#!/usr/bin/env bash
# Parse-only validation for the PowerShell agent script.
#
# Uses the official Microsoft PowerShell container to invoke the real
# PS parser. Catches the class of bugs that string-only checks miss:
#   - Unicode mojibake breaking quoted strings (v0.7.1)
#   - Common-parameter name collisions like $Verbose (v0.7.2)
#   - Brace / try-block mismatches
#   - Missing closing quotes
#
# Exit codes:
#   0  parse clean
#   1  parse errors found (printed)
#   2  docker / pwsh image unavailable (CI failure)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPTS=(
  "agent/powershell/csp-agent.ps1"
)
IMAGE="${PWSH_IMAGE:-mcr.microsoft.com/powershell:latest}"

if ! command -v docker >/dev/null 2>&1; then
  echo "docker not found — cannot run pwsh parser check" >&2
  exit 2
fi
if ! docker info >/dev/null 2>&1; then
  echo "docker daemon not running — start Docker Desktop and retry" >&2
  exit 2
fi

# Pull image quietly on first run. Cached afterwards.
docker pull "$IMAGE" >/dev/null

fail=0
for rel in "${SCRIPTS[@]}"; do
  path="$ROOT/$rel"
  if [[ ! -f "$path" ]]; then
    echo "missing: $rel" >&2
    fail=1
    continue
  fi
  echo "==> parsing $rel"
  # Mount the repo read-only at /work and run the parser inside the container.
  # Output is whatever the parser printed. Exit code maps 1:1.
  if ! docker run --rm \
      -v "$ROOT":/work:ro \
      -w /work \
      "$IMAGE" \
      pwsh -NoProfile -NonInteractive -Command "
        \$tokens = \$null; \$errors = \$null
        \$null = [System.Management.Automation.Language.Parser]::ParseFile(
          '/work/$rel', [ref]\$tokens, [ref]\$errors)
        if (\$errors -and \$errors.Count -gt 0) {
          foreach (\$e in \$errors) {
            Write-Host (\"[ERROR] {0}:{1}:{2} - {3}\" -f
              \$e.Extent.File, \$e.Extent.StartLineNumber,
              \$e.Extent.StartColumnNumber, \$e.Message)
          }
          exit 1
        }
        Write-Host '[OK] parse clean'
      "; then
    echo "  ^ parse FAILED for $rel"
    fail=1
  fi
done

if [[ $fail -ne 0 ]]; then
  echo "PowerShell parser check FAILED — fix the errors above before pushing"
  exit 1
fi
echo
echo "PowerShell parser check passed for ${#SCRIPTS[@]} file(s)"
