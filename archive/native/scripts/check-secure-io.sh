#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat >&2 <<'USAGE'
Usage:
  scripts/check-secure-io.sh --cached
  scripts/check-secure-io.sh --worktree
  scripts/check-secure-io.sh --diff <git-diff-range>

Rejects newly added raw filesystem primitives in security-sensitive JACS
modules. Add "secure_io:allow" on the same line only when the raw filesystem
operation has been reviewed and is intentionally outside secure_io's contract.
USAGE
}

mode="${1:---cached}"
case "${mode}" in
  --cached)
    diff_cmd=(git diff --cached -U0 --diff-filter=ACMR -- jacs/src)
    ;;
  --worktree)
    diff_cmd=(git diff -U0 --diff-filter=ACMR -- jacs/src)
    ;;
  --diff)
    if [ "${2:-}" = "" ]; then
      usage
      exit 2
    fi
    diff_cmd=(git diff -U0 --diff-filter=ACMR "$2" -- jacs/src)
    ;;
  -h|--help)
    usage
    exit 0
    ;;
  *)
    usage
    exit 2
    ;;
esac

sensitive_path_re='^jacs/src/(agent|cli_utils|config|keystore|simple|trust)(/|\.rs)'
forbidden_re='(std::fs::write|(^|[^[:alnum:]_:])fs::write|File::create|std::fs::read_to_string|(^|[^[:alnum:]_:])fs::read_to_string|std::fs::set_permissions|(^|[^[:alnum:]_:])fs::set_permissions|set_permissions[[:space:]]*\()'

current_file=""
current_line=0
violations=()

while IFS= read -r diff_line; do
  case "${diff_line}" in
    '+++ b/'*)
      current_file="${diff_line#+++ b/}"
      current_line=0
      ;;
    '+++ '*)
      current_file=""
      current_line=0
      ;;
    @@*)
      hunk="${diff_line#*+}"
      hunk="${hunk%%[^0-9]*}"
      current_line="${hunk:-0}"
      ;;
    +*)
      if [[ "${diff_line}" != +++* ]]; then
        if [[ "${current_file}" =~ ${sensitive_path_re} ]] &&
           [[ "${diff_line}" =~ ${forbidden_re} ]] &&
           [[ "${diff_line}" != *secure_io:allow* ]] &&
           [[ ! "${diff_line}" =~ ^\+[[:space:]]*(//|///|\*) ]]; then
          violations+=("${current_file}:${current_line}: ${diff_line#+}")
        fi
        if [ "${current_line}" -gt 0 ]; then
          current_line=$((current_line + 1))
        fi
      fi
      ;;
    -*)
      ;;
    *)
      if [ "${current_line}" -gt 0 ]; then
        current_line=$((current_line + 1))
      fi
      ;;
  esac
done < <("${diff_cmd[@]}")

if [ "${#violations[@]}" -gt 0 ]; then
  echo "ERROR: raw filesystem operation added in security-sensitive JACS modules." >&2
  echo "Use jacs/src/secure_io.rs where practical, or mark reviewed exceptions with secure_io:allow." >&2
  echo "" >&2
  printf '  %s\n' "${violations[@]}" >&2
  exit 1
fi
