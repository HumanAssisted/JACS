#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
WORKDIR="${WORKDIR:-$(mktemp -d "${TMPDIR:-/tmp}/jacs-w3c-demo.XXXXXX")}"
ORIGIN="${ORIGIN:-https://agent.example.com}"
REQUEST_URL="${REQUEST_URL:-https://api.example.com/tasks?priority=high}"
REQUEST_BODY='{"task":"review proposal","ok":true}'

cleanup() {
  if [[ -z "${KEEP_WORKDIR:-}" && -d "${WORKDIR}" ]]; then
    rm -rf "${WORKDIR}"
  fi
}
trap cleanup EXIT

jacs() {
  if [[ -n "${JACS_BIN:-}" ]]; then
    "${JACS_BIN}" "$@"
  else
    cargo run -q --manifest-path "${REPO_ROOT}/Cargo.toml" -p jacs-cli -- "$@"
  fi
}

mkdir -p "${WORKDIR}"
export JACS_PRIVATE_KEY_PASSWORD="${JACS_PRIVATE_KEY_PASSWORD:-W3cInterop!Pass2026}"

echo "Creating demo agent in ${WORKDIR}"
(
  cd "${WORKDIR}"
  jacs quickstart --algorithm ed25519 --name "w3c-demo-agent" --domain "agent.example.com"
)

echo "Exporting W3C DID and discovery artifacts"
(
  cd "${WORKDIR}"
  jacs w3c did --origin "${ORIGIN}" > did.txt
  jacs w3c did-document --origin "${ORIGIN}" > did.json
  jacs w3c agent-description --origin "${ORIGIN}" > agent-description.json
  jacs w3c well-known --origin "${ORIGIN}" --out public
)

DID="$(cat "${WORKDIR}/did.txt")"
case "${DID}" in
  did:wba:*) ;;
  *)
    echo "Expected did:wba identifier, got: ${DID}" >&2
    exit 1
    ;;
esac

echo "Signing concrete HTTP request"
(
  cd "${WORKDIR}"
  jacs w3c sign-request \
    --method POST \
    --url "${REQUEST_URL}" \
    --body "${REQUEST_BODY}" \
    --origin "${ORIGIN}" \
    > proof.json
)

echo "Verifying request-bound proof"
(
  cd "${WORKDIR}"
  jacs w3c verify-request \
    --method POST \
    --url "${REQUEST_URL}" \
    --proof proof.json \
    --did-document did.json \
    --body "${REQUEST_BODY}" \
    > verification.json
)

echo "Checking expected failure for body substitution"
if (
  cd "${WORKDIR}"
  jacs w3c verify-request \
    --method POST \
    --url "${REQUEST_URL}" \
    --proof proof.json \
    --did-document did.json \
    --body '{"task":"tampered","ok":false}' \
    > bad-body.json
); then
  echo "Body substitution unexpectedly verified" >&2
  exit 1
fi

echo "Checking expected failure for target URI substitution"
if (
  cd "${WORKDIR}"
  jacs w3c verify-request \
    --method POST \
    --url "https://api.example.com/other" \
    --proof proof.json \
    --did-document did.json \
    --body "${REQUEST_BODY}" \
    > bad-url.json
); then
  echo "Target URI substitution unexpectedly verified" >&2
  exit 1
fi

echo "W3C DID interop demo passed"
echo "DID: ${DID}"
echo "Artifacts: ${WORKDIR}"
