#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
jacsgo_dir="$(cd "${script_dir}/.." && pwd)"
workspace_root="$(cd "${jacsgo_dir}/.." && pwd)"
cli_bin="${JACS_CLI_BIN:-}"

if [[ -z "${cli_bin}" || "${cli_bin}" != /* || ! -x "${cli_bin}" ]]; then
  echo "JACS_CLI_BIN must be an absolute path to a prebuilt executable" >&2
  exit 2
fi

log_file="$(mktemp)"
fixture_dir="$(mktemp -d)"
ready_file="${fixture_dir}/cargo-ready"
competitor_pid=""
cleanup() {
  if [[ -n "${competitor_pid}" ]] && kill -0 "${competitor_pid}" 2>/dev/null; then
    kill "${competitor_pid}" 2>/dev/null || true
    wait "${competitor_pid}" 2>/dev/null || true
  fi
  rm -f "${log_file}"
  rm -rf "${fixture_dir}"
}
trap cleanup EXIT

cat >"${fixture_dir}/Cargo.toml" <<'TOML'
[package]
name = "jacs-competing-cargo-regression"
version = "0.0.0"
edition = "2024"
publish = false
TOML

cat >"${fixture_dir}/build.rs" <<'RUST'
fn main() {
    let ready = std::env::var("JACS_COMPETING_CARGO_READY").expect("ready marker path");
    std::fs::write(ready, b"ready").expect("write ready marker");
    std::thread::sleep(std::time::Duration::from_secs(3));
}
RUST

mkdir -p "${fixture_dir}/src"
cat >"${fixture_dir}/src/lib.rs" <<'RUST'
pub fn competing_build_fixture() {}
RUST

# Use the workspace target directory deliberately: this is the exact
# artifact-lock contention that caused the historical nested `cargo run` to
# hang. The build-script marker proves the competing Cargo process is active
# before the Go test starts.
(
  JACS_COMPETING_CARGO_READY="${ready_file}" \
    CARGO_TARGET_DIR="${workspace_root}/target" \
    cargo build --manifest-path "${fixture_dir}/Cargo.toml" >"${log_file}" 2>&1
) &
competitor_pid=$!

for _ in {1..200}; do
  if [[ -f "${ready_file}" ]]; then
    break
  fi
  if ! kill -0 "${competitor_pid}" 2>/dev/null; then
    wait "${competitor_pid}" || true
    competitor_pid=""
    echo "Competing Cargo build exited before reaching the lock-holding fixture" >&2
    tail -80 "${log_file}" >&2 || true
    exit 1
  fi
  sleep 0.05
done
if [[ ! -f "${ready_file}" ]]; then
  echo "Timed out waiting for the competing Cargo build to become active" >&2
  tail -80 "${log_file}" >&2 || true
  exit 1
fi

cd "${jacsgo_dir}"
if ! JACS_CLI_BIN="${cli_bin}" go test -race -count=1 \
  -run '^TestProvenanceGoSignsRustVerifies$' -timeout 60s .; then
  echo "Go provenance test failed while competing Cargo build was active" >&2
  echo "Competing Cargo output:" >&2
  tail -80 "${log_file}" >&2 || true
  exit 1
fi

if ! wait "${competitor_pid}"; then
  competitor_pid=""
  echo "Competing Cargo build failed" >&2
  tail -80 "${log_file}" >&2 || true
  exit 1
fi
competitor_pid=""
