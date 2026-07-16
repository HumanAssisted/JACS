.PHONY: build-jacs build-jacsbook build-jacsbook-pdf build-wasm test-wasm publish-jacs-wasm release-jacs-wasm retry-jacs-wasm \
        test test-all test-all-pq test-rust-pr test-bindings-fast test-rust-slow test-jacs test-jacs-fast test-jacs-fast-lib test-jacs-fast-bin-shard-a test-jacs-fast-bin-shard-b test-jacs-features test-jacs-pq test-jacs-cli test-jacs-cross-language test-jacs-observability \
        test-jacs-mcp test-jacs-binding-core test-jacs-binding-core-pq test-jacs-wasm \
        test-jacs-duckdb test-jacs-redb test-jacs-surrealdb test-jacs-postgresql test-jacs-storage \
        test-jacspy test-jacspy-parallel test-jacsnpm test-jacsnpm-parallel \
        audit-jacs \
        publish-jacs publish-jacs-media publish-jacs-core publish-jacs-binding-core publish-jacs-mcp publish-jacs-cli publish-jacspy publish-jacsnpm \
        publish-jacs-storage publish-jacs-storage-dry publish-jacs-duckdb publish-jacs-redb publish-jacs-surrealdb publish-jacs-postgresql \
        release-preflight release-jacs release-jacspy release-jacsnpm release-jacs-wasm release-jacsgo release-cli release-jacs-storage release-everything release-delete-tags \
        plan-release-everything plan-release-jacs-storage \
        retry-jacs retry-jacspy retry-jacsnpm retry-jacs-wasm retry-jacsgo retry-cli retry-everything \
        plan-retry-jacs plan-retry-jacspy plan-retry-jacsnpm plan-retry-jacs-wasm plan-retry-jacsgo plan-retry-cli plan-retry-everything \
        bump-patch bump-minor bump-major \
        seal-changelog check-changelog-sealed \
        version versions check-versions check-project-license third-party-notices check-third-party-notices check-release-matrix verify-shipped-release check-version-jacs check-version-jacspy check-version-jacsnpm check-version-wasm check-version-jacsgo check-version-cli \
        install-githooks regen-cross-lang-fixtures sync-schemas smoke-verifiers \
        help

# ============================================================================
# VERSION DETECTION
# ============================================================================
# Extract versions from source files. These are used for release tagging.

# Rust core library version (from jacs/Cargo.toml)
JACS_VERSION := $(shell grep '^version' jacs/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Rust MCP server version (from jacs-mcp/Cargo.toml)
JACS_MCP_VERSION := $(shell grep '^version' jacs-mcp/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Shared Rust binding core version (from binding-core/Cargo.toml)
BINDING_CORE_VERSION := $(shell grep '^version' binding-core/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Media signing helper crate version (from jacs-media/Cargo.toml)
JACS_MEDIA_VERSION := $(shell grep '^version' jacs-media/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Portable protocol crate version (from jacs-core/Cargo.toml). Published
# first in the crates.io dependency chain. See CLAUDE.md Publish Order.
JACS_CORE_VERSION := $(shell grep '^version' jacs-core/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Browser bindings crate version (from jacs-wasm/Cargo.toml). Published to
# npm only as @jacs/wasm via release-wasm.yml (Task 021).
JACS_WASM_RUST_VERSION := $(shell grep '^version' jacs-wasm/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# @jacs/wasm npm package version, written into jacs-wasm/pkg/package.json
# by finalize-pkg.sh after `wasm-pack build` (Task 020). Until the
# template + finalize script land, this falls back to the Cargo version
# so `check-versions` does not error out on a fresh checkout.
JACS_WASM_NPM_VERSION := $(shell test -f jacs-wasm/package.template.json && grep '"version"' jacs-wasm/package.template.json | head -1 | sed 's/.*: *"\(.*\)".*/\1/' || echo $(JACS_WASM_RUST_VERSION))

# Python bindings version (from jacspy/pyproject.toml)
JACSPY_VERSION := $(shell grep '^version' jacspy/pyproject.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Python Rust extension crate version (from jacspy/Cargo.toml)
JACSPY_RUST_VERSION := $(shell grep '^version' jacspy/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Node.js bindings version (from jacsnpm/package.json)
JACSNPM_VERSION := $(shell grep '"version"' jacsnpm/package.json | head -1 | sed 's/.*: *"\(.*\)".*/\1/')

# Node.js Rust extension crate version (from jacsnpm/Cargo.toml)
JACSNPM_RUST_VERSION := $(shell grep '^version' jacsnpm/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Go FFI Rust library version (from jacsgo/lib/Cargo.toml)
JACSGO_VERSION := $(shell grep '^version' jacsgo/lib/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Storage backend crate versions (independent version track)
JACS_DUCKDB_VERSION := $(shell grep '^version' jacs-duckdb/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
JACS_REDB_VERSION := $(shell grep '^version' jacs-redb/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
JACS_SURREALDB_VERSION := $(shell grep '^version' jacs-surrealdb/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
JACS_POSTGRESQL_VERSION := $(shell grep '^version' jacs-postgresql/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')

# Release tags are handled without interpolating manifest-derived versions into
# shell programs. The helper validates SemVer, probes local and remote tag state,
# and applies a per-command deadline.
RELEASE_HELPER := python3 scripts/release_retry.py

# Fast Rust lane for the core crate: exclude dedicated CLI, interop, observability,
# and PQ-only binaries so the default PR path stays bounded.
JACS_TEST_BINS := $(basename $(notdir $(shell find jacs/tests -maxdepth 1 -name '*.rs' -print | sort)))
JACS_FAST_TEST_BINS := $(filter-out a2a_cross_language_tests attestation_cross_lang_tests cli_flags cli_tests cross_language_tests observability_oltp_meter observability_tests pq2025_tests pq_tests,$(JACS_TEST_BINS))

# Alphabetical shard split for CI parallelization.
# Shard A: test names starting with a-d.   Shard B: test names starting with e-z.
JACS_FAST_BIN_SHARD_A := $(filter a% b% c% d%,$(JACS_FAST_TEST_BINS))
JACS_FAST_BIN_SHARD_B := $(filter-out a% b% c% d%,$(JACS_FAST_TEST_BINS))

# ============================================================================
# BUILD
# ============================================================================

build-jacs:
	cargo install --path jacs-cli --force
	~/.cargo/bin/jacs --help
	~/.cargo/bin/jacs version

build-jacspy:
	cd jacspy && maturin develop

build-jacsnpm:
	cd jacsnpm && npm run build

# Build the @jacs/wasm npm package via wasm-pack. PRD §4.8.
# After wasm-pack runs, finalize-pkg.sh (Task 020) rewrites
# pkg/package.json to set name=@jacs/wasm + the right exports map.
build-wasm:
	cd jacs-wasm && wasm-pack build --target web --release . --locked
	@if [ -x jacs-wasm/scripts/finalize-pkg.sh ]; then \
		bash jacs-wasm/scripts/finalize-pkg.sh; \
	else \
		echo "NOTE: jacs-wasm/scripts/finalize-pkg.sh not present yet (Task 020). Skipping pkg metadata finalize."; \
	fi

# Run jacs-wasm tests headless in Chrome. Requires wasm-pack + a
# matching chromedriver on PATH. PRD §3.2.
test-wasm:
	cd jacs-wasm && wasm-pack test --headless --chrome . --locked

# Publish the finalized @jacs/wasm npm package. Run `make build-wasm`
# first. Triggered from CI by the `wasm-vX.Y.Z` tag handler in
# release-wasm.yml (Task 021); local credentials required for direct
# invocation.
publish-jacs-wasm: build-wasm
	cd jacs-wasm/pkg && npm publish --access public

build-jacsbook:
	cd jacs/docs/jacsbook && mdbook build

build-jacsbook-pdf:
	./jacs/docs/jacsbook/scripts/build-pdf.sh

# ============================================================================
# TEST
# ============================================================================

test-jacs:
	cd jacs && RUST_BACKTRACE=1 cargo test --lib --tests -- --nocapture

# Fast test run: ed25519 only (no post-quantum keygen)
test-jacs-fast:
	cd jacs && RUST_BACKTRACE=1 cargo test --features agreements,a2a,attestation --lib $(foreach test,$(JACS_FAST_TEST_BINS),--test $(test)) -- --nocapture --skip secure_fetch::tests
	$(MAKE) test-jacs-secure-fetch

# Loopback harnesses run separately so host/sandbox socket quotas cannot make
# them race unrelated network tests. This still executes every secure-fetch
# regression; it changes scheduling, not coverage.
test-jacs-secure-fetch:
	cd jacs && RUST_BACKTRACE=1 cargo test --features agreements,a2a,attestation --lib secure_fetch::tests -- --nocapture --test-threads=1

# Sharded fast targets for CI parallelization (each maps to one local command).
test-jacs-fast-lib:
	cd jacs && RUST_BACKTRACE=1 cargo test --features agreements,a2a,attestation --lib -- --nocapture --skip secure_fetch::tests
	$(MAKE) test-jacs-secure-fetch

test-jacs-fast-bin-shard-a:
	cd jacs && RUST_BACKTRACE=1 cargo test --features agreements,a2a,attestation $(foreach test,$(JACS_FAST_BIN_SHARD_A),--test $(test)) -- --nocapture

test-jacs-fast-bin-shard-b:
	cd jacs && RUST_BACKTRACE=1 cargo test --features agreements,a2a,attestation $(foreach test,$(JACS_FAST_BIN_SHARD_B),--test $(test)) -- --nocapture

# Full test run: includes post-quantum algorithm tests (slow keygen)
test-jacs-pq:
	cargo build --locked -p jacs-cli
	RUST_BACKTRACE=1 cargo test -p jacs --features agreements,a2a,attestation,pq-tests --lib --tests --verbose -- --skip secure_fetch::tests
	$(MAKE) test-jacs-secure-fetch

test-jacs-features: test-jacs-pq

test-jacs-cli:
	cargo build --locked -p jacs-cli
	cd jacs && RUST_BACKTRACE=1 cargo test --test cli_tests --test cli_flags -- --nocapture
	RUST_BACKTRACE=1 cargo test -p jacs-cli --lib --tests -- --nocapture

test-jacs-cross-language:
	cd jacs && RUST_BACKTRACE=1 cargo test --features "agreements a2a attestation" --test cross_language_tests --test a2a_cross_language_tests --test attestation_cross_lang_tests -- --nocapture

# P2 NFR8 smoke lane (docs/P2_ES256_SMOKE.md "End-to-End CLI Smoke"):
# build the CLI, create a scratch agent, run both content exporters
# (AP2 mandate detached JWS + Agreement-v2-as-VC), then verify both
# artifacts with the committed stock verifier scripts (jose +
# canonicalize; no JACS verification code). Requires node/npm.
smoke-verifiers:
	cargo build --locked -p jacs-cli
	@set -eu; \
	REPO=$$(pwd); \
	JACS=$$REPO/target/debug/jacs; \
	WORK=$$(mktemp -d); \
	trap 'rm -rf "$$WORK"' EXIT; \
	cd "$$WORK"; \
	export JACS_PRIVATE_KEY_PASSWORD='P2-Smoke-Password!2026'; \
	export JACS_KEYCHAIN_BACKEND=disabled; \
	"$$JACS" quickstart --name p2-smoke --domain example.com >/dev/null; \
	"$$JACS" agent export-jwks > p2_jwks.json; \
	"$$JACS" agent export-compat-binding > p2_binding.json; \
	if "$$JACS" agent add-compat-key >/dev/null 2>&1; then \
		echo "UNEXPECTED: duplicate add-compat-key succeeded"; exit 1; \
	fi; \
	echo "ok: duplicate add-compat-key rejected (typed error)"; \
	"$$JACS" agent issue-compat-binding --scopes jwks,did,a2a-agent-card,w3c-agent-identity,ap2-mandate,agreement-vc >/dev/null; \
	printf '%s' '{"id":"checkout_smoke_001","status":"ready_for_payment","currency":"USD","line_items":[{"id":"li_1","title":"Widget","quantity":1,"base_amount":990,"total_amount":990}],"totals":[{"type":"total","display_text":"Total","amount":990}]}' > p2_checkout.json; \
	"$$JACS" ap2 export-mandate --input p2_checkout.json > p2_mandate_export.json; \
	AGENT_ID=$$(python3 -c "import json; print(json.load(open('jacs.config.json'))['jacs_agent_id_and_version'].split(':')[0])"); \
	printf '{"title":"P2 smoke agreement","description":"Agreement used by make smoke-verifiers.","terms":"Party agrees to smoke-test things.","termsFormat":"text/plain","status":"proposed","parties":[{"agentId":"%s","agentType":"ai","role":"signer"}],"signaturePolicy":{"partyQuorum":"all"},"controllers":["%s"]}' "$$AGENT_ID" "$$AGENT_ID" > p2_agreement_input.json; \
	"$$JACS" agreement-v2 create --input p2_agreement_input.json > p2_agreement.json; \
	"$$JACS" agreement-v2 export-vc --agreement - < p2_agreement.json > p2_agreement_vc.json; \
	cp "$$REPO"/scripts/smoke/verify_ap2_jws.mjs "$$REPO"/scripts/smoke/verify_di_vc.mjs .; \
	npm init -y >/dev/null; \
	npm install --silent --no-audit --no-fund jose canonicalize >/dev/null; \
	node verify_ap2_jws.mjs p2_mandate_export.json p2_jwks.json; \
	node verify_di_vc.mjs p2_agreement_vc.json p2_jwks.json; \
	echo '{"claim":"native wall"}' | "$$JACS" quickstart --name p2-smoke --domain example.com --sign > p2_signed_document.json; \
	"$$JACS" verify p2_signed_document.json >/dev/null; \
	echo "SMOKE-VERIFIERS-OK"

# NOTE: `observability-convenience` was removed as a feature in v0.9.4 (the
# convenience module is unconditional); listing it made cargo abort the whole
# lane with "does not contain this feature", so every test here was dead in CI.
test-jacs-observability:
	cd jacs && RUST_BACKTRACE=1 cargo test --features "otlp-logs otlp-metrics otlp-tracing agreements" --test observability_tests --test observability_oltp_meter --test compatibility_observability --test security_observability -- --nocapture

test-jacs-mcp:
	RUST_BACKTRACE=1 cargo test -p jacs-mcp --lib --tests --verbose

test-jacs-binding-core:
	RUST_BACKTRACE=1 cargo test -p jacs-binding-core --features agreements --lib --tests --verbose

test-jacs-binding-core-pq:
	RUST_BACKTRACE=1 cargo test -p jacs-binding-core --features agreements,pq-tests --lib --tests --verbose

# jacs-wasm native sanity suite (agreement v2 + forged-signature + declaration drift).
test-jacs-wasm:
	RUST_BACKTRACE=1 cargo test -p jacs-wasm --lib --tests --verbose

# Storage backend crates (extracted from jacs core)
test-jacs-duckdb:
	RUST_BACKTRACE=1 cargo test -p jacs-duckdb --lib --tests --verbose

test-jacs-redb:
	RUST_BACKTRACE=1 cargo test -p jacs-redb --lib --tests --verbose

test-jacs-surrealdb:
	RUST_BACKTRACE=1 cargo test --manifest-path jacs-surrealdb/Cargo.toml --locked --lib --tests --verbose

test-jacs-postgresql:
	RUST_BACKTRACE=1 cargo test -p jacs-postgresql --lib --tests --verbose

test-jacs-storage: test-jacs-duckdb test-jacs-redb test-jacs-surrealdb test-jacs-postgresql

audit-jacs:
	@command -v cargo-audit >/dev/null 2>&1 || (echo "cargo-audit is required. Install with: cargo install cargo-audit --locked --version 0.22.1"; exit 1)
	cargo audit

test-jacspy:
	cd jacspy && maturin develop && python -m pytest tests/ -v

test-jacspy-parallel:
	cd jacspy && PYTEST_XDIST_WORKERS=$${PYTEST_XDIST_WORKERS:-auto} make test-python-parallel

test-jacsnpm:
	cd jacsnpm && npm test

test-jacsnpm-parallel:
	cd jacsnpm && npm run test:parallel

test: test-jacs

# Default PR suite: fast Rust lanes plus parallel binding runners.
test-rust-pr: test-jacs-fast test-jacs-cli test-jacs-binding-core test-jacs-wasm test-jacs-mcp

test-bindings-fast: test-jacspy-parallel test-jacsnpm-parallel

# Slower Rust compatibility and infrastructure suites.
test-rust-slow: test-jacs-storage test-jacs-cross-language test-jacs-observability

# Run the default fast suite used for everyday PR validation.
test-all: test-rust-pr test-bindings-fast

# Run the extended suite: slow Rust lanes plus post-quantum coverage.
test-all-pq: test-all test-rust-slow test-jacs-pq test-jacs-binding-core-pq

# Regenerate all canonical cross-language fixtures in sequence.
# This intentionally mutates tracked fixture files.
regen-cross-lang-fixtures:
	UPDATE_CROSS_LANG_FIXTURES=1 cargo test -p jacs --test cross_language_tests -- --nocapture
	cd jacspy && UPDATE_CROSS_LANG_FIXTURES=1 pytest tests/test_cross_language.py -q
	cd jacsnpm && UPDATE_CROSS_LANG_FIXTURES=1 npm run test:cross-language --silent

# Install repo-local git hooks (pre-commit guard for fixture changes).
install-githooks:
	git config core.hooksPath .githooks
	@echo "Configured git hooks path to .githooks"

# ============================================================================
# VERSION INFO
# ============================================================================

# Bump version across all files: make bump-patch / bump-minor / bump-major
bump-patch:
	./scripts/bump-version.sh patch

bump-minor:
	./scripts/bump-version.sh minor

bump-major:
	./scripts/bump-version.sh major

# Flip "(unreleased)" -> "Released YYYY-MM-DD" in CHANGELOG.md for the
# current $(JACS_VERSION). Idempotent. Run before tagging a release; commit
# the result so the tag captures the sealed changelog.
seal-changelog:
	@./scripts/seal-changelog.sh seal $(JACS_VERSION)

# Strict gate: fails if CHANGELOG.md ## $(JACS_VERSION) still says "(unreleased)".
# Wired as a prereq on release-* targets to prevent shipping unsealed notes.
check-changelog-sealed:
	@./scripts/seal-changelog.sh check $(JACS_VERSION)

# Show all detected versions
versions:
	@echo "Detected versions from source files:"
	@echo "  jacs (Cargo.toml):        $(JACS_VERSION)"
	@echo "  jacs-core (Cargo.toml):   $(JACS_CORE_VERSION)"
	@echo "  jacs-mcp (Cargo.toml):    $(JACS_MCP_VERSION)"
	@echo "  binding-core (Cargo.toml):$(BINDING_CORE_VERSION)"
	@echo "  jacs-media (Cargo.toml):  $(JACS_MEDIA_VERSION)"
	@echo "  jacs-wasm (Cargo.toml):   $(JACS_WASM_RUST_VERSION)"
	@echo "  jacs-wasm/package.json:   $(JACS_WASM_NPM_VERSION)"
	@echo "  jacspy (pyproject.toml):  $(JACSPY_VERSION)"
	@echo "  jacspy (Cargo.toml):      $(JACSPY_RUST_VERSION)"
	@echo "  jacsnpm (package.json):   $(JACSNPM_VERSION)"
	@echo "  jacsnpm (Cargo.toml):     $(JACSNPM_RUST_VERSION)"
	@echo "  jacsgo/lib (Cargo.toml):  $(JACSGO_VERSION)"
	@echo "  jacs-duckdb:              $(JACS_DUCKDB_VERSION)"
	@echo "  jacs-redb:                $(JACS_REDB_VERSION)"
	@echo "  jacs-surrealdb:           $(JACS_SURREALDB_VERSION)"
	@echo "  jacs-postgresql:          $(JACS_POSTGRESQL_VERSION)"
	@echo ""
	@if [ "$(JACS_VERSION)" = "$(JACS_MCP_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(BINDING_CORE_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACS_MEDIA_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACS_CORE_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACS_WASM_RUST_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACS_WASM_NPM_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACSPY_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACSPY_RUST_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACSNPM_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACSNPM_RUST_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(JACSGO_VERSION)" ]; then \
		echo "✓ All release versions match: $(JACS_VERSION)"; \
	else \
		echo "⚠ WARNING: Versions do not match!"; \
	fi

version: versions

# Verify the embedded schema set in jacs-core/schemas mirrors jacs/schemas
# exactly. They must stay byte-identical: jacs-core is the wasm-portable
# copy used by the browser path, jacs/schemas is what `jacs/Cargo.toml`
# include-ships for the native crate. See PRD §4.4 and Task 006 / Task 017
# (cleanup will collapse to a single source of truth).
sync-schemas:
	@diff -r jacs/schemas jacs-core/schemas > /dev/null || \
		(echo "ERROR: jacs/schemas and jacs-core/schemas differ. Run 'cp -r jacs/schemas/* jacs-core/schemas/' to mirror." && exit 1)
	@echo "OK: jacs/schemas and jacs-core/schemas are in sync"

# Check that all versions match (fails if they don't)
check-versions:
	@if [ "$(JACS_VERSION)" != "$(JACS_MCP_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacs-mcp ($(JACS_MCP_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(BINDING_CORE_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != binding-core ($(BINDING_CORE_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACS_MEDIA_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacs-media ($(JACS_MEDIA_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACS_CORE_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacs-core ($(JACS_CORE_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACS_WASM_RUST_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacs-wasm Cargo.toml ($(JACS_WASM_RUST_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACS_WASM_NPM_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacs-wasm package.template.json ($(JACS_WASM_NPM_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACSPY_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacspy ($(JACSPY_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACSPY_RUST_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacspy Cargo.toml ($(JACSPY_RUST_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACSNPM_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacsnpm ($(JACSNPM_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACSNPM_RUST_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacsnpm Cargo.toml ($(JACSNPM_RUST_VERSION))"; \
		exit 1; \
	fi
	@if [ "$(JACS_VERSION)" != "$(JACSGO_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacsgo/lib ($(JACSGO_VERSION))"; \
		exit 1; \
	fi
	@echo "✓ All release versions match: $(JACS_VERSION)"

# Validate the checked-in evidence matrix without network access. After every
# coordinated release, refresh release/shipped-artifacts.json from registry
# evidence and run verify-shipped-release before updating install-facing docs.
check-release-matrix:
	@./scripts/check-release-matrix.py

check-project-license:
	@python3 scripts/check_project_license.py

third-party-notices:
	@python3 scripts/third_party_notices.py --write

check-third-party-notices:
	@python3 scripts/third_party_notices.py --check

verify-shipped-release: check-versions
	@./scripts/check-release-matrix.py --require-parity

# ============================================================================
# DIRECT PUBLISH (requires local credentials)
# ============================================================================

# Publish all Rust crates to crates.io in dependency order with delays.
# Requires ~/.cargo/credentials or CARGO_REGISTRY_TOKEN.
publish-jacs:
	cd jacs-core && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-core..."
	sleep 30
	cd jacs-media && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-media..."
	sleep 30
	cd jacs && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs..."
	sleep 30
	cd binding-core && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-binding-core..."
	sleep 30
	cd jacs-mcp && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-mcp..."
	sleep 30
	cd jacs-cli && cargo publish --locked

# Individual crate publish targets (use when resuming a partial publish)
publish-jacs-media:
	cd jacs-media && cargo publish --locked

publish-jacs-core:
	cd jacs-core && cargo publish --locked

publish-jacs-binding-core:
	cd binding-core && cargo publish --locked

publish-jacs-mcp:
	cd jacs-mcp && cargo publish --locked

publish-jacs-cli:
	cd jacs-cli && cargo publish --locked

# Publish storage backend crates to crates.io (requires jacs already published).
publish-jacs-storage:
	cd jacs-duckdb && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-duckdb..."
	sleep 30
	cd jacs-redb && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-redb..."
	sleep 30
	cd jacs-surrealdb && cargo publish --locked
	@echo "Waiting 30s for crates.io to index jacs-surrealdb..."
	sleep 30
	cd jacs-postgresql && cargo publish --locked

# Individual storage crate publish targets
publish-jacs-duckdb:
	cd jacs-duckdb && cargo publish --locked

publish-jacs-redb:
	cd jacs-redb && cargo publish --locked

publish-jacs-surrealdb:
	cd jacs-surrealdb && cargo publish --locked

publish-jacs-postgresql:
	cd jacs-postgresql && cargo publish --locked

# Dry run for crates.io publish
publish-jacs-dry:
	cd jacs-core && cargo publish --locked --dry-run
	cd jacs-media && cargo publish --locked --dry-run
	cd jacs && cargo publish --locked --dry-run
	cd binding-core && cargo publish --locked --dry-run
	cd jacs-mcp && cargo publish --locked --dry-run
	cd jacs-cli && cargo publish --locked --dry-run

publish-jacs-storage-dry:
	cd jacs-duckdb && cargo publish --locked --dry-run
	cd jacs-redb && cargo publish --locked --dry-run
	cd jacs-surrealdb && cargo publish --locked --dry-run
	cd jacs-postgresql && cargo publish --locked --dry-run

# Publish to PyPI (requires MATURIN_PYPI_TOKEN or ~/.pypirc)
publish-jacspy:
	cd jacspy && maturin publish

# Dry run for PyPI publish
publish-jacspy-dry:
	cd jacspy && maturin build --locked --release

# Publish to npm directly from a maintainer shell (requires interactive npm login).
# CI tag releases use OIDC trusted publishing instead.
publish-jacsnpm:
	cd jacsnpm && npm publish --access public

# Dry run for npm publish
publish-jacsnpm-dry:
	cd jacsnpm && npm publish --access public --dry-run

# ============================================================================
# GITHUB CI RELEASE (via git tags)
# ============================================================================
# These commands create git tags that trigger GitHub Actions release workflows.
# Versions are auto-detected from source files. Tags are verified before pushing.
#
# Transitional GitHub secret:
#   - CRATES_IO_TOKEN (migration fallback until crates.io OIDC is enabled)
# crates.io, PyPI, and npm trusted-publisher setup is documented in RELEASING.md.
# ============================================================================

# One preflight node separates read-only validation from every tag-writing
# recipe. Consequently `make -j` (including inherited MAKEFLAGS) cannot start a
# release write while any preflight prerequisite is still running.
release-preflight: check-versions check-project-license check-third-party-notices check-release-matrix check-changelog-sealed
	@$(RELEASE_HELPER) check-worktree
	@echo "Release preflight complete."

# Non-destructive, remote-aware plans. These commands apply a deadline and
# print the exact existing tag object/peeled commit when one already exists.
check-version-jacs:
	@$(RELEASE_HELPER) release --surface crate

check-version-jacspy:
	@$(RELEASE_HELPER) release --surface pypi

check-version-jacsnpm:
	@$(RELEASE_HELPER) release --surface npm

check-version-cli:
	@$(RELEASE_HELPER) release --surface cli

check-version-wasm:
	@$(RELEASE_HELPER) release --surface wasm

check-version-jacsgo:
	@$(RELEASE_HELPER) release --surface jacsgo

# Tag and push individual surfaces. The Python helper reads and validates
# manifest versions directly, so no untrusted version text is evaluated by a
# shell. A local-only tag is pushed as-is; a remote-only tag is distinguished
# and left intact; conflicting identities fail closed.
release-jacs: release-preflight
	@$(RELEASE_HELPER) release --surface crate --execute

release-jacspy: release-preflight
	@$(RELEASE_HELPER) release --surface pypi --execute

release-cli: release-preflight
	@$(RELEASE_HELPER) release --surface cli --execute

release-jacsnpm: release-preflight
	@$(RELEASE_HELPER) release --surface npm --execute

release-jacs-wasm: release-preflight
	@$(RELEASE_HELPER) release --surface wasm --execute

release-jacsgo: release-preflight
	@$(RELEASE_HELPER) release --surface jacsgo --execute

# Storage tags are planned as one batch before the first write, then pushed in
# order. Any probe, tag, or push failure stops the helper immediately.
plan-release-jacs-storage: check-versions
	@$(RELEASE_HELPER) release-storage

release-jacs-storage: release-preflight
	@$(RELEASE_HELPER) release-storage --execute

# The helper plans every main and storage tag before its first write. Its fixed
# order puts the CLI tag before npm because the Node package installs that CLI.
plan-release-everything: check-versions
	@$(RELEASE_HELPER) release-all

release-everything: release-preflight # release-all order: release-cli before release-jacsnpm
	@$(RELEASE_HELPER) release-all --execute
	@echo "All release tags pushed."
	@echo "After workflows finish, refresh release/shipped-artifacts.json and run: make verify-shipped-release"

# Destructive maintenance escape hatch. Retry targets never call this because
# deleting the local ref would discard the authoritative original tag identity.
release-delete-tags:
	@echo "Deleting tags for version $(JACS_VERSION)..."
	-git tag -d crate/v$(JACS_VERSION) pypi/v$(JACSPY_VERSION) npm/v$(JACSNPM_VERSION) wasm-v$(JACS_WASM_NPM_VERSION) jacsgo/v$(JACSGO_VERSION) cli/v$(JACS_VERSION)
	-git push origin --delete crate/v$(JACS_VERSION) pypi/v$(JACSPY_VERSION) npm/v$(JACSNPM_VERSION) wasm-v$(JACS_WASM_NPM_VERSION) jacsgo/v$(JACSGO_VERSION) cli/v$(JACS_VERSION)
	@echo "Deleted release tags"

# Retry plans are non-destructive. Execution never deletes the local tag or
# creates a new one: it fetches a remote-only original when necessary, records
# its exact tag object and peeled commit, deletes only the remote ref, then
# re-pushes the unchanged local ref.
plan-retry-jacs: check-versions
	@$(RELEASE_HELPER) retry --surface crate

retry-jacs: check-versions
	@$(RELEASE_HELPER) retry --surface crate --execute

plan-retry-jacspy: check-versions
	@$(RELEASE_HELPER) retry --surface pypi

retry-jacspy: check-versions
	@$(RELEASE_HELPER) retry --surface pypi --execute

plan-retry-jacsnpm: check-versions
	@$(RELEASE_HELPER) retry --surface npm

retry-jacsnpm: check-versions
	@$(RELEASE_HELPER) retry --surface npm --execute

plan-retry-jacs-wasm: check-versions
	@$(RELEASE_HELPER) retry --surface wasm

retry-jacs-wasm: check-versions
	@$(RELEASE_HELPER) retry --surface wasm --execute

plan-retry-cli: check-versions
	@$(RELEASE_HELPER) retry --surface cli

retry-cli: check-versions
	@$(RELEASE_HELPER) retry --surface cli --execute

plan-retry-jacsgo: check-versions
	@$(RELEASE_HELPER) retry --surface jacsgo

retry-jacsgo: check-versions
	@$(RELEASE_HELPER) retry --surface jacsgo --execute

# Smart retry treats only an authoritative registry/API 404 as absent. It
# checks all six Rust crates and cryptographically verifies the exact CLI/Go
# asset inventory and provenance before classifying those releases complete.
plan-retry-everything: check-versions
	@$(RELEASE_HELPER) retry-everything

retry-everything: check-versions
	@$(RELEASE_HELPER) retry-everything --execute

# ============================================================================
# HELP
# ============================================================================

help:
	@echo "JACS Makefile Commands"
	@echo ""
	@echo "VERSION BUMP:"
	@echo "  make bump-patch      Bump patch version (0.9.6 -> 0.9.7) across all files"
	@echo "  make bump-minor      Bump minor version (0.9.6 -> 0.10.0) across all files"
	@echo "  make bump-major      Bump major version (0.9.6 -> 1.0.0) across all files"
	@echo "  make seal-changelog  Flip CHANGELOG.md (unreleased) -> Released YYYY-MM-DD for current version"
	@echo "  make check-changelog-sealed  Fail if current version still marked (unreleased)"
	@echo ""
	@echo "VERSION INFO:"
	@echo "  make versions        Show all detected versions from source files"
	@echo "  make check-versions  Verify all package versions match"
	@echo "  make third-party-notices  Regenerate Cargo dependency notices and crate copies"
	@echo "  make check-third-party-notices  Fail if Cargo dependency notices are stale"
	@echo "  make check-release-matrix  Validate checked-in shipped-artifact evidence"
	@echo "  make verify-shipped-release  Require public Rust/CLI/Python/Node/WASM parity"
	@echo ""
	@echo "BUILD:"
	@echo "  make build-jacs      Build and install Rust CLI"
	@echo "  make build-jacspy    Build Python bindings (dev mode)"
	@echo "  make build-jacsnpm   Build Node.js bindings"
	@echo "  make build-jacsbook  Generate jacsbook (mdbook build)"
	@echo "  make build-jacsbook-pdf  Generate single PDF book at docs/jacsbook.pdf"
	@echo ""
	@echo "TEST:"
	@echo "  make test                Run Rust library tests (alias for test-jacs)"
	@echo "  make test-all            Run the default fast PR suite"
	@echo "  make test-all-pq         Run the extended suite (slow Rust lanes + post-quantum)"
	@echo "  make test-rust-pr        Run the default fast Rust lanes"
	@echo "  make test-bindings-fast  Run Python and Node bindings with their parallel runners"
	@echo "  make test-rust-slow      Run storage, cross-language, and observability suites"
	@echo "  make test-jacs           Run Rust library tests"
	@echo "  make test-jacs-fast      Run Rust tests with features, ed25519 only (fast)"
	@echo "  make test-jacs-pq        Run Rust tests with features + post-quantum tests"
	@echo "  make test-jacs-features  Alias for test-jacs-pq (full coverage)"
	@echo "  make test-jacs-cli       Run CLI integration tests"
	@echo "  make test-jacs-cross-language Run Rust cross-language and fixture-interop tests"
	@echo "  make test-jacs-mcp       Run MCP server tests"
	@echo "  make test-jacs-binding-core     Run binding-core tests (ed25519)"
	@echo "  make test-jacs-binding-core-pq  Run binding-core tests (+ post-quantum)"
	@echo "  make test-jacs-wasm      Run jacs-wasm native sanity tests (agreement v2 + drift)"
	@echo "  make test-jacs-storage   Run all storage backend tests (duckdb, redb, surrealdb, postgresql)"
	@echo "  make test-jacs-duckdb    Run DuckDB storage tests"
	@echo "  make test-jacs-redb      Run Redb storage tests"
	@echo "  make test-jacs-surrealdb Run SurrealDB storage tests"
	@echo "  make test-jacs-postgresql Run PostgreSQL storage tests"
	@echo "  make test-jacs-observability Run observability tests"
	@echo "  make audit-jacs          Run cargo-audit (required security gate)"
	@echo "  make test-jacspy         Run Python binding tests"
	@echo "  make test-jacsnpm        Run Node.js binding tests"
	@echo "  make regen-cross-lang-fixtures  Regenerate Rust->Python->Node fixtures"
	@echo ""
	@echo "GIT HOOKS:"
	@echo "  make install-githooks  Configure core.hooksPath=.githooks"
	@echo ""
	@echo "DIRECT PUBLISH (local credentials required):"
	@echo "  make publish-jacs              Publish all Rust crates in dependency order"
	@echo "  make publish-jacs-core         Publish jacs core only"
	@echo "  make publish-jacs-binding-core Publish jacs-binding-core only"
	@echo "  make publish-jacs-mcp          Publish jacs-mcp only"
	@echo "  make publish-jacs-cli          Publish jacs-cli only"
	@echo "  make publish-jacs-dry          Dry run crates.io publish"
	@echo "  make publish-jacspy      Publish to PyPI"
	@echo "  make publish-jacspy-dry  Dry run PyPI publish"
	@echo "  make publish-jacsnpm     Publish to npm"
	@echo "  make publish-jacsnpm-dry Dry run npm publish"
	@echo ""
	@echo "GITHUB CI RELEASE (via git tags - versions auto-detected):"
	@echo "  make release-jacs    Tag crate/v<version> -> triggers crates.io release"
	@echo "  make release-jacspy  Tag pypi/v<version> -> triggers PyPI release"
	@echo "  make release-jacsnpm Tag npm/v<version> -> triggers npm release"
	@echo "  make release-cli     Tag cli/v<version> -> triggers CLI binary release"
	@echo "  make plan-release-everything  Read-only local/remote plan for every release tag"
	@echo "  make release-everything  Release crates/PyPI/Node/WASM/Go + CLI + storage crates"
	@echo "  make release-delete-tags  DESTRUCTIVE maintenance only; never needed for retry"
	@echo "  make plan-retry-<surface>  Read-only retry plan with exact original tag identity"
	@echo "  make retry-jacs      Re-push the exact original crates.io release tag"
	@echo "  make retry-jacspy    Re-push the exact original PyPI release tag"
	@echo "  make retry-jacsnpm   Re-push the exact original npm release tag"
	@echo "  make retry-jacs-wasm Re-push the exact original WASM release tag"
	@echo "  make retry-cli       Re-push the exact original CLI release tag"
	@echo "  make retry-jacsgo    Re-push the exact original Go release tag"
	@echo "  make plan-retry-everything  Read-only exact-version registry/provenance plan"
	@echo "  make retry-everything  Fail-closed smart retry for authoritatively absent releases"
	@echo ""
	@echo "Required GitHub Secrets:"
	@echo "  CRATES_IO_TOKEN  - migration fallback until crates.io OIDC is enabled"
	@echo "  crates.io, PyPI and npm prefer OIDC trusted publishers (see RELEASING.md)"

# ============================================================================
# DISK MAINTENANCE — Rust target/ + cargo cache hygiene
# ============================================================================
# With .cargo/config.toml's target-dir set, every cargo invocation across
# the workspace + nested crates writes into ./target. These targets prune
# stale artifacts and inspect usage. Recommended cadence:
#   make disk-usage         # anytime, read-only
#   make disk-sweep         # weekly — drops artifacts older than 14 days
#   make disk-clean-light   # monthly — keeps release/
#   make disk-clean-deep    # reclaim disk; forces full rebuild
JACS_TREE := $(CURDIR)
JACS_TARGET_DIR := $(JACS_TREE)/target

.PHONY: disk-usage disk-clean-deep disk-clean-light disk-sweep install-disk-tools

disk-usage: ## Show every Rust target/ in the JACS tree (read-only)
	@find $(JACS_TREE) -type d -name target \
	    -not -path "*/node_modules/*" -not -path "*/.venv*" \
	    -prune -exec du -sh {} + 2>/dev/null | sort -hr

disk-clean-deep: ## cargo clean the workspace (cleans every member crate)
	@if [ -d $(JACS_TARGET_DIR) ]; then \
	  cd $(JACS_TREE) && cargo clean --workspace; \
	else \
	  echo "No target dir at $(JACS_TARGET_DIR) — nothing to clean."; \
	fi

disk-clean-light: ## Drop debug/{incremental,deps,build}; keep release/
	@if [ -d $(JACS_TARGET_DIR)/debug ]; then \
	  rm -rf $(JACS_TARGET_DIR)/debug/incremental \
	         $(JACS_TARGET_DIR)/debug/deps \
	         $(JACS_TARGET_DIR)/debug/build; \
	  echo "Cleaned $(JACS_TARGET_DIR)/debug/{incremental,deps,build}"; \
	else \
	  echo "No debug/ under $(JACS_TARGET_DIR) — nothing to clean."; \
	fi

disk-sweep: install-disk-tools ## Prune artifacts >14 days + autoclean cargo registry
	@if [ -d $(JACS_TARGET_DIR) ]; then \
	  cd $(JACS_TREE) && cargo sweep --time 14; \
	else \
	  echo "No target dir at $(JACS_TARGET_DIR) — nothing to sweep."; \
	fi
	cargo cache --autoclean

install-disk-tools:
	@command -v cargo-sweep >/dev/null 2>&1 || cargo install cargo-sweep
	@command -v cargo-cache >/dev/null 2>&1 || cargo install cargo-cache
