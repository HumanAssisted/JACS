.PHONY: build-jacs build-jacsbook build-jacsbook-pdf test test-jacs audit-jacs test-jacs-cli test-jacs-observability test-jacspy test-jacspy-parallel test-jacsnpm test-jacsnpm-parallel \
        publish-jacs publish-jacspy publish-jacsnpm \
        release-jacs release-jacspy release-jacsnpm release-cli release-all release-everything release-delete-tags \
        retry-jacspy retry-jacsnpm retry-cli \
        version versions check-versions check-version-jacs check-version-jacspy check-version-jacsnpm check-version-cli \
        install-githooks regen-cross-lang-fixtures \
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

# ============================================================================
# BUILD
# ============================================================================

build-jacs:
	cd jacs && cargo install --path . --force --features cli
	~/.cargo/bin/jacs --help
	~/.cargo/bin/jacs version

build-jacspy:
	cd jacspy && maturin develop

build-jacsnpm:
	cd jacsnpm && npm run build

build-jacsbook:
	cd jacs/docs/jacsbook && mdbook build

build-jacsbook-pdf:
	./jacs/docs/jacsbook/scripts/build-pdf.sh

# ============================================================================
# TEST
# ============================================================================

test-jacs:
	cd jacs && RUST_BACKTRACE=1 cargo test --features cli -- --nocapture

audit-jacs:
	@command -v cargo-audit >/dev/null 2>&1 || (echo "cargo-audit is required. Install with: cargo install cargo-audit --locked --version 0.22.1"; exit 1)
	cargo audit --ignore RUSTSEC-2023-0071

test-jacs-cli:
	cd jacs && RUST_BACKTRACE=1 cargo test --features cli --test cli_tests -- --nocapture

test-jacs-observability:
	RUST_BACKTRACE=1 cargo test --features "cli observability-convenience otlp-logs otlp-metrics otlp-tracing" --test observability_tests --test observability_oltp_meter -- --nocapture

test-jacspy:
	cd jacspy && maturin develop && python -m pytest tests/ -v

test-jacspy-parallel:
	cd jacspy && PYTEST_XDIST_WORKERS=$${PYTEST_XDIST_WORKERS:-auto} make test-python-parallel

test-jacsnpm:
	cd jacsnpm && npm test

test-jacsnpm-parallel:
	cd jacsnpm && npm run test:parallel

test: test-jacs

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

# Show all detected versions
versions:
	@echo "Detected versions from source files:"
	@echo "  jacs (Cargo.toml):        $(JACS_VERSION)"
	@echo "  jacs-mcp (Cargo.toml):    $(JACS_MCP_VERSION)"
	@echo "  binding-core (Cargo.toml):$(BINDING_CORE_VERSION)"
	@echo "  jacspy (pyproject.toml):  $(JACSPY_VERSION)"
	@echo "  jacspy (Cargo.toml):      $(JACSPY_RUST_VERSION)"
	@echo "  jacsnpm (package.json):   $(JACSNPM_VERSION)"
	@echo "  jacsnpm (Cargo.toml):     $(JACSNPM_RUST_VERSION)"
	@echo "  jacsgo/lib (Cargo.toml):  $(JACSGO_VERSION)"
	@echo ""
	@if [ "$(JACS_VERSION)" = "$(JACS_MCP_VERSION)" ] && \
		[ "$(JACS_VERSION)" = "$(BINDING_CORE_VERSION)" ] && \
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

# ============================================================================
# DIRECT PUBLISH (requires local credentials)
# ============================================================================

# Publish to crates.io (requires ~/.cargo/credentials or CARGO_REGISTRY_TOKEN)
# Publishes jacs, jacs-mcp, and jacs-cli in order with delays for crates.io indexing.
publish-jacs:
	cd jacs && cargo publish
	@echo "Waiting 30s for crates.io to index jacs..."
	sleep 30
	cd jacs-mcp && cargo publish
	@echo "Waiting 30s for crates.io to index jacs-mcp..."
	sleep 30
	cd jacs-cli && cargo publish

# Dry run for crates.io publish
publish-jacs-dry:
	cd jacs && cargo publish --dry-run
	cd jacs-mcp && cargo publish --dry-run
	cd jacs-cli && cargo publish --dry-run

# Publish to PyPI (requires MATURIN_PYPI_TOKEN or ~/.pypirc)
publish-jacspy:
	cd jacspy && maturin publish

# Dry run for PyPI publish
publish-jacspy-dry:
	cd jacspy && maturin build --release

# Publish to npm (requires npm login or NPM_TOKEN)
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
# Required GitHub Secrets:
#   - CRATES_IO_TOKEN  (for crate/v* tags)
#   - PYPI_API_TOKEN   (for pypi/v* tags)
#   - NPM_TOKEN        (for npm/v* tags)
# ============================================================================

# Verify version and tag for crates.io release
check-version-jacs:
	@echo "jacs version: $(JACS_VERSION)"
	@if git tag -l | grep -q "^crate/v$(JACS_VERSION)$$"; then \
		echo "ERROR: Tag crate/v$(JACS_VERSION) already exists"; \
		exit 1; \
	fi
	@echo "✓ Tag crate/v$(JACS_VERSION) is available"

# Verify version and tag for PyPI release
check-version-jacspy:
	@echo "jacspy version: $(JACSPY_VERSION)"
	@if git tag -l | grep -q "^pypi/v$(JACSPY_VERSION)$$"; then \
		echo "ERROR: Tag pypi/v$(JACSPY_VERSION) already exists"; \
		exit 1; \
	fi
	@echo "✓ Tag pypi/v$(JACSPY_VERSION) is available"

# Verify version and tag for npm release
check-version-jacsnpm:
	@echo "jacsnpm version: $(JACSNPM_VERSION)"
	@if git tag -l | grep -q "^npm/v$(JACSNPM_VERSION)$$"; then \
		echo "ERROR: Tag npm/v$(JACSNPM_VERSION) already exists"; \
		exit 1; \
	fi
	@echo "✓ Tag npm/v$(JACSNPM_VERSION) is available"

# Verify version and tag for CLI binary release
check-version-cli:
	@echo "cli version: $(JACS_VERSION)"
	@if [ "$(JACS_VERSION)" != "$(JACS_MCP_VERSION)" ]; then \
		echo "ERROR: jacs ($(JACS_VERSION)) != jacs-mcp ($(JACS_MCP_VERSION))"; \
		exit 1; \
	fi
	@if git tag -l | grep -q "^cli/v$(JACS_VERSION)$$"; then \
		echo "ERROR: Tag cli/v$(JACS_VERSION) already exists"; \
		exit 1; \
	fi
	@echo "✓ Tag cli/v$(JACS_VERSION) is available"

# Tag and push to trigger crates.io release via GitHub CI
release-jacs: check-version-jacs
	git tag crate/v$(JACS_VERSION)
	git push origin crate/v$(JACS_VERSION)
	@echo "Tagged crate/v$(JACS_VERSION) - GitHub CI will publish to crates.io"

# Tag and push to trigger PyPI release via GitHub CI
release-jacspy: check-version-jacspy
	git tag pypi/v$(JACSPY_VERSION)
	git push origin pypi/v$(JACSPY_VERSION)
	@echo "Tagged pypi/v$(JACSPY_VERSION) - GitHub CI will publish to PyPI"

# Tag and push to trigger npm release via GitHub CI
release-jacsnpm: check-version-jacsnpm
	git tag npm/v$(JACSNPM_VERSION)
	git push origin npm/v$(JACSNPM_VERSION)
	@echo "Tagged npm/v$(JACSNPM_VERSION) - GitHub CI will publish to npm"

# Tag and push to trigger CLI binary release via GitHub CI
release-cli: check-version-cli
	git tag cli/v$(JACS_VERSION)
	git push origin cli/v$(JACS_VERSION)
	@echo "Tagged cli/v$(JACS_VERSION) - GitHub CI will publish GitHub release binaries"

# Release all packages via GitHub CI (verifies all versions match first)
release-all: check-versions release-jacs release-jacspy release-jacsnpm
	@echo "All release tags pushed for v$(JACS_VERSION). GitHub CI will handle publishing."

# Release all packages plus CLI binaries via GitHub CI
release-everything: release-all release-cli
	@echo "All release tags, including CLI binaries, pushed for v$(JACS_VERSION)."

# Delete release tags for current versions (use with caution - for fixing failed releases)
release-delete-tags:
	@echo "Deleting tags for version $(JACS_VERSION)..."
	-git tag -d crate/v$(JACS_VERSION) pypi/v$(JACSPY_VERSION) npm/v$(JACSNPM_VERSION) cli/v$(JACS_VERSION)
	-git push origin --delete crate/v$(JACS_VERSION) pypi/v$(JACSPY_VERSION) npm/v$(JACSNPM_VERSION) cli/v$(JACS_VERSION)
	@echo "Deleted release tags"

# Retry a failed PyPI release: delete old tags (local+remote), retag, push
retry-jacspy:
	@echo "Retrying PyPI release for v$(JACSPY_VERSION)..."
	-git tag -d pypi/v$(JACSPY_VERSION)
	-git push origin --delete pypi/v$(JACSPY_VERSION)
	git tag pypi/v$(JACSPY_VERSION)
	git push origin pypi/v$(JACSPY_VERSION)
	@echo "✓ Re-tagged pypi/v$(JACSPY_VERSION) - GitHub CI will retry PyPI publish"

# Retry a failed npm release: delete old tags (local+remote), retag, push
retry-jacsnpm:
	@echo "Retrying npm release for v$(JACSNPM_VERSION)..."
	-git tag -d npm/v$(JACSNPM_VERSION)
	-git push origin --delete npm/v$(JACSNPM_VERSION)
	git tag npm/v$(JACSNPM_VERSION)
	git push origin npm/v$(JACSNPM_VERSION)
	@echo "✓ Re-tagged npm/v$(JACSNPM_VERSION) - GitHub CI will retry npm publish"

# Retry a failed CLI release: delete old tags (local+remote), retag, push
retry-cli:
	@echo "Retrying CLI release for v$(JACS_VERSION)..."
	-git tag -d cli/v$(JACS_VERSION)
	-git push origin --delete cli/v$(JACS_VERSION)
	git tag cli/v$(JACS_VERSION)
	git push origin cli/v$(JACS_VERSION)
	@echo "✓ Re-tagged cli/v$(JACS_VERSION) - GitHub CI will retry CLI binary release"

# ============================================================================
# HELP
# ============================================================================

help:
	@echo "JACS Makefile Commands"
	@echo ""
	@echo "VERSION INFO:"
	@echo "  make versions        Show all detected versions from source files"
	@echo "  make check-versions  Verify all package versions match"
	@echo ""
	@echo "BUILD:"
	@echo "  make build-jacs      Build and install Rust CLI"
	@echo "  make build-jacspy    Build Python bindings (dev mode)"
	@echo "  make build-jacsnpm   Build Node.js bindings"
	@echo "  make build-jacsbook  Generate jacsbook (mdbook build)"
	@echo "  make build-jacsbook-pdf  Generate single PDF book at docs/jacsbook.pdf"
	@echo ""
	@echo "TEST:"
	@echo "  make test            Run all tests (alias for test-jacs)"
	@echo "  make test-jacs       Run Rust library tests"
	@echo "  make audit-jacs      Run cargo-audit (required security gate)"
	@echo "  make test-jacs-cli   Run CLI integration tests"
	@echo "  make test-jacspy     Run Python binding tests"
	@echo "  make test-jacsnpm    Run Node.js binding tests"
	@echo "  make regen-cross-lang-fixtures  Regenerate Rust->Python->Node fixtures"
	@echo ""
	@echo "GIT HOOKS:"
	@echo "  make install-githooks  Configure core.hooksPath=.githooks"
	@echo ""
	@echo "DIRECT PUBLISH (local credentials required):"
	@echo "  make publish-jacs        Publish to crates.io"
	@echo "  make publish-jacs-dry    Dry run crates.io publish"
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
	@echo "  make release-all     Verify versions match, then release crates/PyPI/npm"
	@echo "  make release-everything  Verify versions match, then release crates/PyPI/npm/CLI"
	@echo "  make release-delete-tags  Delete release tags (for fixing failed releases)"
	@echo "  make retry-jacspy    Retry failed PyPI release (delete tags, retag, push)"
	@echo "  make retry-jacsnpm   Retry failed npm release (delete tags, retag, push)"
	@echo "  make retry-cli       Retry failed CLI release (delete tags, retag, push)"
	@echo ""
	@echo "Required GitHub Secrets:"
	@echo "  CRATES_IO_TOKEN  - for crate/v* tags"
	@echo "  PYPI_API_TOKEN   - for pypi/v* tags"
	@echo "  NPM_TOKEN        - for npm/v* tags"
