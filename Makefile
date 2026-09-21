# Active portable workspace. Historical targets remain in archive/native/Makefile.
.PHONY: help test test-all test-jacs-core test-jacs-cli test-jacs-mcp test-jacs-wasm build check check-versions check-release-matrix check-project-license check-third-party-notices third-party-notices release-preflight plan-release-everything
.PHONY: rust-cache-preview rust-cache-setup rust-cache-status rust-cache-smoke
.PHONY: bump-patch bump-minor bump-major plan-bump-patch plan-bump-minor plan-bump-major
.PHONY: plan-release-jacs plan-release-cli plan-release-jacs-wasm release-jacs release-cli release-jacs-wasm release-everything
.PHONY: plan-retry-jacs plan-retry-cli plan-retry-jacs-wasm plan-retry-everything retry-jacs retry-cli retry-jacs-wasm retry-everything

help:
	@echo 'make build | test | check | third-party-notices | plan-release-everything'
	@echo 'make plan-bump-patch | plan-bump-minor | plan-bump-major  Preview a version bump'
	@echo 'make bump-patch | bump-minor | bump-major                 Apply one version bump'
	@echo 'make plan-release-jacs | plan-release-cli | plan-release-jacs-wasm | plan-release-everything'
	@echo 'make release-jacs       Publish jacs-core, jacs-mcp and jacs-cli via CI'
	@echo 'make release-cli        Publish CLI binaries via CI'
	@echo 'make release-jacs-wasm  Publish @jacs/wasm via CI (npm publisher setup required)'
	@echo 'make release-everything Run all three active release workflows after preflight'
	@echo 'make plan-retry-jacs | plan-retry-cli | plan-retry-jacs-wasm | plan-retry-everything'
	@echo 'make retry-jacs | retry-cli | retry-jacs-wasm | retry-everything  Retry original tags'
	@echo 'Archived native npm, Python, Go and jacs-wasm crates.io publication are disabled.'
	@echo 'make rust-cache-preview  Preview shared Rust cache setup (no changes)'
	@echo 'make rust-cache-setup    Configure kache once per user/Cargo home'
	@echo 'make rust-cache-status   Show shared cache usage and hits'
	@echo 'make rust-cache-smoke    Check reuse, invalidation and bypass offline'

rust-cache-preview:
	@python3 scripts/rust-cache.py

rust-cache-setup:
	@python3 scripts/rust-cache.py --apply

rust-cache-status:
	@kache stats

rust-cache-smoke:
	@python3 scripts/rust-cache-smoke.py

build:
	cargo build --locked -p jacs-cli

test test-all:
	cargo test --locked --workspace

test-jacs-core:
	cargo test --locked -p jacs-core

test-jacs-cli:
	cargo test --locked -p jacs-cli

test-jacs-mcp:
	cargo test --locked -p jacs-mcp

test-jacs-wasm:
	cargo test --locked -p jacs-wasm --test native_sanity

check: check-versions check-project-license check-third-party-notices
	python3 scripts/check_workspace_boundary.py
	bash scripts/check-action-pins.sh
	python3 scripts/check-security-exceptions.py
	python3 -m unittest discover -s scripts/tests -p 'test_*.py'

check-versions check-release-matrix:
	python3 scripts/check-release-matrix.py

check-project-license:
	python3 scripts/check_project_license.py

check-third-party-notices:
	python3 scripts/third_party_notices.py --check

third-party-notices:
	python3 scripts/third_party_notices.py --write

# Bump one coordinated source version; previews validate without writing files.
plan-bump-patch plan-bump-minor plan-bump-major:
	@bash scripts/bump-version.sh $(patsubst plan-bump-%,%,$@) --check

bump-patch bump-minor bump-major:
	@bash scripts/bump-version.sh $(patsubst bump-%,%,$@)

# Plans are read-only. Release targets run preflight before the checked helper.
release-preflight: check
	python3 scripts/release_retry.py check-worktree

plan-release-jacs: check-versions
	python3 scripts/release_retry.py release --surface crate

plan-release-cli: check-versions
	python3 scripts/release_retry.py release --surface cli

plan-release-jacs-wasm: check-versions
	python3 scripts/release_retry.py release --surface wasm

plan-release-everything: check-versions
	python3 scripts/release_retry.py release-all

release-jacs: release-preflight
	python3 scripts/release_retry.py release --surface crate --execute

release-cli: release-preflight
	python3 scripts/release_retry.py release --surface cli --execute

release-jacs-wasm: release-preflight
	python3 scripts/release_retry.py release --surface wasm --execute

release-everything: release-preflight
	python3 scripts/release_retry.py release-all --execute

# Retry the original immutable tag, which may precede the current worktree.
plan-retry-jacs: check-versions
	python3 scripts/release_retry.py retry --surface crate

plan-retry-cli: check-versions
	python3 scripts/release_retry.py retry --surface cli

plan-retry-jacs-wasm: check-versions
	python3 scripts/release_retry.py retry --surface wasm

plan-retry-everything: check-versions
	python3 scripts/release_retry.py retry-everything

retry-jacs: check-versions
	python3 scripts/release_retry.py retry --surface crate --execute

retry-cli: check-versions
	python3 scripts/release_retry.py retry --surface cli --execute

retry-jacs-wasm: check-versions
	python3 scripts/release_retry.py retry --surface wasm --execute

retry-everything: check-versions
	python3 scripts/release_retry.py retry-everything --execute
