# Active portable workspace. Historical targets remain in archive/native/Makefile.
.PHONY: help test test-all test-jacs-core test-jacs-cli test-jacs-mcp test-jacs-wasm build check check-versions check-release-matrix check-project-license check-third-party-notices third-party-notices release-preflight plan-release-everything

help:
	@echo 'make build | test | check | third-party-notices | plan-release-everything'

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

# Read-only planning only. Explicit execution uses the checked release helper.
release-preflight: check
	python3 scripts/release_retry.py check-worktree

plan-release-everything: check-versions
	python3 scripts/release_retry.py release-all
