# Optional developer entry points. The native workspace stays separate.
NATIVE_MANIFEST := $(CURDIR)/archive/native/Cargo.toml
NATIVE_TEST := cargo test --locked --manifest-path "$(NATIVE_MANIFEST)"
NATIVE_FEATURES := agreements,a2a,attestation
NATIVE_TEST_BINS := $(basename $(notdir $(wildcard archive/native/jacs/tests/*.rs)))
NATIVE_FAST_BINS := $(filter-out a2a_cross_language_tests attestation_cross_lang_tests cli_flags cli_tests cross_language_tests observability_oltp_meter observability_tests pq2025_tests pq_tests,$(NATIVE_TEST_BINS))
NATIVE_SHARD_A := $(filter a% b% c% d%,$(NATIVE_FAST_BINS))
NATIVE_SHARD_B := $(filter-out $(NATIVE_SHARD_A),$(NATIVE_FAST_BINS))

.PHONY: build-jacs build-jacs-compat mcp-compat build-wasm test-wasm build-jacsbook build-native-jacsbook build-jacsbook-pdf
.PHONY: test-jacs test-jacs-fast test-jacs-fast-lib test-jacs-fast-bin-shard-a test-jacs-fast-bin-shard-b test-jacs-secure-fetch test-jacs-pq test-jacs-features test-jacs-cross-language test-jacs-observability test-jacs-binding-core test-jacs-binding-core-pq test-jacs-mcp-compat test-jacs-cli-compat
.PHONY: test-jacs-duckdb test-jacs-redb test-jacs-postgresql test-jacs-surrealdb test-jacs-storage test-rust-pr test-rust-slow test-all-pq test-bindings-fast test-jacspy-parallel test-jacsnpm-parallel
.PHONY: audit-jacs install-githooks seal-changelog check-changelog-sealed sync-schemas regen-cross-lang-fixtures smoke-verifiers verify-shipped-release disk-usage homebrew-formula

build-jacs: build

build-jacs-compat:
	cargo build --locked --manifest-path "$(NATIVE_MANIFEST)" -p jacs-cli-compat

# No Make chatter on stdout: this command is an MCP stdio transport.
# Explicit local signing uses JACS_MCP_PROFILE=local-sign and JACS_CONFIG.
mcp-compat:
	@cargo run --quiet --locked --manifest-path "$(NATIVE_MANIFEST)" -p jacs-cli-compat -- mcp

build-wasm:
	cd jacs-wasm && wasm-pack build --target web --release . --locked
	bash jacs-wasm/scripts/finalize-pkg.sh

test-wasm:
	cd jacs-wasm && wasm-pack test --headless --chrome . --locked

build-jacsbook:
	python3 scripts/build-docs.py

build-native-jacsbook:
	python3 scripts/build-docs.py --native-only

build-jacsbook-pdf: build-jacsbook
	playwright pdf --browser chromium --paper-format Letter "file://$(CURDIR)/target/jacsbook/print.html" "$(CURDIR)/target/jacsbook.pdf"

test-jacs:
	$(NATIVE_TEST) -p jacs --lib --tests

test-jacs-fast: test-jacs-fast-lib test-jacs-fast-bin-shard-a test-jacs-fast-bin-shard-b

test-jacs-fast-lib:
	$(NATIVE_TEST) -p jacs --features $(NATIVE_FEATURES) --lib -- --skip secure_fetch::tests
	$(MAKE) test-jacs-secure-fetch

test-jacs-fast-bin-shard-a:
	$(NATIVE_TEST) -p jacs --features $(NATIVE_FEATURES) $(foreach test,$(NATIVE_SHARD_A),--test $(test))

test-jacs-fast-bin-shard-b:
	$(NATIVE_TEST) -p jacs --features $(NATIVE_FEATURES) $(foreach test,$(NATIVE_SHARD_B),--test $(test))

test-jacs-secure-fetch:
	$(NATIVE_TEST) -p jacs --features $(NATIVE_FEATURES) --lib secure_fetch::tests -- --test-threads=1

test-jacs-pq:
	$(NATIVE_TEST) -p jacs --features $(NATIVE_FEATURES),pq-tests --lib --tests -- --skip secure_fetch::tests
	$(MAKE) test-jacs-secure-fetch

test-jacs-features: test-jacs-pq

test-jacs-cross-language:
	$(NATIVE_TEST) -p jacs --features $(NATIVE_FEATURES) --test cross_language_tests --test a2a_cross_language_tests --test attestation_cross_lang_tests

test-jacs-observability:
	$(NATIVE_TEST) -p jacs --features otlp-logs,otlp-metrics,otlp-tracing,agreements --test observability_tests --test observability_oltp_meter --test compatibility_observability --test security_observability

test-jacs-binding-core:
	$(NATIVE_TEST) -p jacs-binding-core --features agreements --lib --tests

test-jacs-binding-core-pq:
	$(NATIVE_TEST) -p jacs-binding-core --features agreements,pq-tests --lib --tests

test-jacs-mcp-compat:
	$(NATIVE_TEST) -p jacs-mcp-compat --features full-tools --lib --tests

test-jacs-cli-compat:
	$(NATIVE_TEST) -p jacs-cli-compat --lib --tests

test-jacs-duckdb test-jacs-redb test-jacs-postgresql:
	$(NATIVE_TEST) -p $(patsubst test-%,%,$@) --lib --tests

test-jacs-surrealdb:
	cargo test --locked --manifest-path archive/native/jacs-surrealdb/Cargo.toml --lib --tests

test-jacs-storage: test-jacs-duckdb test-jacs-redb test-jacs-surrealdb test-jacs-postgresql
test-rust-pr: test-all test-jacs-fast test-jacs-binding-core test-jacs-mcp-compat test-jacs-cli-compat
test-rust-slow: test-jacs-storage test-jacs-cross-language test-jacs-observability
test-all-pq: test-rust-pr test-rust-slow test-bindings test-jacs-pq test-jacs-binding-core-pq
test-bindings-fast: test-jacspy-parallel test-jacsnpm-parallel

test-jacspy-parallel:
	$(MAKE) -C archive/native/jacspy test-python-parallel

test-jacsnpm-parallel:
	cd archive/native/jacsnpm && npm run test:parallel

audit-jacs:
	cargo audit
	cd archive/native && cargo audit
	cargo audit --file archive/native/jacs-surrealdb/Cargo.lock

install-githooks:
	git config core.hooksPath .githooks

seal-changelog check-changelog-sealed:
	@python3 -c 'import subprocess,tomllib; v=tomllib.load(open("jacs-core/Cargo.toml","rb"))["package"]["version"]; subprocess.run(["bash","scripts/seal-changelog.sh","$(if $(filter seal-changelog,$@),seal,check)",v],check=True)'

sync-schemas:
	diff -r archive/native/jacs/schemas jacs-core/schemas

regen-cross-lang-fixtures:
	UPDATE_CROSS_LANG_FIXTURES=1 $(NATIVE_TEST) -p jacs --test cross_language_tests
	cd archive/native/jacspy && UPDATE_CROSS_LANG_FIXTURES=1 python3 -m pytest tests/test_cross_language.py -q
	cd archive/native/jacsnpm && UPDATE_CROSS_LANG_FIXTURES=1 npm run test:cross-language --silent

smoke-verifiers: build
	@target=$$(cargo metadata --no-deps --format-version 1 | python3 -c 'import json,sys; print(json.load(sys.stdin)["target_directory"])'); python3 scripts/smoke-portable-cli.py --binary "$$target/debug/jacs"

verify-shipped-release: check-versions
	python3 scripts/check-release-matrix.py --online --require-parity
	python3 scripts/verify_github_release_attestations.py --matrix release/shipped-artifacts.json
	python3 scripts/verify_recorded_registry_provenance.py release/shipped-artifacts.json

disk-usage:
	df -h . "$${CARGO_HOME:-$$HOME/.cargo}"
	@for output in target archive/native/target archive/native/jacs-surrealdb/target; do if test -d "$$output"; then du -sh "$$output"; fi; done

homebrew-formula:
	python3 scripts/homebrew_release.py --version "$(VERSION)" --source-commit "$(SOURCE_COMMIT)"
