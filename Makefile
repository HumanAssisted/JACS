.PHONY:  build-jacs test

 
build-jacs:
	cd jacs && cargo install --path . --force  --features cli 
	~/.cargo/bin/jacs --help 
	~/.cargo/bin/jacs version

test-jacs:
	cd jacs && RUST_BACKTRACE=1 cargo test --features cli   -- --nocapture

test-jacs-cli:
	cd jacs && RUST_BACKTRACE=1 cargo test --features cli  --test cli_tests  -- --nocapture

test-jacs-observability:
	RUST_BACKTRACE=1 cargo test --features "cli observability-convenience otlp-logs otlp-metrics otlp-tracing" --test observability_tests --test observability_oltp_meter -- --nocapture

publish-jacs:
	cargo publish --features cli  --dry-run -p jacs


test: test-jacs test-jacspy
#   --test agent_tests --test document_tests --test key_tests --test task_tests --test agreement_test  --test create_agent_test
	
	 