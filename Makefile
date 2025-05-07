.PHONY:  build-jacs test

 
build-jacs:
	cd jacs && cargo install --path . --force
	~/.cargo/bin/jacs --help 
	~/.cargo/bin/jacs version

test-jacs:
	cd jacs && RUST_BACKTRACE=1 cargo test  -- --nocapture

test-jacs-cli:
	cd jacs && RUST_BACKTRACE=1 cargo test --test cli_tests  -- --nocapture



publish-jacs:
	cargo publish --dry-run -p jacs


test: test-jacs test-jacspy
#   --test agent_tests --test document_tests --test key_tests --test task_tests --test agreement_test  --test create_agent_test
	
	 