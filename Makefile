.PHONY: build-jacspy build-jacspy-mac build-jacspy-linux build-jacs test

build-jacspy: build-jacspy-mac build-jacspy-linux

build-jacspy-mac:
	$(info PYTHON_INCLUDE: $(PYTHON_INCLUDE))
	$(info PYTHON_LIB: $(PYTHON_LIB))
	echo $(PYTHON_INCLUDE)
	echo $(PYTHON_LIB)
	cd jacspy && env PYTHON_INCLUDE=$(PYTHON_INCLUDE) PYTHON_LIB=$(PYTHON_LIB) cargo build --release
	cp target/release/libjacspy.dylib jacspy/jacspy.so

build-jacspy-linux:
	docker pull python:3.11-bookworm
	docker buildx build --tag "jacs-build" -f ./jacspy/Dockerfile . ;\
	docker  run --rm -v "$(PWD)/jacspy/linux:/output" jacs-build cp /usr/src/jacspy/target/release/libjacspy.so /output/jacspy.so;

build-jacs:
	cd jacs && cargo install --path . --force
	/Users/jonathan.hendler/.cargo/bin/jacs --help 
	/Users/jonathan.hendler/.cargo/bin/jacs version

test-jacs:
	cd jacs && RUST_BACKTRACE=1 cargo test  -- --nocapture

test-jacspy:
	cd jacspy && cargo test  -- --nocapture

test: test-jacs test-jacspy
#   --test agent_tests --test document_tests --test key_tests --test task_tests --test agreement_test  --test create_agent_test
	
	 