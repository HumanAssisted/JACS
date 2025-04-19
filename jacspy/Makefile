.PHONY: build-jacspy build-jacspy-mac build-jacspy-linux build-wheel-mac publish-wheels build-wheel-linux test

# # Build wheel for the current macOS environment
build-wheel-mac:
	@echo "Building macOS wheel..."
	maturin build --release --out dist  # Output wheels to 'dist' directory

# Publish wheels from the 'dist' directory to PyPI
publish-wheels:
	@echo "Publishing wheels from dist/ to PyPI..."
	# export TWINE_USERNAME=__token__
	# export TWINE_PASSWORD=pypi-api-token
	maturin publish --username $$TWINE_USERNAME --password $$TWINE_PASSWORD --skip-existing dist/*.whl

# Build wheel for Linux using Docker (manylinux)
build-wheel-linux:
	@echo "Building Linux (manylinux_2_28) wheel using Docker..."
	docker buildx build --tag "jacs-build-manylinux" -f Dockerfile .
	# Run maturin inside the container to build the wheel(s)
	# Mount PWD to /io, output wheel(s) to /io/dist
	# Remove the explicit --target flag to let maturin create manylinux wheels
	docker run --rm -v "$(PWD)/..:/workspace" jacs-build-manylinux \
		bash -c "cd /workspace/jacspy && maturin build --release --out dist"
	@echo "Linux manylinux wheel(s) should be in $(PWD)/dist/"

test:
	cargo test  -- --nocapture
