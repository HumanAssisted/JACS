
.PHONY: iterate

iterate:
	. ./.venv/bin/activate
	uv pip install -e .
	uv pip install -e ../../jacspy

# Build wheel for the current macOS environment
build-wheel-mac:
	@echo "Building macOS wheel..."
	maturin build --release --out dist  # Output wheels to 'dist' directory

# Publish wheels from the 'dist' directory to PyPI
publish-wheels:
	@echo "Publishing wheels from dist/ to PyPI..."
	# export TWINE_USERNAME=__token__
	# export TWINE_PASSWORD=pypi-api-token
	maturin publish --username $$TWINE_USERNAME --password $$TWINE_PASSWORD --skip-existing dist/*.whl
