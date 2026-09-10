FROM quay.io/pypa/manylinux_2_28_aarch64@sha256:ad74e53b713f3b07d8c889c526dc0c6500da9827b45e38739570875fef52e28f

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/opt/python/cp311-cp311/bin:/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.97.0 \
    RUSTUP_VERSION=1.29.0 \
    RUSTUP_INIT_SHA256=9732d6c5e2a098d3521fca8145d826ae0aaa067ef2385ead08e6feac88fa5792

RUN yum install -y curl gcc make perl-core perl-IPC-Cmd openssl-devel && \
    yum clean all && \
    rm -rf /var/cache/yum

# Bootstrap rustup from the versioned aarch64 binary only after validating
# the publisher-provided SHA-256, then install the workspace Rust toolchain.
RUN set -eux; \
    rustup_init=/tmp/rustup-init; \
    curl --fail --location --proto '=https' --proto-redir '=https' \
      --tlsv1.2 --retry 3 --connect-timeout 15 --max-time 120 \
      --output "$rustup_init" \
      "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/aarch64-unknown-linux-gnu/rustup-init"; \
    echo "${RUSTUP_INIT_SHA256}  ${rustup_init}" | sha256sum -c -; \
    chmod 0755 "$rustup_init"; \
    "$rustup_init" -y --profile minimal --no-modify-path --default-toolchain "$RUST_VERSION"; \
    rm -f "$rustup_init"; \
    rustc --version | grep -F "rustc ${RUST_VERSION} "

# Install maturin using pip for one of the Pythons in the image
RUN /opt/python/cp311-cp311/bin/python -m pip install \
      --disable-pip-version-check --no-cache-dir --only-binary=:all: \
      "maturin==1.5.0"

WORKDIR /work
