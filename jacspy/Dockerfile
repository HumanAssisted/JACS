FROM python:3.11-bookworm

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.85.1

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        gcc \
        libc6-dev \
        curl \
        ; \
    # Install Rust using the official method from rustup.rs
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_VERSION; \
    rustup --version; \
    cargo --version; \
    rustc --version; \
    apt-get remove -y --auto-remove \
        curl \
        ; \
    rm -rf /var/lib/apt/lists/*;

RUN apt-get update && apt-get upgrade -yqq
RUN apt-get install -y python3-dev python3-openssl
ENV PYTHON_INCLUDE=/usr/local/include/python3.11
ENV PYTHON_LIB=/usr/local/lib
WORKDIR /usr/src/jacspy
COPY jacs ../jacs
COPY jacspy .
RUN cargo build --release