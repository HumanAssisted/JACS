FROM quay.io/pypa/manylinux_2_28_x86_64

ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:$PATH \
    RUST_VERSION=1.85.1

RUN yum install -y curl gcc openssl-devel && \
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain $RUST_VERSION && \
    yum remove -y curl && \
    yum clean all && \
    rm -rf /var/cache/yum

WORKDIR /work