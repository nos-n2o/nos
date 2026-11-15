# CI's pinned toolchain as an image, so `make` on a host without it (no rustup, an older
# distro rustc) runs the exact rustc/clippy/nightly CI runs (#180). Built and tagged by
# `make ci-image` from rust-toolchain.toml and ci.yml's MIRI_TOOLCHAIN; never pushed.
ARG RUST_TOOLCHAIN
FROM rust:${RUST_TOOLCHAIN}-trixie
ARG MIRI_TOOLCHAIN
# nos-pam (#996) links -lpam.
RUN apt-get update && apt-get install -y --no-install-recommends libpam0g-dev \
 && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy rustfmt llvm-tools-preview \
 && rustup toolchain install "${MIRI_TOOLCHAIN}" --profile minimal --component miri,rust-src \
 && cargo install --locked cargo-nextest cargo-llvm-cov cargo-deny cargo-audit \
 && rm -rf /usr/local/cargo/registry /usr/local/cargo/git \
 && chmod -R a+rwX /usr/local/rustup /usr/local/cargo
