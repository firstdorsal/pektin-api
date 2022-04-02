# 0. BUILD STAGE
FROM ekidd/rust-musl-builder:nightly-2021-12-23 AS build
# build deps
COPY Cargo.toml Cargo.lock ./
USER root
RUN apt-get update && apt-get install upx -y

RUN rustup component add rust-src --toolchain nightly-2021-12-23-x86_64-unknown-linux-gnu
RUN cargo install cargo-build-deps
RUN cargo build-deps --release
RUN rm -f target/x86_64-unknown-linux-musl/release/deps/pektin*
# build
COPY --chown=root:root src src
RUN cargo build -Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort --release --bin main
RUN strip target/x86_64-unknown-linux-musl/release/main
RUN upx --best --lzma target/x86_64-unknown-linux-musl/release/main
RUN useradd -u 50003 -N pektin-api

# 1. APP STAGE
FROM scratch
WORKDIR /app
COPY --from=build /home/rust/src/target/x86_64-unknown-linux-musl/release/main ./pektin-api
COPY --from=build /etc/passwd /etc/passwd
USER pektin-api
STOPSIGNAL SIGTERM
# run it 
ENTRYPOINT ["./pektin-api"]
