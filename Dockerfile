FROM rust:1.58.1-bullseye AS builder

RUN apt-get update && apt-get -y upgrade \
   && apt-get install -y cmake libclang-dev

RUN USER=root cargo new --bin app
WORKDIR /app

COPY ./Cargo.lock ./Cargo.lock
COPY ./Cargo.toml ./Cargo.toml
COPY ./lighthouse ./lighthouse
COPY ./hotstuff ./hotstuff

RUN cargo build --release
RUN rm src/*.rs

# copy your source tree
COPY ./src ./src

# build for release
ARG CPU_NUM=8
RUN cargo build -j $CPU_NUM --release

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  curl \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY --from=builder /app/target/release/dvf_root_node /usr/local/bin/dvf_root_node
COPY --from=builder /app/target/release/dvf /usr/local/bin/dvf
COPY ./src ./src
COPY ./docker-entrypoint ./docker-entrypoint
RUN chmod +x /app/docker-entrypoint
EXPOSE 9005