FROM rust:1.58.1-bullseye AS builder
RUN apt-get update && apt-get -y upgrade && apt-get install -y cmake libclang-dev
COPY . /app
WORKDIR /app
ARG CPU_NUM=1
RUN cargo build -j $CPU_NUM --release

FROM ubuntu:22.04
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
  libssl-dev \
  curl \
  ca-certificates \
  && apt-get clean \
  && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/dvf_root_node /usr/local/bin/dvf_root_node
COPY --from=builder /app/target/release/dvf /usr/local/bin/dvf
