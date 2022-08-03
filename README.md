# SafeStake

SafeStake is a decentralized validation framework for performing ETH2 duties and its backend is designed on top of [Lighthouse](https://github.com/sigp/lighthouse).

## Architecture

Below is the architecture of SafeStake.

![alt](./imgs/architecture.png?raw=true)

## Get Started

### Installation

Clone this repository:

```shell
git clone --recurse-submodules https://github.com/zicofish/dvf.git
cd dvf
```

Install Eth1 client:

```shell
./scripts/geth_install.sh
geth --version
```

Install Rust and build lighthouse and this project:

```shell
# Install Rust
curl --tlsv1.2 https://sh.rustup.rs -sSf | sh

# Build lighthouse
cd lighthouse
cargo build --release
./target/release/lighthouse --version
cd ..

# Build our project
cargo build --release
./target/release/dvf --version
```



### Start the Root Node Service

This step is ONLY for SafeStake's service provider. Skip this if you just want to run an operator node.

```shell
./scripts/dvf_root_run.sh
```

Save the ENR output to the log file `boot_node_output`, for example, like this:

```
enr:-IS4QNyznRo6EasKc-YC_u7A_tJN3EmFM-GppAvaR33tanOSfNo0XZYh3vTyFtW_LhhKnI0i2kzeCSP8BBoZIwg0ihIBgmlkgnY0gmlwhCNYD_SJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCIy0
```

### Start an Operator

Start the `geth` client and let it sync with the blockchain. The syncing process might take some time (from hours to one day depending on your network environment).

```shell
./scripts/geth_run.sh
```

After syncing, start the beacon node:

```shell
./scripts/beacon_run.sh
```

Start the operator node:

```shell
# Please update the `--boot-enr` argument in the script with the ENR of 
# the root node (provided by SafeStake's service provider)
./scripts/dvf_operator_run.sh
```



## Docker

TO BE UPDATED.

You need to first install [Docker](https://docs.docker.com/engine/install/) before moving on.

### Build docker image

```sh
docker build -t safestake .
```

### Start a docker container

```sh
docker run -it safestake /bin/bash
```

## 

## Documentation

Run the following to generate documentation in `target/doc/ruby/`:

```shell
cargo doc --no-deps
```

## Security Warnings

As of now, this project serves mainly proof-of-concepts, benchmarking and evaluation purpose and not for production use. Also implementation have not been fully-reviewed.
