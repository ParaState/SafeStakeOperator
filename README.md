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
(./target/release/dvf_root_node 35.88.15.244 9005 > boot_node_output 2>&1 &)
```

- `35.88.15.244` is the IP of the running machine. Change it to your machine's IP.

- `9005`?



The log file `boot_node_output` contains an ENR output, for example, like this:

```
enr:-IS4QNyznRo6EasKc-YC_u7A_tJN3EmFM-GppAvaR33tanOSfNo0XZYh3vTyFtW_LhhKnI0i2kzeCSP8BBoZIwg0ihIBgmlkgnY0gmlwhCNYD_SJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCIy0
```

### Start an Operator

Start the `geth` client and let it sync with the blockchain. The syncing process might take some time (from hours to one day depending on your network environment).

```shell
(geth \
    --ropsten \
    --http \
    --datadir /var/lib/goethereum \
    --metrics \
    --metrics.expensive \
    --pprof \
    --http.api="engine,eth,web3,net,debug" \
    --http.corsdomain "*" \
    --authrpc.jwtsecret=/var/lib/goethereum/jwtsecret \
    --override.terminaltotaldifficulty 50000000000000000 \
> geth_output 2>&1 &)
```

- `--ropsten`: run geth on the `ropsten` testnet. Use other values if target a different net.



After syncing, start the beacon node:

```shell
(./lighthouse/target/release/lighthouse bn \
    --network ropsten \
    --datadir /var/lib/lighthouse \
    --staking \
    --http-allow-sync-stalled \
    --merge \
    --execution-endpoints http://127.0.0.1:8551 \
    --metrics \
    --validator-monitor-auto \
    --jwt-secrets="/var/lib/goethereum/jwtsecret" \
    --terminal-total-difficulty-override 50000000000000000 \
> bn_output 2>&1 &)
tail -f bn_output
```

- `--network` : Specify the target net



Start the operator node:

```shell
(./target/release/dvf validator_client \
    --debug-level info \
    --network ropsten \
    --ip 35.88.15.244 \
    --base-port 25000 \
    --boot-enr enr:-IS4QNyznRo6EasKc-YC_u7A_tJN3EmFM-GppAvaR33tanOSfNo0XZYh3vTyFtW_LhhKnI0i2kzeCSP8BBoZIwg0ihIBgmlkgnY0gmlwhCNYD_SJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCIy0 \
> dvf_output 2>&1 &)
tail -f dvf_output
```

- `--network` : Specify the target net

- `--ip` : Provide the IP of the running machine

- `--base-port`: Specify a base port for the Hotstuff protocol. 4 continuous ports need to be available via this setting. For example, `--base-port 25000` will require `25000-25003` to be available.

- `--boot-enr` : Specify the ENR of the root node
  
  

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

Run the following to generate documentation in `target/doc/dvf/`:

```shell
cargo doc --no-deps
```

## Security Warnings

As of now, this project serves mainly proof-of-concepts, benchmarking and evaluation purpose and not for production use. Also implementation have not been fully-reviewed.
