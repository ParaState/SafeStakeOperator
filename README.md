# SafeStake

SafeStake is a decentralized validation framework for performing ETH2 duties and its backend is designed on top of [Lighthouse](https://github.com/sigp/lighthouse) (ETH2 consensus client) and [Hotstuff](https://github.com/asonnino/hotstuff) (a BFT consensus library).

## Overview

Below is the architecture of SafeStake.

![alt](./imgs/architecture.png?raw=true)

The SafeStake eco-system consists of several important stakeholders: SafeStake Service Provider, Validator, Operator.

### Validator

In ETH2, anyone can deposit 32 ETH to become a validator, in order to support ETH2's Proof of Stake consensus protocol. A validator is responsible for performing assigned duties and will get rewards if its work is submitted and acknowledged in time. Fail to actively participate in the duties result in penalties (gradually deduction of the initial 32 ETH balance). You can continue to the following links to learn how to become a validator for different nets:

- [mainnet](https://launchpad.ethereum.org/en/overview)

- [ropsten](https://ropsten.launchpad.ethereum.org/en/overview)

- [prater](https://prater.launchpad.ethereum.org/en/overview)

Based on the above introduction, it is critical that a validator should guarantee its availability online for timely responses to assigned duties. Moreover, *security* is another critical concern: inconsistent, dishonest, or malicious behavior will result in a more serious penalty, called ***slashing*** ([more on slashing](https://launchpad.ethereum.org/en/faq)). Therefore, there are two important requirements for maintaining a validator:

- High Availability

- Strong security (keep the validation key safe and avoid participating in slashable events)

**This is exactly what SafeStake provides under the hood.** It proposes a committee of operators (below) to collaborate in running the duties for a validator. Even if some operators are offline, others can still complete the tasks, which achieves high availability. Moreover, the private key is split among the operators, hence even if some of them are malicious or compromised, the private key is still safe and other honest operators can complete the tasks without being slashed, which achieves strong security.

### Operator

Briefly speaking, an operator is a party who holds a share of a validator's private validation key and signs duties with this key share. SafeStake uses a $(t,n)$-threshold BLS signature scheme to enable this feature. Namely, a validation key is split into $n$ shares, each of which is held by an operator. The key can NOT be reconstructed with less than $t$ shares. In the work flow, an operator can produce a signature share by signing a duty. Afterwards, if $t$ or more signature shares are collected, we can produce a valid signature that is equivalent to one signed by the original validation key.

### SafeStake Service Provider

SafeStake provides services to enable the above features and connects validators to operators. In the core of its system, SafeStake provides a web service where:

- a user can register as an operator and join our operator pool

- a user who is a valid validator (has deposited 32 ETH beforehand) can choose a set of $n$ operators to run its duties.

These two points are detailed in the above architecture (i.e., user X is a validator, user Y is an operator).



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

- `9005` is the port that the root node will be listening on.

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
    --boot-enr enr:-IS4QNyznRo6EasKc-YC_u7A_tJN3EmFM-GppAvaR33tanOSfNo0XZYh3vTyFtW_LhhKnI0i2kzeCSP8BBoZIwg0ihIBgmlkgnY0gmlwhCNYD_SJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2_oxVtw0RW_QAdpzBQA8yWM0xOIN1ZHCCIy0 \
> dvf_output 2>&1 &)
tail -f dvf_output
```

- `--network` : Specify the target net

- `--ip` : Provide the IP of the running machine

- `--boot-enr` : Specify the ENR of the root node

NOTE: The operator node requires ports `25000-25003` to be available for the Hotstuff protocol.

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
