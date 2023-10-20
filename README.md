# SafeStake: A trust-minimized middle layer for secure, decentralized ETH staking

## What is SafeStake? <img src=".gitbook/assets/image (4).png" alt="" data-size="line">

`SafeStake` is a decentralized staking framework and protocol that maximizes staker rewards by keeping validators secure and online to perform Ethereum Proof-of-Stake consensus (ETH2) duties. It splits a validator key into shares and distributes them over several nodes run by independent operators to achieve high levels of security and fault tolerance. Written in Rust, SafeStake runs on top of the ETH2/consensus client [Lighthouse](https://github.com/sigp/lighthouse) and uses [Hotstuff](https://github.com/asonnino/hotstuff) (a BFT consensus library) for consensus. The referenced [thesis](https://eprint.iacr.org/2019/985). 

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption><p>SafeStake Network Architecture</p></figcaption></figure>

### SafeStake makes earning staking rewards safe and easy for all ETH holders.

* `Stage 1 - Deposit 32 ETH` and choose a group of four operators to manage your validator.
* `Stage 2 - Deposit 8 ETH` as an initializer to participate in running a 'Pooled Validator' and choose three additional operators to manage your validator.
* `Stage 3 - Deposit ≥ 0.1 ETH but < 32 ETH` to participate in running a 'Pooled Validator.' Stake ETH in the SafeStake pool and get `sfETH` tokens in return. Your share of the pooled validator's rewards will be accrued automatically to your sfETH token balance and are completely liquid, allowing you the freedom to trade, buy, or sell your tokens any time you want.

**SafeStake is the first ETH staking pool to implement distributed validator technology (DVT) written in Rust for increased decentralization, security, and reliability.**

### Test Drive SafeStake

You can join the SafeStake testnet by running a **Validator** or an **Operator Node**.

<figure><img src=".gitbook/assets/image (1).png" alt="Test SafeStake"><figcaption><p>Join the SafeStake Network</p></figcaption></figure>

### Run a SafeStake Validator

In the SafeStake ecosystem, there is no need for stakers to deploy validators as they delegate those duties to operators. A deposit of as little as .01 ETH up to 32 ETH is all a user needs to join the network as a validator. Just connect your wallet and follow the instructions to get started.

### Run a SafeStake Operator Node

Please refer to the step-by-step instructions [here](safestake-running-an-operator-node-on-going.md).

## SafeStake White Paper

Read the SafeStake [white paper](https://docsend.com/view/22tth6krr9mnfhre?lt\_utm\_source=lt\_share\_link).

## Additional Information

Check out [our website](https://www.safestake.xyz/) for more about SafeStake.

[Help test](https://testnet.safestake.xyz/) the SafeStake network!

Twitter: [https://twitter.com/safestakeDVT](https://twitter.com/safestakeDVT)

Join our [Discord](http://discord.gg/zFS3Mnfpwj) chat channel!

## Beta Advisory

Currently, the SafeStake project is in beta and is mainly for proof-of-concept, benchmarking, and evaluation purposes. It is still in active testing and not yet ready for production use. In addition, all possible implementations of SafeStake have not been fully reviewed and vetted.
