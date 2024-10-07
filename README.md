# SafeStake: A trust-minimized middle layer for secure, decentralized ETH staking

[![Publish Image & UnitTest](https://github.com/ParaState/SafeStakeOperator/actions/workflows/ci_dev.yml/badge.svg?branch=dev)](https://github.com/ParaState/SafeStakeOperator/actions/workflows/ci_dev.yml)

## What is SafeStake? <img src=".gitbook/assets/image (4).png" alt="" data-size="line">

`SafeStake` is a decentralized staking framework and protocol that maximizes staker rewards by keeping validators secure and online to perform Ethereum Proof-of-Stake consensus (ETH2) duties. It splits a validator key into shares and distributes them over several nodes run by independent operators to achieve high levels of security and fault tolerance. Written in Rust, SafeStake runs on top of the ETH2/consensus client [Lighthouse](https://github.com/sigp/lighthouse) and uses [Hotstuff](https://github.com/asonnino/hotstuff) (a BFT consensus library) for consensus. The referenced [thesis](https://eprint.iacr.org/2019/985). 

<figure><img src=".gitbook/assets/image (2).png" alt=""><figcaption><p>SafeStake Network Architecture</p></figcaption></figure>

### SafeStake makes earning staking rewards safe and easy for all ETH holders.

* `Stage 1 - Deposit 32 ETH` and choose a group of four operators to manage your validator.
* `Stage 2 - Partnering with LST protocols to run 'Pooled Validator', empowring LST/LRT protocols to deploy validators on SafeStake platform to enhance security and improve performance resilience. 

**SafeStake is the first ETH staking pool to implement distributed validator technology (DVT) written in Rust for increased decentralization, security, and reliability.**

### Test Drive SafeStake

You can join the SafeStake testnet by running a **Validator** or an **Operator Node**.

<figure><img src=".gitbook/assets/image (1).png" alt="Test SafeStake"><figcaption><p>Join the SafeStake Network</p></figcaption></figure>

### Run a SafeStake Validator

In the SafeStake ecosystem, there is no need for stakers to deploy validators as they delegate those duties to operators. A deposit of as little as .01 ETH up to 32 ETH is all a user needs to join the network as a validator. Just connect your wallet and follow the instructions to get started.

### Run a SafeStake Operator Node

Please refer to the step-by-step instructions [here](docs/safestake-running-an-operator-node.md).

## SafeStake White Paper

Read the SafeStake [white paper](https://docsend.com/view/22tth6krr9mnfhre?lt\_utm\_source=lt\_share\_link).

## Additional Information

Check out [our website](https://www.safestake.xyz/) for more about SafeStake.

[Help test](https://testnet.safestake.xyz/) the SafeStake network!

Twitter: [https://twitter.com/safestakeDVT](https://twitter.com/safestakeDVT)

Join our [Discord](http://discord.gg/zFS3Mnfpwj) chat channel!

## Beta Advisory

Currently, the SafeStake project is in public testnet stage. In addition, the smart contracts have been reviewed by the Nethermind Team and fulfilled audit by PeckShield. Please check the detailed [audit report](https://github.com/peckshield/publications/tree/master/audit_reports/PeckShield-Audit-Report-SafeStake-v1.0.pdf) and the Operator Networking Security Assessment Report by SigmaPrime. [Sigma_Prime_SafeStake_Operator_Security_Assessment_Report_v2_1.pdf](https://github.com/user-attachments/files/17098313/Sigma_Prime_SafeStake_Operator_Security_Assessment_Report_v2_1.pdf). 
Stay tuned for the Stage1 mainnet launch!
