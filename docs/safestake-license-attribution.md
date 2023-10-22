# Attribution Notice

Safestake implements its operator software based on [Hotstuff](https://github.com/asonnino/hotstuff) and [Lighthouse validator client](https://github.com/sigp/lighthouse/tree/stable/validator_client).

## Hotstuff
Our code under the `hotstuff` directory is mostly taken from the [Hotstuff](https://github.com/asonnino/hotstuff) repository, with the following modification:
- Upgrade to support port reuse for multiple committees (VAs)
- Optimize recovery and syncrhonization mechanisms after node crash and reboot


## Lighthouse
Our operator is a modified decentralized version of Lighhouse's validator client. It reuses most of Lighthouse's VA logics, including:
- Duty retrieval and execution
- Slashing protection

The most important updates we make are:
- Update the signing method to include an option to sign distributely among a committee of operators
- Update the VA load and save logics to handle operators instead of complete validators.