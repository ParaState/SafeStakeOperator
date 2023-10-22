# SafeStake: Tech Stack

### The SafeStake tech stack consists of the following components:

* Threshold BLS Signature
* Shamir Secret Sharing
* Threshold Signature without Trusted Dealer
* Distributed Key Generation (DKG) & Multi-Party Computation
* HotStuff Consensus
*   Solidity Smart Contracts



### Threshold BLS Signature

A non-interactive threshold signature scheme that allows a group of users to collectively sign a message.&#x20;

**Non-interactive** means a signer is not required to communicate with the other signers to generate signature shares for the message. **Threshold** refers to the minimum number of users required to generate the signature successfully (tt out of nn users). The tt signature shares are combined to create a valid signature. In addition, this threshold signature scheme is verifiable and uses a mechanism to detect incorrectly generated signature shares.&#x20;

Technically, the threshold BLS signature is a combination of **Shamir Secret Sharing** and the BLS signature scheme. A (t,nt,n)-threshold secret sharing scheme allows a dealer to generate nn secret shares given a secret, or s∈Fps∈Fp. The secret shares can be distributed to nn users, and a minimum tt out of nn users are required to recover the secret ss. Because at least tt secret shares are required to recover the secret, a bad actor with less than the minimum amount will not be able to recover the secret.

SafeStake threshold signatures consist of the following algorithms:

`PKVfy(tt; PKPK; sPK1sPK1; ⋯⋯; sPKnsPKn): takes as inputs the threshold tt, a public key PKPK, and share public keys sPK1sPK1; ⋯⋯; sPKnsPKn returns 1 if the key bundle is considered valid, and else returns 0. It can only return 1 if tt, nn are positive integers with t≤nt≤n.`

`SKVfy(sSKsSK; sPKsPK)→N→N: takes as inputs a share-signing key sSKsSK returns 1 if sSKsSK is considered a valid share-signing key with respect to share public key sPKsPK, and else returns 0.`

`SigShare(sSKsSK, mm)→sh→sh: takes as inputs a share-signing key sSKsSK and a message m∈{0,1}∗m∈{0,1}∗ produces a signature share shsh.`

`SigShVfy(sPKsPK, mm, shsh)→b→b: takes as inputs a share public key sPKsPK, a message mm and a signature share shsh returns 1 if the signature share is to be considered valid, and else returns 0.`

`SigShCombine(II, sh1sh1, ⋯⋯, shtsht)→σ→σ: takes as inputs a set II of distinct indices i1<⋯<iti1<⋯<it and tt signature shares sh1sh1, ⋯⋯, shtsht and combines them to a signature σσ.`

`SigVfy(PKPK, mm, σσ)→b→b: takes as inputs a verification key vkvk, a message m∈{0,1}∗m∈{0,1}∗ and a signature σσ returns 1 if the signature is to be considered valid, and else returns 0.`

Assuming there is a secure and authenticated channel between the dealer and the signers, a malicious actor would have to compromise at least tt signers to forge a valid signature under this BLS signature scheme. However, it is still possible for a tenacious adversary to do this. So, to further enhance the threshold signature scheme security, we have implemented a threshold signature scheme with proactive security.

### Threshold Signature without a Trusted Dealer

SafeStake's staking pool is made possible by operators, known as an 'initializers,' who create initial mini-pools by staking 8 ETH, then gathering 24 additional ETH from the 'pool' to create a validator. This presents a security risk as the potential exists for this operator to set the withdrawal address to one under their control and steal the staking rewards. It also makes it possible to perform a 'frontrunning' attack to steal the deposit from the sfETH pool. Therefore, it is necessary to ensure that neither users or operators can access the private validator key.&#x20;

### Distributed Key Generation (DKG) & Multi-Party Computation (MPC)

To solve the above dilemma, SafeStake runs a DKG protocol to set up the private key for the threshold signature scheme, resulting in a threshold signature scheme that doesn't use a trusted dealer and ensures no single entity holds the private key. The DKG scheme's job is to agree on a common secret/public key pair such that the secret key is shared among a set of nn participants. Only a subset of t+1≤nt+1≤n parties can use or reveal the generated secret key, while tt collaborating parties cannot recover the secret. In contrast to a traditional secret sharing scheme, DKG doesn't rely on a trusted dealer who generates, knows, and distributes the secret key, avoiding this potential security issue. Instead, it generates the key pair using **multi-party computation** so that no single party can find the shared secret.

Below iteration is the mathematical process of our DKG scheme.

[https://docsend.com/view/z9vdm2tqdmsesibe](https://docsend.com/view/z9vdm2tqdmsesibe)

### HotStuff Consensus Protocol

HotStuff is a leader-based, partially synchronous Byzantine fault-tolerant (BFT) replication protocol. It is built around a novel framework that forms a bridge between classic BFT foundations and blockchains. SafeStake uses HotStuff as a consensus layer to govern the operator networks. Consensus is used to determine the message content of the threshold signature scheme among the operator nodes and can also be applied to determine various validator parameters, such as balance, slash rate, etc. by the ParaStateDAO. HotStuff enables a correct leader to drive the protocol to consensus at the pace of actual network delay (a property called 'responsiveness') and with communication complexity that is linear in the number of replicas. **It is the first partially synchronous BFT replication protocol to combine these functions.**&#x20;

### Solidity Smart Contracts

a. **Beacon Chain Deposit Contract**\
b. **SafeStake Network Contract** - the gateway contract enabling management functionalities for validators and operators.\
c. **Staking Pool Smart Contracts**\
i) **Pool Manager Contract** - The staking pool gateway contract that aggregates users’ funds into pools. Also responsible for maintaining a validator registry and managing its validator's operation through SafeStake smart contract integration.\
ii) **poolETH Token Contract** - An ERC20 token contract that represents the staked ETH in the staking pool and calculates a staker’s accrued rewards using a staking token derivative (sfETH).\
iii) **Mini-Pool Contract** - A contract that takes 8 ETH from an initializer operator and 24 ETH from the SafeStake ETH pool for the initial deposit. Manages the entire ETH 2.0 staking process on SafeStake.
