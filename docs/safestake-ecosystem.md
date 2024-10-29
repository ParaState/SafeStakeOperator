# SafeStake: Ecosystem

The SafeStake ecosystem consists of three stakeholders:&#x20;

* Validators
* Operators&#x20;
* SafeStake Service Provider / ParaState DAO

### Validators

Validators are responsible for performing duties to secure Ethereum's Proof-of-Stake mechanism. They earn small rewards in ETH when they complete them accurately and promptly. However, if a validator fails to actively participate in its assigned tasks, it will be penalized in gradual deductions from the initial 32 ETH balance. However, Ethereum prevents running the same validator key on more than one client, and previous attempts to create a redundant, fault-tolerant environment have only resulted in more severe penalties or 'slashing' ([more on slashing](https://launchpad.ethereum.org/en/faq)).

Knowing that validator uptime is critical to maximizing validator rewards and avoiding penalties, it's essential to choose a **reliable** staking solution. Validator **security** is also of paramount importance as inconsistent, dishonest, or malicious behavior will result in a validator being slashed.&#x20;

**SafeStake provides both of these critical features.**&#x20;

* **High Availability**\
  Keeps validators online and available to perform duties.
* **Strong Security** \
  Splits the validator key into shares and distributes it to independent operator nodes. The key can be stored safely offline and our tech stack ensures no single operator or bad actor can recreate it.

As we mentioned in the overview, SafeStake operates as a staking pool, allowing virtually any ETH holder to run a validator and earn staking rewards. Deposit as little as 0.1 ETH to get started.

### Operators

The SafeStake framework employs committees of non-trusting tech-savvy operators working in collaboration to manage validators so stakers don't have to. It provides a turnkey solution for stakers and results in a fault-tolerant system that achieves high availability. Even if some operators are offline, others will respond to complete the validator's task. It's ultra-secure because multiple operators each have a share of the key and a minimum number of those shares are required to combine to create a valid signature. This means that even if the 'Byzantine Fault' operators on the network act maliciously, the key will remain safe. Other operators on the network will take over to sign the data and avoid penalties.

#### There are two types of operators:&#x20;

1\. Operators that run the threshold signature scheme to support the decentralized staking service for stakers depositing 32 ETH.

2\. There is another type of Operators who provide liquidity to create a mini-pool called 'initiators'. **Initiators** stake 8 ETH to initiate the mini-pool process and select three other operators to be part of the committee managing the validator. Two of these three operators must come from the Parastate DAO. Together they will run the Distributed Key Generation (DKG) scheme to set up the private/public key pair for the trustless BLS threshold signature scheme of the mini-pool Validator. This key pair forms both the validation and withdrawal keys for ETH 2.0 staking. The initiator triggers a mini-pool contract with their 8 ETH deposit, which enters a waiting queue for the remaining 24 ETH to be deposited from the SafeStake pool. When the pool is ready to provide the additional ETH needed, the mini-pool contract starts the staking process on the Beacon Chain.&#x20;

It is worth noting that in other staking infrastructure provider where similar initializer operators specify the execution layer address that collects priority fees and MEV extraction, oracles are used to monitor and help prevent malicious operators from stealing those fees. SafeStake's design is simplified and more effective. The validator private key is decentralized so no single operator determines the execution layer address, preventing them from stealing the funds.

To `run` an operator node on the SafeStake network, refer to the instructions [here](safestake-running-an-operator-node.md).

### SafeStake Service Provider / ParaState DAO

The SafeStake infrastructure and protocol also relies on its supporters to help build and maintain it. Without SafeStake Services Providers and the ParaState DAO, we could not provide decentralized staking services. At its core, SafeStake provides a robust web service where:

* Users who deposit ETH to run a validator can maximize their staking rewards and minimize missed opportunities and penalties.
* Users can run operator nodes and charge fees to manage validators for stakers.

### &#x20;<a href="#sow-stage-2" id="sow-stage-2"></a>
