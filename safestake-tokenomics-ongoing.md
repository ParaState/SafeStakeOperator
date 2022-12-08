# SafeStake: Tokenomics (ongoing)

## A Decentralized Staking as a Service (SaaS) Infrastructure

### STATE Token <a href="#main-use-cases-of-state-token" id="main-use-cases-of-state-token"></a>

The STATE token is the official ERC-20 token of the SafeStake network. Its main uses include:

1. Operators registering on the SafeStake network
2. Stakers paying operator fees
3. Governance
4. Economic incentivizes

### Tokenomics <a href="#tokenomics" id="tokenomics"></a>

1. Validators on the SafeStake network are required to pay 30 STATE/month to each operator as a service fee. The four operators in the committee managing the validator will receive a total payment of 120 STATE token per month from the staker. In  the future, operators will be enabled to set their own fees within a reasonable threshold.
2. Operators on the SafeStake network are required to maintain a minimum balance of X STATE tokens and monitor their Beacon Chain staking account to make sure it always meets the 32 ETH requirement. Maintaining a minimum STATE token balance is essential to cover any slashing penalties that may occur during start up.&#x20;
3. In addition, initializer operators who stake 8 ETH to create mini-pool contracts for new validators will also be required to pay 120 STATE/month, since the extra 24 ETH is provided by the local staking pool. However, since the initializer operator is one of the four managing operators, they will receive 30 STATE/month back in validator fees.
4. Initializer operators are required to deposit Y additional ETH during setup to handle any slashing penalties that occur when the validator mini-pool is first created. This fund can be withdrawn once the initializer’s staking yield surpasses the slashing penalties. If slashing penalties occur in the first epoch, a 10% penalties markup (in STATE tokens) will be implemented. During the mini-pool setup, Initializers must select three (3) additional operators that will make up the operator committee managing the validator. In addition, two (2) of these three (3) operators must be from the ParaState DAO.
5. The above fees are calculated per epoch.
6. The ParaState DAO collects 10% of each operator’s service fees and 10% of each validator's yield as the 'protocol fee.' These fees are collected automatically via smart contract on an epoch-by-epoch basis. The funds collected for the protocol fee will be stored in the network security treasury and controlled by the ParaState DAO.&#x20;

### Slashing Mechanism for Unresponsive Operators

This slashing mechanism built into SafeStake aims to guarantee that operators on the network maintain a minimum uptime of 99.5%. The operator node which is failed to achieve consensus amongst the Operator Committee in a specific epoch will be slashed for the STATE rewards pro rata in that epoch in the fee management contract. And these slashed STATE tokens will be burnt. The minimum balance of state tokens operators must maintain will cover slashing penalties.&#x20;

****





_Please Note: All parameters in the above formula will be adjusted by the ParaStateDAO according to practical feedback._

<mark style="color:yellow;"></mark>

### &#x20;<a href="#sow-stage-2" id="sow-stage-2"></a>
