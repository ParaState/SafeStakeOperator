# SafeStake: Tokenomics (ongoing)

## A Decentralized Staking as a Service (SaaS) Infrastructure

### DVT Token  <a href="#main-use-cases-of-state-token" id="main-use-cases-of-state-token"></a>

State token is rebranded to DVT. Please refer to the [Rebranding Governance Proposal](https://vote.safestake.xyz/#/proposal/0xc8ab763f7491bfe47ae8b41747dffa19907ace150798c8a2824685e386cdc1a5), and the [Token Symbol Vote](https://vote.safestake.xyz/#/proposal/0xe92565a32a08c7c3aafdf6c7ca6f9589a2ddc443eb46a914de63991e76359f75).&#x20;

The DVT token is the official ERC-20 token of the SafeStake network. Its main uses include:

1. Validator registering on the SafeStake network
2. Native payment token on SafeStake network
3. Governance
4. Economic incentivizes

### Tokenomics <a href="#tokenomics" id="tokenomics"></a>

Initial total supply: 100,000,000 DVT

Eco Treasury Vault: 26,560,000 DVT

1. Validators on the SafeStake network are required to pay 30 DVT/month to each operator as a service fee. The four operators in the committee managing the validator will receive a total payment of 120 DVT token per month from the staker. In  the future, operators will be enabled to set their own fees within a reasonable threshold. This initial cost setting of around $21/month is based on the leading staking service provider[ in the advanced VPS category](https://www.allnodes.com/pricing).&#x20;
2. Operators on the SafeStake network are encouraged to maintain a minimum balance of DVT tokens if they want to be selected in priority to organize as an Op committee during Validator registration.&#x20;
3. In addition, initiator operators who stake 8 ETH to create mini-pool contracts for new validators will also be required to pay in full 120 DVT/month, since the extra 24 ETH is provided by the liquidity staking pool. However, since the initiator operator is one of the four managing operators, they will receive 30 DVT/month back in the subject validator service fees.
4. During the mini-pool setup, Initiators must select three (3) additional operators that will make up the operator committee managing the validator. In addition, two (2) of these three (3) operators must be from the SafeStake DAO.
5. The above fees are calculated per block.
6. The SafeStake DAO collects 10% of total operator’s service fees and 10% of total validator's yield as the 'protocol fee.' These fees are collected automatically via smart contract on a block basis. The funds collected for the protocol fee will be stored in the network security treasury and controlled by the SafeStake DAO.&#x20;

### According to the latest [$DVT Token Economics Governance Proposal](https://vote.safestake.xyz/#/proposal/0x68e5f259359a50829999665ab70259116c01a0cbe8cb6d85e65e9b283bef0799), the Eco treasury vault will release tokens based on the below logic.&#x20;

There are three different players in the SafeStake and DVT token ecosystem - operators, validators, and speculators.&#x20;

Starting with the last first, speculators always buy low and sell high, which is a sub-set of how operators behave. It only makes sense that because operators earn DVT tokens as revenue, they will be motivated to take increased profits and sell the token when the price goes up. However, operators may also decide to hold the tokens or even purchase them back from the market when the token price drops too low since they always want their earnings in subscription fees to cover the expenses of running their node(s), at the very least.&#x20;

So the two major players in the SafeStake ecosystem become the operators and validators. Operators are the cornerstone of success. More operators joining the network allows the system to support more validators with a more robust staking service.&#x20;

Now, let’s define the **principles** which trigger an Eco Treasury token release:

&#x20;      Let, K = initial monthly subscription fee (120 DVT tokens),

&#x20;              V = the number of validators in the month(t),

&#x20;              DVT token spot price will be calculated by VWAP on CMC or CoinGecko.

a)  If Kq of Month(t+2) >= K of Month(t) \*150%, it will trigger K\*V DVT tokens to be released from the Eco Treasury vault at Month(t+3).

b) If Kq of Month(t+2) >= K of Month(t) \*200%, it will trigger 2K\*V DVT tokens to be released from the Eco Treasury vault at Month(t+3).

c)  If Kq of Month(t+2) < K of Month(t) \*150%, it will not trigger a new release.

d) If in a consecutive 6-month period, Kq of Month(t+5) >= K of Month(t) \*150%, it will trigger the network contract settings to modify the subscription fee (with fewer DVT tokens), in order to benchmark the original K value. This is to decrease the token amount in demand in order to control the inflation.&#x20;

e)  If in a consecutive 3-month period, Kq of Month(t+2) < K of Month(t) \*75%, it will trigger the network contract settings to modify the subscription fee (with more DVT tokens), in order to benchmark the original K value. This is to increase the token amount in demand in order to control the deflation.&#x20;

f)   When the Eco Treasury vault is out of DVT tokens based on the above release triggers, it will mint new tokens to inject into the market.&#x20;

Next, we’d like to explain the logic that defines the above principles of tweaking supply and demand. The Nash Equilibrium in a coalition game cannot be planned; instead, it can only be achieved empirically and dynamically. The following is a two-player coalition game relative to our SafeStake ecosystem of operators and validators:

<figure><img src=".gitbook/assets/coalition game.png" alt=""><figcaption></figcaption></figure>

Let’s define the payoffs as&#x20;

(1,1) both operator and validator buy the tokens when the price goes up\
(3,1) both operator and validator sell the tokens when the price goes up\
(2,3) both operator and validator buy the tokens when the price goes down\
(0,0) both operator and validator sell the tokens when the price goes down.&#x20;

We can use the coalition game above to find a Nash Equilibrium that uses mixed strategies. Validators play a  mixed strategy of (Buy, Sell) = (0.75, 0.25), and operators have an expected payout = 1.5. This conclusion is sound when viewing validators as less subject to price speculation, and having a real need to subscribe to SafeStake’s operator node service in order to maximize their staking yields. Additionally, when the price of the DVT token drops, the service cost for validators also decreases, making them more likely to purchase additional tokens to extend their subscriptions.\


### Slashing Mechanism for Unresponsive Operators

This slashing mechanism built into SafeStake aims to guarantee that operators on the network maintain a minimum uptime of 99.5%. The operator node which is failed to achieve consensus amongst the Operator Committee in a specific epoch will be slashed for the $DVT rewards pro rata in that epoch in the fee management contract. And these slashed $DVT tokens will be burnt.&#x20;







_Please Note: All parameters in the above formula will be adjusted by the SafeStake DAO according to practical feedback._



### &#x20;<a href="#sow-stage-2" id="sow-stage-2"></a>
