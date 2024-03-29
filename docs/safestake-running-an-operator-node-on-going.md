# SafeStake: Running an Operator Node (on going)

_**Updates happen frequently! Our**_ [_**Github**_](https://github.com/ParaState/SafeStakeOperator) _**always has the latest operator node resources and setup instructions.**_

## Deploy the Operator node

### Dependencies

### Server Host

* Public Static Network IP of IPv4 (need to disable IPv6)
* Hardware
  * (Standalone Mode Recommend)
    * CPU: 16
    * Memory: 32G
    * Disk: 600GB
  * (Light Mode Recommend)
    * CPU: 2
    * Memory: 4G
    * Disk: 200GB
* OS
  * Unix
* Software
  * Docker
  * Docker Compose

### Running Mode Of Operator Node

`Standalone Mode`

Standalone mode contains the following list of programs/soft on a single host:

* Geth/Nethermind/Besu/Erigon Service
* Lighthouse Service
* OperatorNode Service

`Light Mode`

Light mode contains only the OperatorNode service, the following list of programs/soft on a host:

* OperatorNode Service

> Geth/Nethermind/Besu/Erigon service and Lighthouse service can run on other hosts. Users should configure the `beacon node endpoint` (discussed later) in order to connect to Lighthouse's beacon node instance. The purpose of this is to make the architecture clearer and easier to scale operator nodes. And the cost efficiency ratio of infrastructure will be higher.


### Deployment

#### 1. Set firewall rule

Log in to your host cloud service provider, open the following firewall inbound rules:


| Type             | IpProtocol  | Port  | IpRanges  | Usage    |
| ---------------- | ----------- | ------| --------  |--------  |
| Inbound/Ingress  | TCP & UDP   | 30303 | 0.0.0.0/0 | Geth/Nethermind/Besu/Erigon p2p |
| Inbound/Ingress  | TCP & UDP   | 9000  | 0.0.0.0/0 | Lighthouse p2p |
| Inbound/Ingress  | TCP         | 5052  | Internal  | Operator - Lighthouse |
| Inbound/Ingress  | TCP         | 8546  | Internal  | Operator - Geth/Nethermind/Besu websocket (port 8545 for Erigon)|
| Inbound/Ingress  | TCP         | 8551  | Internal  | Lighthouse - Geth/Nethermind/Besu/Erigon |
| Inbound/Ingress  | TCP         | 26000 | 0.0.0.0/0 | hotstuff consensus |
| Inbound/Ingress  | TCP         | 26001 | 0.0.0.0/0 | hotstuff consensus |
| Inbound/Ingress  | TCP         | 26002 | 0.0.0.0/0 | hotstuff consensus |
| Inbound/Ingress  | TCP         | 26003 | 0.0.0.0/0 | When aggregating signatures, operator nodes use this port to request signature from each other |
| Inbound/Ingress  | UDP         | 26004 | 0.0.0.0/0 | Node discovery |
| Inbound/Ingress  | TCP         | 26005 | 0.0.0.0/0 | DKG port, which will listen only when DKG is triggered. By default, the port won't listen.|


#### 2. SSH Login to your server ([jumpserver](https://www.jumpserver.org/) recommand)

#### 3. Install Docker and Docker compose

* [install docker engine](https://docs.docker.com/engine/install/)
* [install docker compose](https://docs.docker.com/compose/install/)

#### 4. Enable docker service and start it immediately.

```
 sudo systemctl enable docker
```

#### 5. Create local volume directory

```
 sudo mkdir -p /data/geth
 # OR, if you use Nethermind/Besu/Erigon:
 # sudo mkdir -p /data/nethermind
 # sudo mkdir -p /data/besu
 # sudo mkdir -p /data/erigon
 sudo mkdir -p /data/lighthouse
 sudo mkdir -p /data/jwt
 sudo mkdir -p /data/operator
```

#### 6. Generate your jwt secret to jwt dirctory

```
openssl rand -hex 32 | tr -d "\n" | sudo tee /data/jwt/jwtsecret
```

#### 7. Clone operator code from Github

```
git clone --recurse-submodules https://github.com/ParaState/SafeStakeOperator.git dvf
```

#### 8. Running Geth/Nethermind/Besu/Erigon & Lighthouse Service
NOTE: This step is to provide a quick way to setup and run the execution client and consensus client. If you already have a node running execution client and consensus client, you can skip this step.

```bash
cd dvf
cp .env.example .env
sudo docker compose -f docker-compose-operator.yml up geth -d
# OR, if you use Nethermind/Besu/Erigon:
# sudo docker compose -f docker-compose-operator.yml up nethermind -d
# sudo docker compose -f docker-compose-operator.yml up besu -d
# sudo docker compose -f docker-compose-operator.yml up erigon -d
sudo docker compose -f docker-compose-operator.yml up lighthouse -d
```

NOTE: Remember to open the `5052` firewall port for this host

Syncing data may take several hours. You can use the command to see the latest logs of lighthouse to check if the data is synced:
```bash
sudo docker compose -f docker-compose-operator.yml logs -f --tail 10 lighthouse
```

Once the data is synced, you will see output like below:
```bash
INFO Synced, slot: 3690668, block: 0x1244…cb92, epoch: 115333, finalized_epoch: 115331, finalized_root: 0x0764…2a3d, exec_hash: 0x929c…1ff6 (verified), peers: 78
```
or you can use this command to check if lighthouse is synced:
```
curl -X GET "http://localhost:5052/lighthouse/syncing" -H  "accept: application/json"
```
if the output shows `{"data":"Synced"}`, it means it is already synced.

#### 9. Edit local environment variables
```bash
vim .env
```

Now that we have open the `.env` file, we will update the values based on our own configuration.



**Leave these variables unchanged now**:
```bash
GETH_NETWORK=holesky
NETHERMIND_NETWORK=holesky
BESU_NETWORK=holesky
ERIGON_NETWORK=holesky
LIGHTHOUSE_NETWORK=holesky
OPERATOR_NETWORK=holesky
IMAGE_TAG=v3.1-testnet
REGISTRY_CONTRACT_ADDRESS=B4Afe3F48B8Bff3E5cE3d603B8cE9F87524581be
NETWORK_CONTRACT_ADDRESS=a508E281d1FF048012A754505C92dF20C7e1Bc0e
API_SERVER=https://api-testnet-holesky.safestake.xyz/api/op/
# different chain has different ttd
TTD=10790000
# separated by ',' for multiple relays, such as MEV_BOOST_RELAYS=xxx,xxx,xxx
MEV_BOOST_RELAYS=https://0xafa4c6985aa049fb79dd37010438cfebeb0f2bd42b115b89dd678dab0670c1de38da0c4e9138c9290a398ecd9a0b3110@boost-relay-holesky.flashbots.net
#gas limit. [default: 30,000,000]
GAS_LIMIT_INTEGER=30000000
OPERATOR_ID=<YOUR_OPERATOR_ID>
```

**Update these variables with yours**

```bash
WS_URL= #YOUR WS URL: ws://<geth/nethermind/besu node ip>:8546 or ws://<erigon node ip>:8545
BEACON_NODE_ENDPOINT= # The beacon node endpoint. Depending on whether you are running single-node mode or multi-node mode, fill in the correct Lighthouse beacon node service url, e.g. http://127.0.0.1:5052 for a local node
# public ipv4 ip of the server running your operator
NODE_IP=<IP_ADDRESS>
```


For `BEACON_NODE_ENDPOINT`, if you follow the previous step to run Geth/Nethermind/Besu/Erigon and Lighthouse and you want operator runs on the same machine, then you can use a local IP:
```bash
BEACON_NODE_ENDPOINT=http://127.0.0.1:5052
```

Otherwise, suppose the host where you run the Lighthouse & Geth/Nethermind/Besu/Erigon service has an IP `12.102.103.1`, then you can set:
```bash
BEACON_NODE_ENDPOINT=http://12.102.103.1:5052
```

#### 10. Generate a registration public and private key
```bash
sudo docker compose -f docker-compose-operator.yml up dvf_key_tool
```
Output:
```
...
dvf-dvf_key_tool-1  | INFO: node public key AtzozvDHiWUpO+oJph2ikv+EyBN5pdBXsfgZqLi0+Yqd
dvf-dvf_key_tool-1 exited with code 0
```
Save the public key, which will be used later. Or you can find the public key in the "name" field of the file `/data/operator/v1/holesky/node_key.json`

#### 11. Go to [SafeStake website](https://holesky.safestake.xyz/):
* Click "Join As Operator".

<figure><img src="imgs/operatpr-setup1.png" alt=""><figcaption></figcaption></figure>

* Select a wallet where you have enough holesky testnet token to pay minimum fee to sign a transaction.
<figure><img src="imgs/operatpr-setup2.png" alt=""><figcaption></figcaption></figure>


* After you connect your wallet, click "Register Operator"
<figure><img src="imgs/operatpr-setup3.png" alt=""><figcaption></figcaption></figure>

* Your wallet address is auto filled. You need to enter the "Display Name" for your node and the "Operator Public Key" got from the previous step. Then click "Next".
<figure><img src="imgs/operatpr-setup4.png" alt=""><figcaption></figcaption></figure>

* Click "Register Operator"
<figure><img src="imgs/operatpr-setup5.png" alt=""><figcaption></figcaption></figure>

* Wallet extension page will pop out. You need to click "Confirm" to sign the transaction.
<figure><img src="imgs/operatpr-setup6.png" alt=""><figcaption></figcaption></figure>

After we register an Operator on the Safestake website, we will be shown our `OPERATOR ID`, which is the unique identifier we need to start with. We will need to update the OPERATOR ID to the `.env` file before running the operator service.

#### 12. Edit local environment variables for OPERATOR_ID
```bash
vim .env
```
```bash
OPERATOR_ID= #The Operator ID is the ID you receive after registering the operator on SafeStake website
```

#### 13. Start operator service

```bash
sudo docker compose -f docker-compose-operator.yml up --force-recreate -d operator
```


*Congratulations, now the Operator program has been installed and deployed.*

---


### Some final notes about Operator's private/public keys

You can always view your public key in case you forget it with the command:

```
sudo docker compose -f docker-compose-operator.yml logs -f operator | grep "node public key"
```

output

> dvf-operator-1 | \[2022-08-13T16:01:33.814Z INFO dvf::node::node] node public key Al0wMNz3JpkYDH7HVp93dZfLMt1GJHypLfhwOWS0NwC/

It is a good practice to back up your operator private key file

> **Keep it safe and put it in a safe place!**

```
/data/operator/v1/holesky/node_key.json
```

**`Your SafeStake Operator Node is now configured`**

then you may go to [SafeStake website](https://holesky.safestake.xyz/) to register a validator and then choose your operator.

## Backup and Migration

If you are using our default settings, all data other than configration files is stored in the folder `/data`. It is possible for Geth/Nethermind/Besu/Erigon and lighthouse to resync data in a new machine. For operator, it is important to always backup and copy the folder `/data/operator/` to the new machine before you start operator in the new machine.

Some description of the folders and files under `/data/operator/v1/holesky/`:
```
── holesky
    ├── contract_record.yml # record the current synced block number
    ├── dvf_node_db # hotstuff consensus files
    ├── node_key.json # operator's public and private key
    ├── secrets # secret files for encryption
    ├── validators # data files of the validators that the operator is serving, inherited from the native folder of lighthouse validator client, including slashing_protection.sqlite, etc.
```

## Common issues troubleshooting
```mermaid
graph TD;
    A[Operator is shown as \n inactive/idle in explorer] --> B{any validator chooses\nthe operator?};
    B --> |No| C[register a validator\n in our website and \n choose your operator];
    B --> |Yes| D[check if the following errors \nshown in the log of first 100 lines];
    D --> |?| E[Wrong scheme: https];
    E --> |solution| F["WS_URL in .env file should be set\n beginning with ws:// or wss:// instead of https://"];
    F --> G[change the block number in the file\n /data/operator/v1/holesky/contract_record.yml to \na block number before the registration of the validator];
    G --> H[restart operator];
    D --> |?| K["Failed to connect to {ip}:26000"];
    K --> |solution| L[need to open the port 26000 to the internet,\n also carefully check if other firewall rules shown\n in the doc are set correctly in your server];
```
