# SafeStake: Running an Operator Node (on going)

_**Updates happen frequently! Our**_ [_**Github**_](https://github.com/ParaState/SafeStakeOperator) _**always has the latest operator node resources and setup instructions.**_

## Deploy the Operator node

### Dependencies

### Server Host

* Public Static Network IP
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

* Geth Service
* Lighthouse Service
* OperatorNode Service

`Light Mode`

Light mode contains only the OperatorNode service, the following list of programs/soft on a host:

* OperatorNode Service

> Geth service and Lighthouse service can run on other hosts. Users should configure the `beacon node endpoint` (discussed later) in order to connect to Lighthouse's beacon node instance. The purpose of this is to make the architecture clearer and easier to scale operator nodes. And the cost efficiency ratio of infrastructure will be higher.

### Preparation: Get your Infura WS\_URL

* Follow the instructions found at [https://docs.infura.io/infura/](https://docs.infura.io/infura/)
* Create Infura account [here](https://app.infura.io/register) and login the account
* Create new key

<figure><img src="imgs/infura-step1.png" alt=""><figcaption></figcaption></figure>

* Select 'WEBSOCKETS'

<figure><img src="imgs/infura-step2.png" alt=""><figcaption></figcaption></figure>

* Select 'Goerli' network under 'Ethereum'

<figure><img src="imgs/infura-step3.png" alt=""><figcaption></figcaption></figure>

* Copy your WS\_URL

<figure><img src="imgs/infura-step4.png" alt=""><figcaption></figcaption></figure>

### Deployment

#### 1. Set firewall rule

Log in to your host cloud service provider, open the following firewall inbound rules:

| Type            | IpProtocol | FromPort | ToPort | IpRanges  |
| --------------- | ---------- | -------- | ------ | --------- |
| Inbound/Ingress | tcp        | 80       | 80     | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 8585     | 8585   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 25000    | 25003  | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 5052     | 5052   | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 1234     | 1234   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 5052     | 5052   | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 9000     | 9000   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 30303    | 30303  | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 8551     | 8551   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 443      | 443    | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 30303    | 30303  | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 9000     | 9000   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 8545     | 8547   | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 9005     | 9005   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 8585     | 8585   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 22       | 22     | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 26000    | 26005  | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 25004    | 25004  | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 26000    | 26003  | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 25005    | 25005  | 0.0.0.0/0 |
| Inbound/Ingress | udp        | 26004    | 26004  | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 3456     | 3456   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 3000     | 3001   | 0.0.0.0/0 |
| Inbound/Ingress | tcp        | 1234     | 1234   | 0.0.0.0/0 |

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

#### 8. Generate a registration public and private key

```bash
cd dvf
sudo docker compose -f docker-compose-operator.yml up dvf_key_tool
```

Output:

```
...
dvf-dvf_key_tool-1  | INFO: node public key AtzozvDHiWUpO+oJph2ikv+EyBN5pdBXsfgZqLi0+Yqd
dvf-dvf_key_tool-1 exited with code 0
```

Save the public key, which will be used later. Go to [SafeStake website](https://testnet.safestake.xyz/) and `Join As Operator`.

After we register an Operator on the Safestake website, we will be shown our `OPERATOR ID`, which is the unique identifier we need to start with. We will need to update the OPERATOR ID to the `.env` file before running the operator service.

#### 9. Obtain your beacon node endpoint

You should acquire a beacon node endpoint for the operator to connect with. You can either run such a service by yourself, or potentially obtain it from some third-party service (we might open such a paid service later if necessary).

We will show later how to run such a service with `Lighthouse` by yourself. For now, let's continue with other steps.

#### 10. Edit local environment variables

```
cd dvf
cp .env.example .env
vim .env
```

Now that we have open the `.env` file, we will update the values based on our own configuration.

`Goerli Testnet`

**Leave these variables unchanged**:

```bash
GETH_NETWORK=goerli
LIGHTHOUSE_NETWORK=prater
OPERATOR_NETWORK=prater
IMAGE_TAG=v1.0-testnet
REGISTRY_CONTRACT_ADDRESS=f31605c163b54C00371b10af21E8eDa32B969F21
NETWORK_CONTRACT_ADDRESS=C1b4AA96afA5D3566A86920e69Fc6C274d54F3B4
API_SERVER=https://api-testnet.safestake.xyz/v1/
# different chain has different ttd
TTD=10790000
# separated by ',' for multiple relays, such as MEV_BOOST_RELAYS=xxx,xxx,xxx
MEV_BOOST_RELAYS=https://0xafa4c6985aa049fb79dd37010438cfebeb0f2bd42b115b89dd678dab0670c1de38da0c4e9138c9290a398ecd9a0b3110@boost-relay-goerli.flashbots.net
#gas limit. [default: 30,000,000]
GAS_LIMIT_INTEGER=30000000
WS_URL=<infura_ws_url>
OPERATOR_ID=<YOUR_OPERATOR_ID>
# The beacon node endpoint, e.g., http://127.0.0.1:5052 for a local node
BEACON_NODE_ENDPOINT=<FILLED_WITH_YOUR_CHOICE>
```

**Update these variables with yours**

```bash
WS_URL= #YOUR WSS URL
OPERATOR_ID= #The Operator ID is the ID you receive after registering the operator on SafeStake website
BEACON_NODE_ENDPOINT= # Depending on whether you are running single-node mode or multi-node mode, fill in the correct Lighthouse beacon node service url
```

`WS_URL` and `OPERATOR_ID` should have been obtained by following previous steps. As for `BEACON_NODE_ENDPOINT`, if you can't find an available third-party beacon node service, you can follow [this section](safestake-running-an-operator-node-on-going.md#running-lighthouse--geth-service) to setup one by yourself.

#### 11. Start operator service

```bash
sudo docker compose -f  docker-compose-operator.yml up --force-recreate -d operator
```

_Congratulations, now the Operator program has been installed and deployed._

You can continue to the next section if you need to run Lighthouse & Geth service by yourself, otherwise, the operator tutorial ends here.

***

### Running Lighthouse & Geth Service

```bash
sudo docker compose -f docker-compose-operator.yml up geth -d
sudo docker compose -f docker-compose-operator.yml up lighthouse -d
```

NOTE: Remember to open the `5052` firewall port for this host

Now that the service is running, you have your own `BEACON_NODE_ENDPOINT` to fill into the `.env` file. For example, if the service is running on the same machine where the operator software is running, then you can use a local IP:

```bash
BEACON_NODE_ENDPOINT=http://127.0.0.1:5052
```

Otherwise, suppose the host where you run the Lighthouse & Geth service has an IP `12.102.103.1`, then you can set:

```bash
BEACON_NODE_ENDPOINT=http://12.102.103.1:5052
```

***

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
/data/operator/v1/prater/node_key.json
```

**`Your SafeStake Operator Node is now configured`**
