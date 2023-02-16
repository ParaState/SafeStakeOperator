# SafeStake: Running an Operator Node (on going)

{% hint style="danger" %}
**Updates happen frequently! Our** [**Github**](https://github.com/ParaState/SafeStakeOperator) **always has the latest operator node resources and setup instructions.**
{% endhint %}

**Operators must first set up a SafeStake Service Provider Node**

The SafeStake service provider contains several components:

* A web server and frontend
* A nodejs backend (to communicate with operators)
* A root node service (for peer discovery in a p2p network)

### **Root Node Service**

The duty agreement among operators uses Hotstuff consensus and runs on a p2p network. This requires operators to know each other's IP addresses. For this purpose, SafeStake runs and maintains a root node that operators can consult and use to join the p2p network.

**Dependencies**

**Server**

* Public Static Network IP
* Hardware(Recommend)
  * CPU: 16
  * Memory: 32G
  * Disk: 600GB
* OS
  * Unix
* Software
  * Docker
  * Docker Compose

**Set firewall rule**

| Port range | Protocol | Source    |
| ---------- | -------- | --------- |
| 22         | TCP      | 0.0.0.0/0 |
| 9000       | UDP      | 0.0.0.0/0 |

**Installation**

Clone this repository:

```
git clone --recurse-submodules https://github.com/ParaState/SafeStakeOperator dvf
cd dvf
```

Install Docker and Docker Compose

* [install docker engine](https://docs.docker.com/engine/install/)
* [install docker compose](https://docs.docker.com/compose/install/)

Build root node:

```
sudo docker compose -f docker-compose-boot.yml build
```

**Start Service**

Run the following to start the root node service:

```
sudo docker compose -f docker-compose-boot.yml up -d
```

Get root node enr

```
docker-compose -f docker-compose-boot.yml logs -f dvf_root_node | grep enr
```

output

> dvf-dvf\_root\_node-1 | Base64 ENR: _enr:-IS4QNa-kpJM1eWfueeEnY2iXlLAL0QY2gAWAhmsb4c8VmrSK9J7N5dfXS\_DgSASCDrUTHMqMUlP4OXSYEVh-Z7zFHkBgmlkgnY0gmlwhAMBnbWJc2VjcDI1NmsxoQPKY0yuDUmstAHYpMa2\_oxVtw0RW\_QAdpzBQA8yWM0xOIN1ZHCCIy0_

_**NOTE:**_  SafeStake will maintain the ENR(s) of the root node(s) on its website so that users registering as operators can utilize them to start operator nodes.

{% hint style="success" %}
**`<The SafeStake Service Provider is now installed/>`**
{% endhint %}

### **Deploy the Operator node**

#### Dependencies

#### Server Host

* Public Static Network IP
* Hardware
  * (SingleNode Mode Recommend)
    * CPU: 16
    * Memory: 32G
    * Disk: 600GB
  * (MultiNode Mode Recommend)
    * CPU: 2
    * Memory: 4G
    * Disk: 200GB
* OS
  * Unix
* Software
  * Docker
  * Docker Compose

#### **Running Mode Of Operator Node**

`SingleNode Mode`

SingleNode mode contains the following list of programs/soft Run on a single host:
* Geth Service
* Lighthouse Service
* OperatorNode Service

`MultiNode Mode`

MultiNode mode contains only Operator Node service, the following list of programs/soft:
* OperatorNode Service （Stand-alone deployment）

* Geth Service (Dedicated Host deployment)
* Lighthouse Service (Dedicated Host deployment)


> Geth service and Lighthouse service run on other hosts.
The purpose of this is to make the architecture clearer and easier to scale operator nodes. And the cost efficiency ratio of infrastructure will be higher.
As a result, the deployment document is divided into two architectural patterns of deployment


#### Get your Infura WS\_URL

* Follow the instructions found at [https://docs.infura.io/infura/](https://docs.infura.io/infura/)
* Create Infura account (or other Ethereum api service providers)
* Create new key

<figure><img src=".gitbook/assets/image (8).png" alt=""><figcaption></figcaption></figure>

* Select 'Goerli' network

<figure><img src=".gitbook/assets/image (10) (1).png" alt=""><figcaption></figcaption></figure>

* Select Websock

<figure><img src=".gitbook/assets/image.png" alt=""><figcaption></figcaption></figure>

* Copy your WS\_URL

#### Use your own configuration

Fill your WS\_URL

#### Or get your alchemy ws\_url

* Follow the document [https://docs.alchemy.com/reference/api-overview](https://docs.alchemy.com/reference/api-overview)
* Regiter a alchemy account
* Create new app

> [![alchemy step1](https://github.com/ParaState/SafeStakeOperator/raw/main/imgs/alchemy-step1.png?raw=true)](imgs/alchemy-step1.png)

* Select Goerli network

> [![alchemy step2](https://github.com/ParaState/SafeStakeOperator/raw/main/imgs/alchemy-step2.png?raw=true)](imgs/alchemy-step2.png)

* Select your app and view key

> [![alchemy step3](https://github.com/ParaState/SafeStakeOperator/raw/main/imgs/alchemy-step3.png?raw=true)](imgs/alchemy-step3.png)

* Select WEBSOCKETS and copy

> [![alchemy step4](https://github.com/ParaState/SafeStakeOperator/raw/main/imgs/alchemy-step4.png?raw=true)](imgs/alchemy-step4.png)

Save the WSS Socket URL, which will be used later.


### SingleNode Mode Installation steps

#### Set firewall rule

Log in to your host cloud service provider,open the following rules:
![](<.gitbook/assets/image (3).png>)

#### Installation

#### Login to your server ([jumpserver](https://www.jumpserver.org/) recommand)

#### Install Docker and Docker compose

* [install docker engine](https://docs.docker.com/engine/install/)
* [install docker compose](https://docs.docker.com/compose/install/)

#### Enable docker service and start it immediately.

```
 sudo systemctl enable docker
```

#### Create local volume directory

```
 sudo mkdir -p /data/geth
 sudo mkdir -p /data/lighthouse
 sudo mkdir -p /data/jwt
 sudo mkdir -p /data/operator
```

#### Generate your jwt secret to jwt dirctory

```
openssl rand -hex 32 | tr -d "\n" | sudo tee /data/jwt/jwtsecret
```

#### Clone operator code from Github

```
git clone --recurse-submodules https://github.com/ParaState/SafeStakeOperator.git dvf
```

```
cd dvf
cp .env.example .env
```
We will modify the values based on the actual configuration of the different environments.

`Testnet`

Changeless:
```bash
ENR=enr:-IS4QKIF_55zNM3o29E91Rj2gwjTQJHvnGVW8e--2nvsixCXCKbS0vhuBILafB1qv3AyR2GhKt611zf_x5V6zwGEmEwBgmlkgnY0gmlwhBKIH16Jc2VjcDI1NmsxoQNsOWU-IpJ0fRj4WlVELfC5HLLhzhHZr9HMsN401NGJdYN1ZHCCIy0
GETH_NETWORK=goerli
LIGHTHOUSE_NETWORK=prater
OPERATOR_NETWORK=prater
IMAGE_TAG=staging
CONTRACT_ADDRESS=93Ec63F53Fd7362CEAb5A70F1c1B1BD5B49eeb81
REGISTRY_CONTRACT_ADDRESS=c5e19f5f5EB1E051b3A0c2Ea0C00d6DDCBD9662a
NETWORK_CONTRACT_ADDRESS=Cd22Bd1E42e0BD56Fc21900EDB38268F451d59B3
API_SERVER=https://api-testnet.safestake.xyz/v1/collect_performance
# different chain has different ttd
TTD=10790000
# separated by ',' for multiple relays, such as MEV_BOOST_RELAYS=xxx,xxx,xxx
MEV_BOOST_RELAYS=https://0xafa4c6985aa049fb79dd37010438cfebeb0f2bd42b115b89dd678dab0670c1de38da0c4e9138c9290a398ecd9a0b3110@boost-relay-goerli.flashbots.net
#gas limit. [default: 30,000,000]
GAS_LIMIT_INTEGER=30000000
```

Change
```bash
WS_URL= #YOUR WSS URL
OPERATOR_ID= #The Operator ID is the ID registered to the website
BEACON_NODE_ENDPOINT=http://127.0.0.1:5052 # Depending on whether you are running single-node mode or multi-node mode, fill in the correct Lighthouse service url
```
After modifying to the correct value, you can start the next step of actually running the Operator service


### Run Operator Node(SingleNode Mode)

#### Generate a registration public and private key
```bash
sudo docker compose -f docker-compose-operator.yml up dvf_key_tool
```
Output:
```
...
dvf-dvf_key_tool-1  | INFO: node public key AtzozvDHiWUpO+oJph2ikv+EyBN5pdBXsfgZqLi0+Yqd
dvf-dvf_key_tool-1 exited with code 0
```
Save the public key, which will be used later. We need this key when registering Operator on the website.


#### Start operator service

Before running, modify the following env var：
```bash
WS_URL= #YOUR WSS URL
OPERATOR_ID= #The Operator ID is the ID registered to the website
BEACON_NODE_ENDPOINT=http://127.0.0.1:5052 # Depending on whether you are running single-node mode or multi-node mode, fill in the correct Lighthouse service url
```

```bash
sudo docker compose -f  docker-compose-operator.yml up -d
```
---

### Run Operator Node(MultiNode Mode)

#### Generate a registration public and private key
```bash
sudo docker compose -f docker-compose-operator.yml up dvf_key_tool
```
Output:
```
...
dvf-dvf_key_tool-1  | INFO: node public key AtzozvDHiWUpO+oJph2ikv+EyBN5pdBXsfgZqLi0+Yqd
dvf-dvf_key_tool-1 exited with code 0
```
Save the public key, which will be used later. We need this key when registering Operator on the website.

After we register on the Safestake website, we will be shown our OPERATOR ID, which is the unique identifier we need to start with. Then we need to update the OPERATOR ID to the `.env` file before running the operator service. 

#### Start Lighthouse & Geth Service at Dedicated Host

**Beacon Host**

```bash
sudo docker compose -f docker-compose-operator.yml up geth -d
sudo docker compose -f docker-compose-operator.yml up lighthouse -d
```

Tips: Remember to open the 5052 firewall port for this host

#### Start operator serivce

**Operator Host**

Before running, modify the following env var：

```bash
WS_URL= #YOUR WSS URL
OPERATOR_ID= #The Operator ID is the ID registered to the website
BEACON_NODE_ENDPOINT=http://10.1.2.8:5052 # Fill in the beacon host's IP address
```

Start operator container：

```bash
sudo docker compose -f docker-compose-operator.yml up operator -d
```
---
Congratulations, now that the OP program has been installed and deployed, the rest we can go to the website to register.
 

#### Obtain your operator public key

```
sudo docker compose -f docker-compose-operator.yml logs -f operator | grep "node public key"
```

output

> dvf-operator-1 | \[2022-08-13T16:01:33.814Z INFO dvf::node::node] node public key Al0wMNz3JpkYDH7HVp93dZfLMt1GJHypLfhwOWS0NwC/

#### Back up your operator private key file

> **Keep it safe and put it in a safe place!**

path

```
/data/operator/prater/node_key.json
```

{% hint style="success" %}
**`<Your SafeStake Operator Node is now configured/>`**
{% endhint %}

##
