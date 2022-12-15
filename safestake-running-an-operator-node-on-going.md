# SafeStake: Running an Operator Node (on going)

{% hint style="danger" %}
**Updates happen frequently! Our** [**Github**](https://github.com/ParaState/SafeStakeOperator) **always has the latest operator node resources and setup instructions.**
{% endhint %}

**Operators must first set up a SafeStake Service Provider Node**

The SafeStake service provider contains several components:

* A web server and frontend
* A nodejs backend (to communicate with operators)
* A root node service (for peer discovery in a p2p network)

**Root Node Service**

The duty agreement among operators uses Hotstuff consensus and runs on a p2p network. This requires operators to know each other's IP addresses. For this purpose, SafeStake runs and maintains a root node that operators can consult and use to join the p2p network.

**Dependencies**

**Server**

* Public Static Network IP
* Hardware(recommend)
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

_**NOTE:**_\*\* \*\* SafeStake will maintain the ENR(s) of the root node(s) on its website so that users registering as operators can utilize them to start operator nodes\_**.**\_

{% hint style="success" %}
**`<The SafeStake Service Provider is now installed/>`**
{% endhint %}

### **Deploy the Operator node**

#### Dependencies

#### Server

* Public Static Network IP
* Hardware(recommend)
  * CPU: 16
  * Memory: 32G
  * Disk: 600GB
* OS
  * Unix
* Software
  * Docker
  * Docker Compose

#### Set firewall rule

![](<.gitbook/assets/image (3).png>)

### Installation

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

#### Use your own configuration

```
vim .env
```

Fill your WS\_URL

### Run

#### Run your operator

```
sudo docker compose -f  docker-compose-operator.yml up -d
```

#### Obtain your operator public key

```
sudo docker compose -f docker-compose-operator.yml logs -f operator | grep "node public key"
```

output

> dvf-operator-1 | \[2022-08-13T16:01:33.814Z INFO dvf::node::node] node public key Al0wMNz3JpkYDH7HVp93dZfLMt1GJHypLfhwOWS0NwC/

#### Back up your operator private key file

path

```
/data/operator/prater/node_key.json
```

{% hint style="success" %}
**`<Your SafeStake Operator Node is now configured/>`**
{% endhint %}

##
