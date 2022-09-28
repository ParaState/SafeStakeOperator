# Project SafeStake Operator Node

**Description**:  
SafeStake is a decentralized validation framework for performing ETH2 duties and its backend is designed on top of Lighthouse (ETH2 consensus client) and Hotstuff (a BFT consensus library).

## Dependencies
### Server 

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

### Set firewall rule
![firewall rule](https://github.com/ParaState/SafeStakeOperator/blob/main/imgs/firewall_rule.png?raw=true)

## Installation

### Login your server([jumpserver](https://www.jumpserver.org/) recommand)
### Install Docker and Docker compose
* [install docker engine](https://docs.docker.com/engine/install/)
* [install docker compose](https://docs.docker.com/compose/install/)

### Enable docker service and start it immediately.
```
 sudo systemctl enable docker
```

### Create local volume directory

```
 sudo mkdir -p /data/geth
 sudo mkdir -p /data/lighthouse
 sudo mkdir -p /data/jwt
 sudo mkdir -p /data/operator
```
### Generate your jwt secret to jwt dirctory

```
openssl rand -hex 32 | tr -d "\n" | sudo tee /data/jwt/jwtsecret
```
### Clone operator code from github

```
git clone --recurse-submodules https://github.com/ParaState/SafeStakeOperator.git dvf
```
```
cd dvf
cp .env.example .env
```
### Get your infura ws_url
  - Follow the document [https://docs.infura.io/infura/](https://docs.infura.io/infura/)
  - Regiter a infura account
  - Create new key
  
  > ![infura step1](https://github.com/ParaState/SafeStakeOperator/blob/main/imgs/infura-step1.png?raw=true)
  - Select goerli network
  
  > ![infura step1](https://github.com/ParaState/SafeStakeOperator/blob/main/imgs/infura-step2.png?raw=true)
  
  - Select Websocks
  
  > ![infura step1](https://github.com/ParaState/SafeStakeOperator/blob/main/imgs/infura-step3.png?raw=true)
  
  - Copy your WS_URL

  
  
### Use your own configuration
```
vim .env
```
Fill your WS_URL

## Run
### Build your operator
```
sudo docker-compose -f docker-compose-operator.yml build operator
```
### Run your operator
```
sudo docker-compose -f docker-compose-operator.yml up -d
```
### Get your operator public key
```
sudo docker-compose -f docker-compose-operator.yml logs -f operator | grep "node public key"
```
output
> dvf-operator-1  | [2022-08-13T16:01:33.814Z INFO  dvf::node::node] node public key Al0wMNz3JpkYDH7HVp93dZfLMt1GJHypLfhwOWS0NwC/

### Back up your operator private key file
path

```
/data/operator/prater/node_key.json
```
