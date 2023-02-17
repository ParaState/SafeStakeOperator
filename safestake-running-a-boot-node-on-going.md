# SafeStake: Running a Boot Node (on going)

{% hint style="danger" %}
**Updates happen frequently! Our** [**Github**](https://github.com/ParaState/SafeStakeOperator) **always has the latest operator node resources and setup instructions.**
{% endhint %}

***NOTE: This tutorial is meant for SafeStake admininistrator. You DON'T need to read this if you are a user who wants to setup an operator node. Instead, you should read the [tutorial for operator node](./safestake-running-an-operator-node-on-going.md).***


## **Boot Node Service**

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

_**NOTE:**_  SafeStake will maintain the ENR(s) of the boot node(s) on its website so that users registering as operators can utilize them to start operator nodes.

{% hint style="success" %}
**`<The boot node is now ready to be used./>`**
{% endhint %}
