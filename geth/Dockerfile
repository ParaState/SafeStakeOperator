FROM ubuntu:22.04
RUN apt update && \
apt-get -y upgrade && \
apt-get install -y --no-install-recommends libssl-dev \
curl ca-certificates && \
gpg --keyserver keyserver.ubuntu.com --recv-keys 2a518c819be37d2c2031944d1c52189c923f6ca9 && \
gpg --export --armor 2a518c819be37d2c2031944d1c52189c923f6ca9 | apt-key add - && \ 
echo -e "deb http://ppa.launchpad.net/ethereum/ethereum/ubuntu focal main" | tee /etc/apt/sources.list.d/ethereum-ubuntu-ethereum-xenial.list && \
apt update && apt-get install -y ethereum && apt-get clean && \
rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["./docker-entrypoint"]
