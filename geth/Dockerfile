FROM ubuntu:22.04
RUN apt update && \
apt install -y --no-install-recommends software-properties-common && \
add-apt-repository -y ppa:ethereum/ethereum && \
apt -y install geth && \ 
apt-get clean && \
rm -rf /var/lib/apt/lists/*

ENTRYPOINT ["./docker-entrypoint"]
