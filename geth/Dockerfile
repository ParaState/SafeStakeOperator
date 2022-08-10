FROM ubuntu:20.04
RUN apt update && \
apt install -y --no-install-recommends software-properties-common && \
add-apt-repository -y ppa:ethereum/ethereum && \
apt -y install telnet geth && \ 
apt-get clean && \
rm -rf /var/lib/apt/lists/*

COPY . /app
RUN ["chmod", "+x", "/app/docker-entrypoint"]

ENTRYPOINT ["/app/docker-entrypoint"]
