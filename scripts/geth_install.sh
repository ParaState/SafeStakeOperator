add-apt-repository -y --remove ppa:ethereum/ethereum
apt update
apt-key del 2A518C819BE37D2C2031944D1C52189C923F6CA9
gpg --keyserver keyserver.ubuntu.com --recv-keys 2a518c819be37d2c2031944d1c52189c923f6ca9
gpg --export --armor 2a518c819be37d2c2031944d1c52189c923f6ca9 | apt-key add -
echo -e "deb http://ppa.launchpad.net/ethereum/ethereum/ubuntu focal main" | tee /etc/apt/sources.list.d/ethereum-ubuntu-ethereum-xenial.list
apt update
apt-get install -y ethereum
