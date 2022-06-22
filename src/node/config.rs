use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use crate::DEFAULT_DVF_ROOT_DIR;

#[derive(Clone)]
pub struct NodeConfig {
    pub base_port: u16, 
    pub tx_receiver_address: SocketAddr,
    pub mempool_receiver_address: SocketAddr,
    pub consensus_receiver_address: SocketAddr,
    pub dvfcore_receiver_address: SocketAddr,
    pub signature_receiver_address: SocketAddr,
    pub base_store_path: PathBuf,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self::new(
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            25000
        ) 
    }
}

impl NodeConfig {
    fn new(ip: IpAddr, base_port: u16) -> Self {
        let base_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_DVF_ROOT_DIR);
        let base_store_path = base_dir.join("dvf_node_db");
        Self {
            base_port: base_port,
            tx_receiver_address: SocketAddr::new(ip.clone(), base_port),
            mempool_receiver_address: SocketAddr::new(ip.clone(), base_port + 1),
            consensus_receiver_address: SocketAddr::new(ip.clone(), base_port + 2),
            dvfcore_receiver_address: SocketAddr::new(ip.clone(), base_port + 3),
            signature_receiver_address: SocketAddr::new(ip.clone(), base_port + 4),
            base_store_path
        }
    }

    pub fn set_base_port(mut self, new_port: u16) -> Self {
        self.base_port = new_port;
        self.tx_receiver_address.set_port(new_port);
        self.mempool_receiver_address.set_port(new_port + 1);
        self.consensus_receiver_address.set_port(new_port + 2);
        self.dvfcore_receiver_address.set_port(new_port + 3);
        self.signature_receiver_address.set_port(new_port + 4);
        self
    }
}
