use types::{Hash256, Signature, Keypair, PublicKey};
use std::sync::Arc;
use crate::utils::error::DvfError;
use std::net::SocketAddr;
use node::dvfcore::SignatureInfo;
use network::SimpleSender;
use bytes::Bytes;
use tokio::sync::mpsc::{self, Receiver};
use futures::executor::block_on;
use std::collections::HashSet;
use downcast_rs::DowncastSync;

pub enum OperatorMessage {
}

pub trait TOperator: DowncastSync + Sync + Send {
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>; 
    fn public_key(&self) -> PublicKey;
}
impl_downcast!(sync TOperator);

pub struct LocalOperator {
    pub id: u64,
    pub voting_keypair: Arc<Keypair>,
    pub send_channel: mpsc::UnboundedSender<OperatorMessage>,
    pub recv_channel: mpsc::UnboundedReceiver<OperatorMessage>,
}

impl TOperator for LocalOperator {

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        Ok(self.voting_keypair.sk.sign(msg))
    }

    fn public_key(&self) -> PublicKey {
        self.voting_keypair.pk.clone()
    }
}

impl LocalOperator {
    pub fn new(id: u64, keypair: Arc<Keypair>) -> Self {
        let (send_channel, recv_channel) = mpsc::unbounded_channel(); 
        Self {
            id,
            voting_keypair: keypair,
            send_channel,
            recv_channel
        }
    }
}

pub struct HotStuffOperator {
    pub voting_keypair: Arc<Keypair>,
    pub network: SimpleSender,
    pub address: SocketAddr,
    pub rx_signature: Receiver<SignatureInfo>
}

impl TOperator for HotStuffOperator {

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        Ok(self.voting_keypair.sk.sign(msg))
    }

    fn public_key(&self) -> PublicKey {
        self.voting_keypair.pk.clone()
    }
}

impl HotStuffOperator {
    pub fn new(keypair: Arc<Keypair>, address: SocketAddr, rx_signature: Receiver<SignatureInfo>) -> Self {
        Self {
            voting_keypair: keypair,
            network: SimpleSender::new(),
            address: address,
            rx_signature: rx_signature
        }
    }

    /// send msg to network for consensus
    pub async fn propose(&mut self, msg: Hash256) {
        // prefix id is fixed 
        // update
        let validator_vec : Vec<u8>= vec![50; 88];
        let validator_id = String::from_utf8(validator_vec).unwrap();
        let mut prefix_msg : Vec<u8> = Vec::new();
        prefix_msg.extend(validator_id.into_bytes());
        prefix_msg.extend(msg.to_fixed_bytes().to_vec());
        self.network.send(self.address, Bytes::from(prefix_msg)).await;
    }

    pub async fn wait_signature(&mut self) -> Vec<SignatureInfo>{
        let mut received = 0;
        let mut ids = HashSet::<u64>::new();
        let mut res = Vec::new();
        loop {
            if let Some(signature_info) = self.rx_signature.recv().await {
                if ids.contains(&signature_info.id)  {
                    continue;
                } else {
                    ids.insert(signature_info.id);
                    res.push(signature_info);
                    received+=1;
                }
                if received == 10 {
                    break;
                }
                    
            }
        }
        res
    }
}

pub struct RemoteOperator {
    pub id: u64,
    pub public_key: PublicKey,
    pub socket_address: SocketAddr,
}

impl TOperator for RemoteOperator {
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> { 
        Err(DvfError::Unknown)
    }

    fn public_key(&self) -> PublicKey {
        self.public_key.clone()
    }
}

