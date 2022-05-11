use types::{Hash256, Signature, Keypair, PublicKey};
use std::sync::Arc;
use crate::utils::error::DvfError;
use tokio::sync::mpsc;
use std::net::SocketAddr;

pub enum OperatorMessage {
}

pub trait TOperator: Sync + Send {
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>; 
    fn public_key(&self) -> Result<&PublicKey, DvfError>;
}

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

    fn public_key(&self) -> Result<&PublicKey, DvfError> {
        Ok(&self.voting_keypair.pk)
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

pub struct RemoteOperator {
    pub id: u64,
    pub public_key: PublicKey,
    pub socket_address: SocketAddr,
}

impl TOperator for RemoteOperator {
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> { 
        Err(DvfError::Unknown)
    }

    fn public_key(&self) -> Result<&PublicKey, DvfError> {
        Err(DvfError::Unknown)  
    }
}

