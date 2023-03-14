use types::{Hash256, Signature, Keypair, PublicKey};
use std::sync::Arc;
use crate::utils::error::DvfError;
use network::{ReliableSender, SimpleSender, DvfMessage, VERSION};
use std::net::SocketAddr;
use bytes::Bytes;
use downcast_rs::DowncastSync;
use std::time::Duration;
use tokio::time::{timeout, sleep_until, Instant};
use log::{info, warn};
use async_trait::async_trait;

pub enum OperatorMessage {
}

#[async_trait]
pub trait TOperator: DowncastSync + Sync + Send {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>; 
    fn public_key(&self) -> PublicKey;
    async fn propose(&self, msg: Hash256);
}
impl_downcast!(sync TOperator);

pub struct LocalOperator {
    pub validator_id: u64,
    pub operator_id: u64,
    pub operator_keypair: Arc<Keypair>,
    pub transaction_address: SocketAddr,
    network: SimpleSender,
}

#[async_trait]
impl TOperator for LocalOperator {

    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        Ok(self.operator_keypair.sk.sign(msg))
    }

    fn public_key(&self) -> PublicKey {
        self.operator_keypair.pk.clone()
    }

    async fn propose(&self, msg: Hash256) {
        info!("[Dvf {}/{}] Proposing msg {}", self.operator_id, self.validator_id, msg);
        let dvf_message = DvfMessage { version: VERSION, validator_id: self.validator_id, message: msg.to_fixed_bytes().to_vec()};
        self.network.send(self.transaction_address, Bytes::from(bincode::serialize(&dvf_message).unwrap())).await;
    }
}

impl LocalOperator {
    pub fn new(validator_id: u64, operator_id: u64, operator_keypair: Arc<Keypair>, transaction_address: SocketAddr) -> Self {
        Self {
            validator_id,
            operator_id,
            operator_keypair,
            transaction_address,
            network: SimpleSender::new(),
        }
    }
}

pub struct RemoteOperator {
    pub validator_id: u64,
    pub operator_id: u64,
    pub operator_public_key: PublicKey,
    pub signature_address: SocketAddr,
    network: ReliableSender,
}

#[async_trait]
impl TOperator for RemoteOperator {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> { 
        let n_try: u64 = 3;
        let timeout_mill :u64 = 400;
        let dvf_message = DvfMessage { version: VERSION, validator_id: self.validator_id, message: msg.to_fixed_bytes().to_vec()};
        let serialize_msg = bincode::serialize(&dvf_message).unwrap();
        for i in 0..n_try {
            let next_try_instant = Instant::now() + Duration::from_millis(timeout_mill);
            let receiver = self.network.send(self.signature_address, Bytes::from(serialize_msg.clone())).await;
            let result = timeout(Duration::from_millis(timeout_mill), receiver).await; 
            match result {
                Ok(output) => {
                    match output {
                        Ok(data) => {
                            match bincode::deserialize::<Signature>(&data) {
                                Ok(bls_signature) =>{
                                    info!("Received a signature from operator {}/{} ({:?})", self.operator_id, self.validator_id, self.signature_address);
                                    return Ok(bls_signature);
                                }
                                Err(_) => {
                                    warn!("Deserialize failed from operator {}/{}, retry...", self.operator_id, self.validator_id);
                                }
                            }
                        },
                        Err(_) => {
                            warn!("recv is interrupted.");
                        }
                    }
                },
                Err(_) => {
                    warn!("Retry from operator {}/{}", self.operator_id, self.validator_id);
                }
            }
            if i < n_try - 1 {
                sleep_until(next_try_instant).await;
            }
        }
        warn!("Failed to receive a signature from operator {}/{} ({:?})", self.operator_id, self.validator_id, self.signature_address);
        Err(DvfError::Unknown)
    }

    fn public_key(&self) -> PublicKey {
        self.operator_public_key.clone()
    }

    async fn propose(&self, _msg: Hash256) { }

}

impl RemoteOperator {
    pub fn new(validator_id: u64, operator_id: u64, operator_public_key: PublicKey, signature_address: SocketAddr) -> Self {
        Self {
            validator_id,
            operator_id,
            operator_public_key,
            signature_address, 
            network: ReliableSender::new(),
        }
    }

}

