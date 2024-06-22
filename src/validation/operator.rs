use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::node::config::{
    base_to_consensus_addr, base_to_mempool_addr, base_to_signature_addr, base_to_transaction_addr,
    is_addr_invalid,
};
use crate::utils::error::DvfError;
use async_trait::async_trait;
use bytes::Bytes;
use downcast_rs::DowncastSync;
use log::{debug, warn};
use network::{DvfMessage, ReliableSender, SimpleSender, VERSION};
use tokio::time::{sleep_until, timeout, Instant};
use types::{Hash256, Keypair, PublicKey, Signature};

pub enum OperatorMessage {}

#[async_trait]
pub trait TOperator: DowncastSync + Sync + Send {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>;
    fn public_key(&self) -> PublicKey;
    async fn propose(&self, msg: Hash256);
    fn base_address(&self) -> SocketAddr;
    fn transaction_address(&self) -> SocketAddr {
        base_to_transaction_addr(self.base_address())
    }
    fn mempool_address(&self) -> SocketAddr {
        base_to_mempool_addr(self.base_address())
    }
    fn consensus_address(&self) -> SocketAddr {
        base_to_consensus_addr(self.base_address())
    }
    fn signature_address(&self) -> SocketAddr {
        base_to_signature_addr(self.base_address())
    }
}
impl_downcast!(sync TOperator);

pub struct LocalOperator {
    pub validator_id: u64,
    pub operator_id: u64,
    pub operator_keypair: Arc<Keypair>,
    pub base_address: SocketAddr,
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
        debug!(
            "[Dvf {}/{}] Proposing msg {}",
            self.operator_id, self.validator_id, msg
        );
        let dvf_message = DvfMessage {
            version: VERSION,
            validator_id: self.validator_id,
            message: msg.to_fixed_bytes().to_vec(),
        };
        self.network
            .send(
                self.transaction_address(),
                Bytes::from(bincode::serialize(&dvf_message).unwrap()),
            )
            .await;
    }

    fn base_address(&self) -> SocketAddr {
        self.base_address
    }
}

impl LocalOperator {
    pub fn new(
        validator_id: u64,
        operator_id: u64,
        operator_keypair: Arc<Keypair>,
        base_address: SocketAddr,
    ) -> Self {
        Self {
            validator_id,
            operator_id,
            operator_keypair,
            base_address,
            network: SimpleSender::new(),
        }
    }
}

pub struct RemoteOperator {
    pub validator_id: u64,
    pub operator_id: u64,
    pub operator_public_key: PublicKey,
    // pub signature_address: SocketAddr,
    pub base_address: SocketAddr,
    network: ReliableSender,
}

#[async_trait]
impl TOperator for RemoteOperator {
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        // skip this function quickly
        if is_addr_invalid(self.base_address()) {
            return Err(DvfError::SocketAddrUnknown);
        }

        let n_try: u64 = 2;
        let timeout_mill: u64 = 600;
        let sleep_mill: u64 = 300;
        let dvf_message = DvfMessage {
            version: VERSION,
            validator_id: self.validator_id,
            message: msg.to_fixed_bytes().to_vec(),
        };
        let serialize_msg = bincode::serialize(&dvf_message).unwrap();
        for i in 0..n_try {
            let receiver = self
                .network
                .send(self.signature_address(), Bytes::from(serialize_msg.clone()))
                .await;
            let result = timeout(Duration::from_millis(timeout_mill), receiver).await;
            match result {
                Ok(output) => match output {
                    Ok(data) => match bincode::deserialize::<Signature>(&data) {
                        Ok(bls_signature) => {
                            debug!(
                                "Received a signature from operator {}/{} ({:?})",
                                self.operator_id,
                                self.validator_id,
                                self.signature_address()
                            );
                            return Ok(bls_signature);
                        }
                        Err(_) => {
                            warn!(
                                "Deserialize failed from operator {}/{}, retry..., msg: {:?} received data: {:?}",
                                self.operator_id, self.validator_id, msg, std::str::from_utf8(&data)
                            );
                        }
                    },
                    Err(_) => {
                        warn!("recv is interrupted.");
                    }
                },
                Err(e) => {
                    warn!(
                        "Retry from operator {}/{}, error: {}",
                        self.operator_id, self.validator_id, e
                    );
                }
            }
            if i < n_try - 1 {
                let next_try_instant = Instant::now() + Duration::from_millis(sleep_mill);
                sleep_until(next_try_instant).await;
            }
        }
        warn!(
            "Failed to receive a signature from operator {}/{} ({:?})",
            self.operator_id,
            self.validator_id,
            self.signature_address()
        );
        Err(DvfError::Unknown)
    }

    fn public_key(&self) -> PublicKey {
        self.operator_public_key.clone()
    }

    async fn propose(&self, _msg: Hash256) {}

    fn base_address(&self) -> SocketAddr {
        self.base_address
    }
}

impl RemoteOperator {
    pub fn new(
        validator_id: u64,
        operator_id: u64,
        operator_public_key: PublicKey,
        base_address: SocketAddr,
    ) -> Self {
        Self {
            validator_id,
            operator_id,
            operator_public_key,
            base_address,
            network: ReliableSender::new(),
        }
    }
}
