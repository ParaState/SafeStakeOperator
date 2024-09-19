use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use crate::node::config::{
    base_to_active_addr, base_to_consensus_addr, base_to_duties_addr, base_to_mempool_addr,
    base_to_signature_addr, base_to_transaction_addr, is_addr_invalid,
};
use crate::node::dvfcore::DutyConsensusResponse;
use crate::utils::error::DvfError;
use async_trait::async_trait;
use bytes::Bytes;
use downcast_rs::DowncastSync;
use log::{debug, info, warn, error};
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
    fn duties_address(&self) -> SocketAddr {
        base_to_duties_addr(self.base_address())
    }
    fn active_address(&self) -> SocketAddr {
        base_to_active_addr(self.base_address())
    }
    async fn consensus_on_duty(&self, msg: &[u8]);
    async fn is_active(&self) -> bool;
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

    async fn consensus_on_duty(&self, _msg: &[u8]) {
        return;
    }

    async fn is_active(&self) -> bool {
        true
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

        let n_try: u64 = 3;
        let timeout_mill: u64 = 600;
        let sleep_mill: u64 = 200;
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
                            debug!(
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

    async fn consensus_on_duty(&self, msg: &[u8]) {
        // skip this function quickly
        if is_addr_invalid(self.base_address()) {
            warn!("invalid socket address");
            return;
        }
        let n_try: u64 = 1;
        let timeout_mill: u64 = 800;
        let sleep_mill: u64 = 300;
        let dvf_message = DvfMessage {
            version: VERSION,
            validator_id: self.validator_id,
            message: msg.to_vec(),
        };

        let serialize_msg = bincode::serialize(&dvf_message).unwrap();
        for i in 0..n_try {
            let receiver = self
                .network
                .send(self.duties_address(), Bytes::from(serialize_msg.clone()))
                .await;
            let result = timeout(Duration::from_millis(timeout_mill), receiver).await;
            match result {
                Ok(output) => match output {
                    Ok(data) => {
                        let resp = match bincode::deserialize::<DutyConsensusResponse>(&data) {
                            Ok(r) => r,
                            Err(e) => {
                                error!("failed to deserialize response data, {:?}", e);
                                return;
                            }
                        };
                        info!(
                            "Received consensus response from [{}/{}]: {:?}",
                            self.operator_id, self.validator_id, resp
                        );
                    }
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
    }

    async fn is_active(&self) -> bool {
        // skip this function quickly
        if is_addr_invalid(self.base_address()) {
            warn!("invalid socket address");
            return false;
        }

        let n_try: u64 = 1;
        let timeout_mill: u64 = 200;
        let sleep_mill: u64 = 300;
        let random_hash = Hash256::random();
        let dvf_message = DvfMessage {
            version: VERSION,
            validator_id: self.validator_id,
            message: random_hash.to_fixed_bytes().to_vec(),
        };

        let serialize_msg = bincode::serialize(&dvf_message).unwrap();
        for i in 0..n_try {
            let receiver = self
                .network
                .send(self.active_address(), Bytes::from(serialize_msg.clone()))
                .await;
            let result = timeout(Duration::from_millis(timeout_mill), receiver).await;
            match result {
                Ok(output) => match output {
                    Ok(data) => match bincode::deserialize::<Signature>(&data) {
                        Ok(sig) => {
                            return sig.verify(&self.operator_public_key, random_hash);
                        }
                        Err(_) => {
                            return false;
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
        false
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

#[tokio::test]
async fn remote_operator_test() {
    let mut logger =
        env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();
    let validator_id = 1888062277302860207;
    let operator_id = 3;
    let operator_public_key = PublicKey::deserialize(&hex::decode("86b85f1340b60b7f0c0fc73ef9ca59ce6ea8efc82c8d8d6590d2bf4fc34c9936779090932f19484b6a6942eb93d5e1c5").unwrap()).unwrap();
    let remote_operator = RemoteOperator::new(
        validator_id,
        operator_id,
        operator_public_key,
        "13.228.88.177:26000".parse().unwrap(),
    );
    remote_operator
        .sign(Hash256::from_slice(
            &hex::decode("6524c8437429bbb3fe6490a57a604986481d9f52d0ea72ddd08fd131ac6d0ffc")
                .unwrap(),
        ))
        .await
        .unwrap();
}
