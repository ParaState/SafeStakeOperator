use std::sync::Arc;
use crate::utils::error::DvfError;
use crate::validation::operator::{TOperator};
use types::{Hash256, Signature, PublicKey};
use tokio::sync::{RwLock};
use tokio::sync::mpsc::{Receiver};
use async_trait::async_trait;


/// Operator committee for a validator. 
/// 
#[async_trait]
pub trait TOperatorCommittee : Send {
    fn new(validator_id: u64, validator_public_key: PublicKey, t: usize, rx_consensus: Receiver<Hash256>) -> Self;
    fn validator_id(&self) -> u64;
    async fn add_operator(&mut self, operator_id: u64, operator: Arc<RwLock<dyn TOperator>>); 
    async fn consensus(&self, msg: Hash256) -> Result<(), DvfError>;
    async fn sign(&self, msg: Hash256) -> Result<(Signature, Vec<u64>), DvfError>;
    async fn get_leader(&self, nonce: u64) -> u64;
    async fn get_op_pos(&self, op_id: u64) -> usize;
    fn get_validator_pk(&self) -> String;
    fn threshold(&self) -> usize;
}

/// Generic operator committee who delegates most functionalities to an underlying committee implementation (specified through the generic type parameter)
pub struct GenericOperatorCommittee<Committee> {
    cmt: Committee 
}

impl <Committee> GenericOperatorCommittee<Committee> 
where
    Committee: TOperatorCommittee
{
    pub fn new(validator_id: u64, validator_public_key: PublicKey, threshold: usize, rx_consensus: Receiver<Hash256>) -> Self {
        Self {
            cmt: TOperatorCommittee::new(validator_id, validator_public_key, threshold, rx_consensus)
        }
    }

    pub fn validator_id(&self) -> u64 {
        self.cmt.validator_id()
    }

    pub async fn add_operator(&mut self, operator_id: u64, operator: Arc<RwLock<dyn TOperator>>) {
        self.cmt.add_operator(operator_id, operator).await;
    }

    pub fn threshold(&self) -> usize {
        self.cmt.threshold()
    }

    pub async fn sign(&self, msg: Hash256) -> Result<(Signature, Vec<u64>), DvfError> {
        self.cmt.sign(msg).await
    }

    pub async fn get_leader(&self, nonce: u64) -> u64 {
        self.cmt.get_leader(nonce).await
    }

    pub fn get_validator_pk(&self) -> String {
        self.cmt.get_validator_pk()
    }

    pub fn get_op_pos(&self, op_id: u64) -> usize {
        self.cmt.get_op_pos(op_id)
    }
}


