use std::sync::Arc;
use crate::utils::error::DvfError;
use crate::validation::operator::{TOperator};
use types::{Hash256, Signature, PublicKey};
use tokio::sync::{RwLock};
use tokio::sync::mpsc::{Receiver};
use async_trait::async_trait;


/// Operator committee for a validator. 
#[async_trait]
pub trait TOperatorCommittee {
    fn new(id: u64, validator_public_key: PublicKey, t: usize, rx_consensus: Receiver<Hash256>) -> Self;
    async fn add_operator(&mut self, id: u64, operator: Arc<RwLock<dyn TOperator>>); 
    async fn consensus(&self, msg: Hash256) -> Result<(), DvfError>;
    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>;
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
    pub fn new(id: u64, validator_public_key: PublicKey, threshold: usize, rx_consensus: Receiver<Hash256>) -> Self {
        Self {
            cmt: TOperatorCommittee::new(id, validator_public_key, threshold, rx_consensus)
        }
    }

    pub async fn add_operator(&mut self, id: u64, operator: Arc<RwLock<dyn TOperator>>) {
        self.cmt.add_operator(id, operator).await;
    }

    pub fn threshold(&self) -> usize {
        self.cmt.threshold()
    }

    pub async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        self.cmt.sign(msg).await
    }
}


