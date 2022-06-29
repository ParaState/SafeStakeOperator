use std::collections::HashMap;
use std::sync::{Arc};
use crate::validation::{
    generic_operator_committee::{TOperatorCommittee},
    operator::{TOperator},
};
use crate::crypto::ThresholdSignature;
use crate::utils::error::DvfError;
use bls::{Hash256, Signature, PublicKey};
use tokio::sync::{RwLock};
use tokio::sync::mpsc::{Receiver};
use futures::executor::block_on;
use async_trait::async_trait;


/// Provides the externally-facing operator committee type.
pub mod types {
    pub use super::FakeOperatorCommittee as OperatorCommittee;
}

/// Fake operator committee whose consensus protocol is dummy 
pub struct FakeOperatorCommittee {
    validator_id: u64,
    validator_public_key: PublicKey,
    operators: RwLock<HashMap<u64, Arc<RwLock<dyn TOperator>>>>,
    threshold_: usize,
    rx_consensus: Receiver<Hash256>,
}

#[async_trait]
impl TOperatorCommittee for FakeOperatorCommittee {
    fn new(validator_id: u64, validator_public_key: PublicKey, t: usize, rx_consensus: Receiver<Hash256>) -> Self {
        Self {
            validator_id,
            validator_public_key,
            operators: <_>::default(),
            threshold_: t,
            rx_consensus,
        }
    }

    async fn add_operator(&mut self, operator_id: u64, operator: Arc<RwLock<dyn TOperator>>) {
        self.operators.write()
            .await
            .insert(operator_id, operator);
    }

    fn threshold(&self) -> usize {
        self.threshold_
    }

    async fn consensus(&self, msg: Hash256) -> Result<(), DvfError> {
        Ok(())
    }

    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        println!("<<<<<<<[Duty]: {:02x?}>>>>>>", msg);
        println!("<<<<<<<[Committee Sign]>>>>>>");
        println!("<<<<<<<[Start Consensus]>>>>>>");
        // Run consensus protocol 
        self.consensus(msg).await?;
        println!("<<<<<<<[Consensus Succeeds]>>>>>>");
        
        // If consensus is achieved, aggregate the valid signatures
        let operators = block_on(self.operators.read());
        let ids: Vec<u64> = operators.keys().map(|k| *k).collect();
        let operators: Vec<&Arc<RwLock<dyn TOperator>>> = ids.iter().map(|k| operators.get(&k).unwrap()).collect(); 
        let mut pks: Vec<PublicKey> = operators.iter().map(|x| block_on(x.read()).public_key()).collect();
        let mut pk_refs: Vec<&PublicKey> = pks.iter().map(|x| x).collect();

        let mut sigs: Vec<Signature> = Vec::<_>::new();
        for op in operators {
            match block_on(op.read()).sign(msg) {
                Ok(sig) => sigs.push(sig),
                Err(_) => {} 
            }
        }
        let sigs: Vec<&Signature> = sigs.iter().map(|x| x).collect();
        println!("<<<<<<<[Got {} signatures]>>>>>>", sigs.len());

        let threshold_sig = ThresholdSignature::new(self.threshold());
        
        let sig = threshold_sig.threshold_aggregate(&sigs[..], &pk_refs[..], &ids[..], msg);

        println!("<<<<<<<[Threshold Committee Signing Succeeds]>>>>>>");
        sig
    }
}
