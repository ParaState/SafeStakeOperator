use std::collections::HashMap;
use std::sync::{Arc};
use std::{thread, time};
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
use futures::future::join_all;
use log::{info, error};
use tokio::sync::Mutex;
use async_trait::async_trait;


/// Provides the externally-facing operator committee type.
pub mod types {
    pub use super::HotstuffOperatorCommittee as OperatorCommittee;
}

/// Hotstuff operator committee whose consensus protocol is dummy 
pub struct HotstuffOperatorCommittee {
    validator_id: u64,
    validator_public_key: PublicKey,
    operators: RwLock<HashMap<u64, Arc<RwLock<dyn TOperator>>>>,
    threshold_: usize,
    rx_consensus: Arc<RwLock<Receiver<Hash256>>>,
}

#[async_trait]
impl TOperatorCommittee for HotstuffOperatorCommittee {
    fn new(validator_id: u64, validator_public_key: PublicKey, t: usize, rx_consensus: Receiver<Hash256>) -> Self {
        Self {
            validator_id,
            validator_public_key,
            operators: <_>::default(),
            threshold_: t,
            rx_consensus: Arc::new(RwLock::new(rx_consensus)),
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

    // assumt operators are already sorted
    async fn consensus(&self, msg: Hash256) -> Result<(), DvfError> {
        let operators = self.operators.read().await;
        let select_order = msg.to_low_u64_le() % operators.len() as u64;
        let mut ids : Vec<u64> = operators.keys().map(|k| *k).collect();
        ids.sort();
        let selected_id = ids[select_order as usize];
        let operator = operators.get(&selected_id).unwrap().clone();
        let rx_consensus = self.rx_consensus.clone();
        
        let fut = tokio::spawn(async move {
            // Acquire the write lock, so that only one thread can invoke a consensus instance
            let mut rx_consensus = rx_consensus.write().await;

            operator.read()
                .await
                .propose(msg);

            match rx_consensus.recv().await {
                Some(value) => {
                    if value == msg {
                        info!("Consensus achieved for msg {}", msg);
                        Ok(()) 
                    }
                    else {
                        Err(DvfError::ConsensusFailure(
                            format!("Consensus msg changed ({} != {}). Something went seriously wrong.", value, msg))
                        )
                    }
                }
                None => {
                    Err(DvfError::ConsensusFailure(
                        format!("Failed to receive consensus of msg {}", msg))
                    )
                }
            }
        });
        fut.await.map_err(|e| DvfError::ConsensusFailure(format!("Tokio run error: {}", e)))?
    }

    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        // Run consensus protocol 
        self.consensus(msg).await?;

        let operators = &self.operators.read().await;
        let signing_futs = operators.keys().map(|operator_id| async move {
            let operator = operators.get(operator_id).unwrap().read().await; 
            operator.sign(msg)
                .map(|x| (operator_id.clone(), operator.public_key(), x))
            
        });
        let results = join_all(signing_futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<(u64, PublicKey, Signature)>>();

        let ids = results.iter().map(|x| x.0).collect::<Vec<u64>>();
        let pks = results.iter().map(|x| &x.1).collect::<Vec<&PublicKey>>();
        let sigs = results.iter().map(|x| &x.2).collect::<Vec<&Signature>>();

        info!("Received {} signatures", sigs.len());

        let threshold_sig = ThresholdSignature::new(self.threshold());
        let sig = threshold_sig.threshold_aggregate(&sigs[..], &pks[..], &ids[..], msg);

        sig
    }

    
}
