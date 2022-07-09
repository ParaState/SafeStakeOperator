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
use futures::future::join_all;
use log::{info, error};
use tokio::sync::Notify;
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
    consensus_notifications: Arc<RwLock<HashMap<Hash256, Arc<Notify>>>>,
}

#[async_trait]
impl TOperatorCommittee for HotstuffOperatorCommittee {
    fn new(validator_id: u64, validator_public_key: PublicKey, t: usize, rx_consensus: Receiver<Hash256>) -> Self {
        let committee = Self {
            validator_id,
            validator_public_key,
            operators: <_>::default(),
            threshold_: t,
            rx_consensus: Arc::new(RwLock::new(rx_consensus)),
            consensus_notifications: Arc::new(RwLock::new(HashMap::default())),
        };

        let rx_consensus = committee.rx_consensus.clone();
        let consensus_notifications = committee.consensus_notifications.clone();
        tokio::spawn(async move {
            loop {
                let mut rx_consensus = rx_consensus.write().await;
                match rx_consensus.recv().await{
                    Some(value) => {
                        info!("Consensus achieved for msg {}", value);
                        let mut notes = consensus_notifications.write().await;
                        if let Some(notify) = notes.get(&value) {
                            notify.notify_one();
                        }
                        else {
                            let notify = Arc::new(Notify::new());
                            notify.notify_one();
                            notes.insert(value, notify);
                        }
                    }
                    None => {
                        return; 
                    }
                }
            }
        });
        
        committee
    }

    fn validator_id(&self) -> u64 {
        self.validator_id
    }

    async fn add_operator(&mut self, operator_id: u64, operator: Arc<RwLock<dyn TOperator>>) {

        self.operators.write()
            .await
            .insert(operator_id, operator);
    }

    fn threshold(&self) -> usize {
        self.threshold_
    }

    async fn get_leader(&self, nonce: u64) -> u64 {
        let operators = self.operators.read().await;
        let select_order = nonce % operators.len() as u64;
        let mut ids : Vec<u64> = operators.keys().map(|k| *k).collect();
        ids.sort();
        ids[select_order as usize]
    }

    async fn consensus(&self, msg: Hash256) -> Result<(), DvfError> {
        let operators = self.operators.read().await;
        for operator in operators.values() {
            operator.read()
                .await
                .propose(msg)
                .await;
        }

        let notify = {
            let mut notes = self.consensus_notifications.write().await; 
            if let Some(notify) = notes.get(&msg) {
                notify.clone()
            }
            else {
                let notify = Arc::new(Notify::new());
                notes.insert(msg, notify.clone());
                notify
            }
        };
        notify.notified().await;
        let mut notes = self.consensus_notifications.write().await; 
        notes.remove(&msg);
        Ok(())
    }

    async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        // Run consensus protocol 
        self.consensus(msg).await?;

        let operators = &self.operators.read().await;
        let signing_futs = operators.keys().map(|operator_id| async move {
            let operator = operators.get(operator_id).unwrap().read().await; 
            operator.sign(msg)
                .await
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
