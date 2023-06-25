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
use futures::future::join_all;
use log::{info};
use tokio::sync::Notify;
use tokio::task::JoinHandle;
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
    consensus_notifications: Arc<RwLock<HashMap<Hash256, Arc<Notify>>>>,
    thread_handle: JoinHandle<()>,
}

impl Drop for HotstuffOperatorCommittee {
    fn drop(&mut self) {
        info!("Shutting down hotstuff operator committee");
        self.thread_handle.abort();
    }
}

#[async_trait]
impl TOperatorCommittee for HotstuffOperatorCommittee {
    fn new(validator_id: u64, validator_public_key: PublicKey, t: usize, mut rx_consensus: Receiver<Hash256>) -> Self {

        let consensus_notifications: Arc<RwLock<HashMap<Hash256, Arc<Notify>>>> = 
            Arc::new(RwLock::new(HashMap::default()));
        let consensus_notifications_clone = consensus_notifications.clone();
        let thread_handle = tokio::spawn(async move {
            loop {
                match rx_consensus.recv().await{
                    Some(value) => {
                        info!("Consensus achieved for msg {}", value);
                        let notes = consensus_notifications_clone.write().await;
                        if let Some(notify) = notes.get(&value) {
                            notify.notify_one();
                        }
                        // else {
                        //     let notify = Arc::new(Notify::new());
                        //     notify.notify_one();
                        //     notes.insert(value, notify);
                        // }
                    }
                    None => {
                        return; 
                    }
                }
            }
        });

        Self {
            validator_id,
            validator_public_key,
            operators: <_>::default(),
            threshold_: t,
            consensus_notifications,
            thread_handle,
        }
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

        let operators = self.operators.read().await;
        for operator in operators.values() {
            operator.read()
                .await
                .propose(msg)
                .await;
        }

        // let notify = {
        //     let mut notes = self.consensus_notifications.write().await; 
        //     if let Some(notify) = notes.get(&msg) {
        //         notify.clone()
        //     }
        //     else {
        //         let notify = Arc::new(Notify::new());
        //         notes.insert(msg, notify.clone());
        //         notify
        //     }
        // };
        notify.notified().await;
        let mut notes = self.consensus_notifications.write().await; 
        notes.remove(&msg);
        Ok(())
    }

    async fn sign(&self, msg: Hash256) -> Result<(Signature, Vec<u64>), DvfError> {
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
        let sig = threshold_sig.threshold_aggregate(&sigs[..], &pks[..], &ids[..], msg)?;

        Ok((sig, ids))
    }

    fn get_validator_pk(&self) -> String {
        self.validator_public_key.as_hex_string()
    }

    
}
