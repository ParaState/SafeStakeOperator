use std::collections::HashMap;
use std::sync::{Arc};
use crate::validation::{
    generic_operator_committee::{TOperatorCommittee},
    operator::{TOperator},
};
use crate::crypto::ThresholdSignature;
use crate::{DvfCommitteeIndex, DvfOperatorTsid};
use crate::utils::error::DvfError;
use bls::{Hash256, Signature, PublicKey};
use parking_lot::{RwLock};
/// Provides the externally-facing operator committee type.
pub mod types {
    pub use super::FakeOperatorCommittee as OperatorCommittee;
}

/// Fake operator committee whose consensus protocol is dummy 
pub struct FakeOperatorCommittee {
    id: DvfCommitteeIndex,
    voting_public_key: PublicKey,
    operators: RwLock<HashMap<DvfOperatorTsid, Arc<RwLock<dyn TOperator>>>>,
    threshold_: usize,
}

impl TOperatorCommittee for FakeOperatorCommittee {
    fn new(id: DvfCommitteeIndex, voting_public_key: PublicKey, t: usize) -> Self {
        Self {
            id,
            voting_public_key,
            operators: <_>::default(),
            threshold_: t
        }
    }

    fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<RwLock<dyn TOperator>>) {
        self.operators.write().insert(id, operator);
    }

    fn threshold(&self) -> usize {
        self.threshold_
    }

    fn consensus(&self, msg: Hash256) -> bool {
        return true;
    }

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        println!("<<<<<<<[Duty]: {:02x?}>>>>>>", msg);
        println!("<<<<<<<[Committee Sign]>>>>>>");
        println!("<<<<<<<[Start Consensus]>>>>>>");
        // Run consensus protocol 
        let status = self.consensus(msg);
        if !status {
            return Err(DvfError::ConsensusFailure);
        }
        println!("<<<<<<<[Consensus Succeeds]>>>>>>");
        
        // If consensus is achieved, aggregate the valid signatures
        let operators = self.operators.read();
        let ids: Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();
        let operators: Vec<&Arc<RwLock<dyn TOperator>>> = ids.iter().map(|k| operators.get(&k).unwrap()).collect(); 
        let mut pks: Vec<PublicKey> = operators.iter().map(|x| x.read().public_key()).collect();
        let mut pk_refs: Vec<&PublicKey> = pks.iter().map(|x| x).collect();

        let mut sigs: Vec<Signature> = Vec::<_>::new();
        for op in operators {
            match op.read().sign(msg) {
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
