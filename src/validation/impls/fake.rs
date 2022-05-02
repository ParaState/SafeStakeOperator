use std::collections::HashMap;
use std::sync::Arc;
use crate::validation::{
    operator_committee::{TOperatorCommittee},
    operator::{LocalOperator, TOperator},
};
use crate::crypto::ThresholdSignature;
use crate::DvfOperatorTsid;
use crate::utils::error::DvfError;
use types::{Hash256, Signature, PublicKey};

/// Fake operator committee whose consensus protocol is dummy 
pub struct FakeOperatorCommittee {
    operators: HashMap<DvfOperatorTsid, Arc<dyn TOperator>>,
    threshold_: usize
}

impl TOperatorCommittee for FakeOperatorCommittee {
    fn new(t: usize) -> Self {
        Self {
            operators: HashMap::new(),
            threshold_: t
        }
    }

    fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<dyn TOperator>) {
        self.operators.insert(id, operator);
    }

    fn threshold(&self) -> usize {
        self.threshold_
    }

    fn consensus(&self, msg: Hash256) -> bool {
        return true;
    }

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        // Run consensus protocol 
        let status = self.consensus(msg);
        if !status {
            return Err(DvfError::ConsensusFailure);
        }

        let ids: Vec<DvfOperatorTsid> = self.operators.keys().map(|k| *k).collect();
        let operators: Vec<&Arc<dyn TOperator>> = ids.iter().map(|k| self.operators.get(&k).unwrap()).collect(); 
        let pks: Vec<&PublicKey> = operators.iter().map(|x| x.public_key().unwrap()).collect();
        let sigs: Vec<Signature> = operators.iter().map(|x| x.sign(msg)).collect();
        let sigs: Vec<&Signature> = sigs.iter().map(|x| x).collect();

        let threshold_sig = ThresholdSignature::new(self.threshold());
        
        threshold_sig.threshold_aggregate(&sigs[..], &pks[..], &ids[..], msg)
    }
}
