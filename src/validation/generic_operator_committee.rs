use std::sync::Arc;
use crate::utils::error::DvfError;
use crate::{DvfCommitteeIndex, DvfOperatorTsid};
use crate::validation::operator::{TOperator};
use types::{Hash256, Signature, PublicKey};
use parking_lot::{RwLock};

/// Operator committee for a validator. 
pub trait TOperatorCommittee {
    fn new(id: DvfCommitteeIndex, voting_public_key: PublicKey, t: usize) -> Self;
    fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<RwLock<dyn TOperator>>); 
    fn consensus(&self, msg: Hash256) -> bool;
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>;
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
    pub fn new(id: DvfCommitteeIndex, voting_public_key: PublicKey, t: usize) -> Self {
        Self {
            cmt: TOperatorCommittee::new(id, voting_public_key, t)
        }
    }

    pub fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<RwLock<dyn TOperator>>) {
        self.cmt.add_operator(id, operator);
    }

    pub fn threshold(&self) -> usize {
        self.cmt.threshold()
    }

    pub fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        self.cmt.sign(msg)
    }
}


