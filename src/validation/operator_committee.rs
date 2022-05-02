use std::collections::HashMap;
use std::sync::Arc;
use crate::utils::error::DvfError;
use crate::{DvfCommitteeIndex, DvfOperatorTsid};
use crate::validation::operator::{TOperator};
use types::{Hash256, Signature};

pub trait TOperatorCommittee {
    fn new(t: usize) -> Self;
    fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<dyn TOperator>); 

    fn consensus(&self, msg: Hash256) -> bool;
    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>;
    fn threshold(&self) -> usize;
}

pub struct GenericOperatorCommittee<Committee> {
    id: DvfCommitteeIndex,
    cmt: Committee 
}

impl <Committee> GenericOperatorCommittee<Committee> 
where
    Committee: TOperatorCommittee
{
    pub fn new(id: DvfCommitteeIndex, t: usize) -> Self {
        Self {
            id,
            cmt: TOperatorCommittee::new(t)
        }
    }

    pub fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<dyn TOperator>) {
        self.cmt.add_operator(id, operator);
    }

    pub fn threshold(&self) -> usize {
        self.cmt.threshold()
    }

    pub fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        self.cmt.sign(msg)
    }
}
