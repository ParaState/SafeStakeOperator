use std::collections::HashMap;
use std::sync::{Arc};
use crate::validation::{
    generic_operator_committee::{TOperatorCommittee},
    operator::{TOperator, HotStuffOperator},
};
use crate::crypto::ThresholdSignature;
use crate::DvfOperatorTsid;
use crate::DvfCommitteeIndex;
use crate::utils::error::DvfError;
use bls::{Hash256, Signature, PublicKey};
use parking_lot::{RwLock};
use std::net::SocketAddr;
use tokio::net::TcpStream;
use futures::executor::block_on;
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use bytes::Bytes;
use futures::sink::SinkExt as _;
/// Provides the externally-facing operator committee type.
pub mod types {
    pub use super::HotstuffOperatorCommittee as OperatorCommittee;
}

/// Hotstuff operator committee whose consensus protocol is dummy 
pub struct HotstuffOperatorCommittee {
    id: DvfCommitteeIndex,
    voting_public_key: PublicKey,
    operators: RwLock<HashMap<DvfOperatorTsid, Arc<RwLock<dyn TOperator>>>>,
    threshold_: usize,
}

impl TOperatorCommittee for HotstuffOperatorCommittee {
    fn new(id: DvfCommitteeIndex, voting_public_key: PublicKey, t: usize) -> Self {
        Self {
            id,
            voting_public_key,
            operators: <_>::default(),
            threshold_: t,
        }
    }

    fn add_operator(&mut self, id: DvfOperatorTsid, operator: Arc<RwLock<dyn TOperator>>) {

        self.operators.write().insert(id, operator);
    }

    fn threshold(&self) -> usize {
        self.threshold_
    }

    fn consensus(&self, msg: Hash256) -> bool {
        // send network request
        let operators = self.operators.write();
        let ids : Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();
        let id = ids[0];
        let mut operator = operators.get(&id).unwrap().write();
        let hotstuff_operator = operator.downcast_mut::<HotStuffOperator>().unwrap(); 
        println!("propose msg by id { }", id);
        if id == 1 {
            println!("propose msg by id { }", id);
            block_on(hotstuff_operator.propose(msg));
        }
            
        return true;
    }

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        // Run consensus protocol 
        println!("<<<<<<<[Duty]: {:02x?}>>>>>>", msg);
        println!("<<<<<<<[Committee Sign]>>>>>>");
        println!("<<<<<<<[Start Consensus]>>>>>>");
        let status = self.consensus(msg);
        println!("<<<<<<<[Consensus Succeeds]>>>>>>");

        let operators = self.operators.write();
        let ids : Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();

        let id :u64 = ids[0];
        let mut operator = operators.get(&id).unwrap().write();
        let hotstuff_operator = operator.downcast_mut::<HotStuffOperator>().unwrap();
        // wait 
        let signatures = block_on(hotstuff_operator.wait_signature());

        let ids : Vec<DvfOperatorTsid> = signatures.iter().map(|x| x.id as u64).collect();
        // ids.push(id);
        println!("{:?}", &ids);
        let pks: Vec<&PublicKey> = signatures.iter().map(|x| &x.from).collect();
        // pks.push(self_pk);
        let sigs: Vec<&Signature> = signatures.iter().map(|x| &x.signature).collect();
        println!("<<<<<<<[Got {} signatures]>>>>>>", sigs.len());
        // sigs.push(&self_signature);
        let threshold_sig = ThresholdSignature::new(self.threshold());
        let sig = threshold_sig.threshold_aggregate(&sigs[..], &pks[..], &ids[..], msg);
        println!("<<<<<<<[Threshold Committee Signing Succeeds]>>>>>>");
        sig
    }

    
}
