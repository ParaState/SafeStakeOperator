use std::collections::HashMap;
use std::sync::{Arc};
use std::{thread, time};
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

    // assumt operators are already sorted
    fn consensus(&self, msg: Hash256) -> bool {
        // send network request
        // let operators = self.operators.write();
        // let ids : Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();
        // let id = ids[0];
        // let mut operator = operators.get(&id).unwrap().write();
        // let hotstuff_operator = operator.downcast_mut::<HotStuffOperator>().unwrap(); 
        // println!("propose msg by id { }", id);
        // if id == 1 {
        //     println!("propose msg by id { }", id);
        //     block_on(hotstuff_operator.propose(msg));
        // }
        let operators = self.operators.read();
        let select_order = msg.to_fixed_bytes()[0] as u64 % operators.len() as u64;
        let ids : Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();
        let selected_id = ids[select_order as usize];
        let operator = operators.get(&selected_id).unwrap().write();
        operator.propose(msg, self.id);
            
        return true;
    }

    fn sign(&self, msg: Hash256) -> Result<Signature, DvfError> {
        // Run consensus protocol 
        println!("<<<<<<<[Duty]: {:02x?}>>>>>>", msg);
        println!("<<<<<<<[Committee Sign]>>>>>>");
        println!("<<<<<<<[Start Consensus]>>>>>>");
        let status = self.consensus(msg);
        let ten_millis = time::Duration::from_millis(2000);
        thread::sleep(ten_millis);
        println!("<<<<<<<[Request Other Signature]>>>>>>");

        // let operators = self.operators.write();
        // let ids : Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();

        // let id :u32 = ids[0];
        // let mut operator = operators.get(&id).unwrap().write();
        // let hotstuff_operator = operator.downcast_mut::<HotStuffOperator>().unwrap();
        // // wait 
        // let signatures = block_on(hotstuff_operator.wait_signature());
        // let ids : Vec<DvfOperatorTsid> = signatures.iter().map(|x| x.id as u32).collect();
        // // ids.push(id);
        // println!("{:?}", &ids);
        // let pks: Vec<&PublicKey> = signatures.iter().map(|x| &x.from).collect();
        // // pks.push(self_pk);
        // let sigs: Vec<&Signature> = signatures.iter().map(|x| &x.signature).collect();
        // // sigs.push(&self_signature);
        // let threshold_sig = ThresholdSignature::new(self.threshold());
        // threshold_sig.threshold_aggregate(&sigs[..], &pks[..], &ids[..], msg)

        let operators = self.operators.write();
        let keys: Vec<DvfOperatorTsid> = operators.keys().map(|k| *k).collect();
        let mut ids:  Vec<DvfOperatorTsid> = Vec::new();
        let operators: Vec<&Arc<RwLock<dyn TOperator>>> = keys.iter().map(|k| operators.get(&k).unwrap()).collect();
        let mut pks: Vec<PublicKey> = Vec::new();
        let mut sigs: Vec<Signature> = Vec::<_>::new();
        // TODO use multiple threads to do this
        for op in operators {
            let operator = op.read();
            match operator.sign(msg, self.id) {
                Ok(sig) => {
                    sigs.push(sig);
                    ids.push(operator.get_id());
                    pks.push(operator.public_key().clone());
                }
                Err(_) => {} 
            }
        }
        let pk_refs: Vec<&PublicKey> = pks.iter().map(|x| x).collect();
        let sigs: Vec<&Signature> = sigs.iter().map(|x| x).collect();
        println!("<<<<<<<[Got {} signatures]>>>>>>", sigs.len());
        let threshold_sig = ThresholdSignature::new(self.threshold());

        let sig = threshold_sig.threshold_aggregate(&sigs[..], &pk_refs[..], &ids[..], msg);

        println!("<<<<<<<[Threshold Committee Signing Succeeds]>>>>>>");
        sig
    }

    
}
