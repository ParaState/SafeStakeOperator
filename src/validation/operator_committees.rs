use crate::validation::OperatorCommittee;
use crate::utils::error::DvfError;
use crate::validation::operator_committee_definitions::{OperatorCommitteeDefinition, OperatorCommitteeDefinitions};
use crate::validation::operator::RemoteOperator;
use crate::DEFAULT_CHANNEL_CAPACITY;
use crate::node::config::SIGNATURE_PORT_OFFSET;
use std::sync::Arc;
use std::convert::TryInto;
use std::path::PathBuf;
use std::collections::HashMap;
use tokio::sync::{RwLock};
use tokio::sync::mpsc::{channel, Sender};
use types::Hash256;


impl OperatorCommittee { 
    pub async fn from_definition(
        def: OperatorCommitteeDefinition,
    ) -> (Self, Sender<Hash256>) {
        let (tx, rx) = channel(DEFAULT_CHANNEL_CAPACITY);

        let mut committee = Self::new(def.validator_id, def.validator_public_key.clone(), def.threshold as usize, rx);
        for i in 0..(def.total as usize) {
            let mut addr = def.base_socket_addresses[i].clone();
            addr.set_port(addr.port() + SIGNATURE_PORT_OFFSET);
            let operator = RemoteOperator::new(
                def.validator_id,
                def.operator_ids[i],
                def.operator_public_keys[i].clone(),
                addr,
            );
            committee.add_operator(def.operator_ids[i], Arc::new(RwLock::new(operator))).await;
        }
        (committee, tx)
    }
}

//pub struct OperatorCommittees {
    ///// A list of validator definitions which can be stored on-disk.
    //definitions: OperatorCommitteeDefinitions,
    ///// The directory that the `self.definitions` will be saved into.
    //committees_dir: PathBuf,
    ///// The canonical set of validators.
    //pub committee_map: HashMap<u64, OperatorCommittee>,
//}

//impl OperatorCommittees {
    //pub async fn from_definitions(
        //definitions: OperatorCommitteeDefinitions,
        //committees_dir: PathBuf,
    //) -> Result<Self, DvfError> {
        //let mut this = Self {
            //definitions,
            //committees_dir,
            //committee_map: HashMap::default(),
        //};
        //this.update_committees().await?;
        //Ok(this)
    //}

    //pub async fn update_committees(&mut self) -> Result<(), DvfError> {
        //for def in self.definitions.as_slice() { 
            //if self.committee_map.contains_key(&def.committee_index) {
                //continue;
            //}
            //match OperatorCommittee::from_definition(def.clone()) {
                //Ok(committee) => {
                    //self.committee_map.insert(def.validator_id, committee);
                //}
                //Err(e) => {
                    //return Err(e);
                //}
            //}
        //}
        //Ok(())
    //}
//}
