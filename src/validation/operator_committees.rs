use crate::validation::OperatorCommittee;
use crate::utils::error::DvfError;
use crate::validation::operator_committee_definitions::{OperatorCommitteeDefinition, OperatorCommitteeDefinitions};
use crate::validation::operator::RemoteOperator;
use crate::DvfCommitteeIndex;
use std::sync::Arc;
use std::convert::TryInto;
use std::path::PathBuf;
use std::collections::HashMap;
use parking_lot::{RwLock};

impl OperatorCommittee { 
    pub fn from_definition(
        def: OperatorCommitteeDefinition,
    ) -> Result<Self, DvfError> {
        let mut committee = Self::new(def.committee_index, def.voting_public_key.clone(), def.threshold.try_into().unwrap());
        for i in 0..(def.total as usize) {
            let operator = RemoteOperator {
                id: def.ids[i],
                public_key: def.public_keys[i].clone(),
                socket_address: def.socket_addresses[i],
            };
            committee.add_operator(def.ids[i], Arc::new(RwLock::new(operator)));
        }
        Ok(committee)
    }
}

pub struct OperatorCommittees {
    /// A list of validator definitions which can be stored on-disk.
    definitions: OperatorCommitteeDefinitions,
    /// The directory that the `self.definitions` will be saved into.
    committees_dir: PathBuf,
    /// The canonical set of validators.
    pub committee_map: HashMap<DvfCommitteeIndex, OperatorCommittee>,
}

impl OperatorCommittees {
    pub async fn from_definitions(
        definitions: OperatorCommitteeDefinitions,
        committees_dir: PathBuf,
    ) -> Result<Self, DvfError> {
        let mut this = Self {
            definitions,
            committees_dir,
            committee_map: HashMap::default(),
        };
        this.update_committees().await?;
        Ok(this)
    }

    pub async fn update_committees(&mut self) -> Result<(), DvfError> {
        for def in self.definitions.as_slice() { 
            if self.committee_map.contains_key(&def.committee_index) {
                continue;
            }
            match OperatorCommittee::from_definition(def.clone()) {
                Ok(committee) => {
                    self.committee_map.insert(def.committee_index, committee);
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
        Ok(())
    }
}
