use crate::node::config::invalid_addr;
use crate::validation::operator::RemoteOperator;
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::validation::OperatorCommittee;
use std::sync::Arc;
use tokio::sync::RwLock;
// use types::Hash256;
// use crate::DEFAULT_CHANNEL_CAPACITY;
// use hsutils::monitored_channel::{MonitoredChannel, MonitoredSender};

impl OperatorCommittee {
    pub async fn from_definition(def: OperatorCommitteeDefinition) -> Self {
        // let (tx, rx) = MonitoredChannel::new(
        //     DEFAULT_CHANNEL_CAPACITY,
        //     format!("{}-dvf-op-committee", def.validator_id),
        //     "debug",
        // );

        let mut committee = Self::new(
            def.validator_id,
            def.validator_public_key.clone(),
            def.threshold as usize,
            // rx,
        );
        for i in 0..(def.total as usize) {
            let addr = def.base_socket_addresses[i].unwrap_or(invalid_addr());
            let operator = RemoteOperator::new(
                def.validator_id,
                def.operator_ids[i],
                def.node_public_keys[i].clone(),
                def.operator_public_keys[i].clone(),
                addr,
            );
            committee
                .add_operator(def.operator_ids[i], Arc::new(RwLock::new(operator)))
                .await;
        }
        committee
    }
}
