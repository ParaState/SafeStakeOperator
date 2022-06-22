
use dvf::validation::{OperatorCommittee};
use dvf::validation::operator::TOperator;
use dvf::validation::operator::{RemoteOperator, LocalOperator};
use dvf::crypto::{ThresholdSignature};
use std::sync::Arc;
use types::Hash256;
use eth2_hashing::{Context, Sha256Context};
use hotstuff_config::Export as _;
use dvf::node::node::Node;
use hotstuff_config::{Committee, Secret};
use consensus::Committee as ConsensusCommittee;
use mempool::Committee as MempoolCommittee;
use std::fs;
use log::{info};
use futures::future::join_all;
use dvf::node::dvfcore::{DvfCore};
use parking_lot::{RwLock};
use types::Keypair;
use tokio::time::{sleep, Duration};
use env_logger::Env;
use dvf::node::config::NodeConfig;


async fn start_nodes(n_nodes: usize) -> Result<Vec<Arc<Node>>, String> {
    let keys: Vec<_> = (0..n_nodes).map(|_| Secret::new()).collect();
    let configs: Vec<NodeConfig> = (0..n_nodes).map(|i| {
        NodeConfig::default().set_base_port((25_000 + i * 100) as u16)
    }).collect();

    println!("Starting {} nodes", n_nodes);
    let mut nodes: Vec<Arc<Node>> = Vec::default();
    for i in 0..n_nodes {
        let node = Node::new(configs[i].clone(), keys[i].clone()).await.expect("Should start node");
        nodes.push(Arc::new(node)); 
        info!("Start node {} ({}) successfully", i, keys[i].name);
    }
    Ok(nodes)
}

async fn start_dvf_committee(validator_id: u64, nodes: &[Arc<Node>], threshold: usize) -> Result<(Keypair, OperatorCommittee), String> {
    let mut m_threshold = ThresholdSignature::new(threshold);
    let (kp, kps, ids) = m_threshold.key_gen(nodes.len());

    // Print the committee file.
    let epoch = 1;
    let mempool_committee = MempoolCommittee::new(
        nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                (node.secret.name, 
                1, 
                nodes[i].config.tx_receiver_address.clone(), 
                nodes[i].config.mempool_receiver_address.clone(), 
                nodes[i].config.dvfcore_receiver_address.clone(), 
                nodes[i].config.signature_receiver_address.clone())
            })
            .collect(),
        epoch,
    );
    let consensus_committee = ConsensusCommittee::new(
        nodes
            .iter()
            .enumerate()
            .map(|(i, node)| {
                (node.secret.name, 
                1,
                nodes[i].config.consensus_receiver_address.clone())
            })
            .collect(),
        epoch,
    );
    let committee_file = format!("committee_{}.json", validator_id);
    let _ = fs::remove_file(committee_file.as_str());
    let committee = Committee {
        mempool: mempool_committee,
        consensus: consensus_committee,
    };
  
    committee.write(committee_file.as_str()).map_err(|e| e.to_string())?;

    println!("Starting DVF instances for validator {}", validator_id);
    for i in 0..nodes.len() {
        // create dvf consensus
        let node = nodes[i].clone();
        let bls_id = ids[i];
        let bls_kp = kps[i].clone();
        tokio::spawn(async move {
            let committee_file = format!("committee_{}.json", validator_id);
            let committee = Committee::read(committee_file.as_str()).unwrap();
            let mut dvf_inst = DvfCore::new(
                node,
                validator_id,
                bls_id,
                committee,
                bls_kp)
                .await
                .expect("Should start dvf instance");
            dvf_inst.save_committed_block().await
        });
    }
    sleep(Duration::from_millis(1000)).await;

    let mut committee = OperatorCommittee::new(validator_id, kp.pk.clone(), threshold);
    let local_operator = Arc::new(
        RwLock::new(LocalOperator::new(ids[0], Arc::new(kps[0].clone())))); 
    committee.add_operator(ids[0], local_operator);
    for i in 1..nodes.len() {
        let signature_address = nodes[i].config.signature_receiver_address.clone();
        let remote_operator = Arc::new(
            RwLock::new(RemoteOperator::new(ids[i], kps[i].pk.clone(), signature_address)));  
        committee.add_operator(ids[i], remote_operator);
    }

    Ok((kp, committee))
}

fn committee_sign(committee: OperatorCommittee, kp: Keypair, message: &str) {
    println!("Start committee signing");

    let mut context = Context::new();
    context.update(message.as_bytes());
    let message_hash = Hash256::from_slice(&context.finalize());

    println!("Propose {:02x?}", message_hash);
    let sig1 = committee.sign(message_hash).unwrap();
    let sig2 = kp.sk.sign(message_hash);

    let status1 = sig1.verify(&kp.pk, message_hash);
    let status2 = sig2.verify(&kp.pk, message_hash);

    println!("Committee sign and verify: {}", status1);
    println!("Original sign and verify {}", status2);
}

async fn deploy_testbed(n_nodes: usize, threshold: usize) -> Result<(), String> {

    let mut logger = env_logger::Builder::from_env(Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();

    let nodes = start_nodes(n_nodes).await?;
    
    let validator_id = 1;
    let (kp, committee) = start_dvf_committee(validator_id, &nodes, threshold).await?;
    
    committee_sign(committee, kp, "hello world");

    Ok(())
}


#[tokio::main(worker_threads = 200)]
// #[tokio::main]
async fn main() {
    let t: usize = 5;
    let n: usize = 10;
    match deploy_testbed(n, t).await {
        Ok(()) => println!("Testbed exited successfully"),
        Err(e) => {
            eprintln!("Testbed exited with error: {}", e);
            std::process::exit(1)
        } 
    }

}
