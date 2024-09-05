use crate::node::node::Node;
use crate::node::utils::SignDigest;
use crate::utils::error::DvfError;
use crate::validation::operator::LocalOperator;
use crate::validation::operator_committee_definitions::OperatorCommitteeDefinition;
use crate::validation::signing_method::SignableMessage;
use crate::validation::OperatorCommittee;
use async_trait::async_trait;
use bls::{Hash256, PublicKey as BlsPublicKey, Signature};
use bytes::Bytes;
use futures::SinkExt;
use hsconfig::Committee as HotstuffCommittee;
use hscrypto::Digest;
use hsutils::monitored_channel::MonitoredSender;
use keccak_hash::keccak;
use log::{error, info, warn};
use network::{MessageHandler, Writer};
use serde::{Deserialize, Serialize};
use slashing_protection::SlashingDatabase;
use slashing_protection::{NotSafe, Safe};
use std::collections::HashMap;
use std::error::Error;
use std::fmt;
use std::marker::PhantomData;
use std::sync::Arc;
use store::Store;
use tokio::sync::RwLock;
use types::{
    AbstractExecPayload, AttestationData, BeaconBlock, BlindedPayload, EthSpec, FullPayload,
    Keypair,
};
#[derive(Serialize, Deserialize, Clone)]
pub struct DvfInfo {
    pub validator_id: u64,
    pub committee: HotstuffCommittee,
}

impl fmt::Debug for DvfInfo {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(
            f,
            "{}: Commitee({:?})",
            self.validator_id,
            serde_json::to_string_pretty(&self.committee)
        )
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub enum DvfType {
    Attester,
    Proposer(BlockType),
}

#[derive(Serialize, Deserialize, Clone)]
pub enum BlockType {
    Blinded,
    Full,
}

#[derive(Clone)]
pub struct DvfSignatureReceiverHandler {
    pub store: Store,
}

#[async_trait]
impl MessageHandler for DvfSignatureReceiverHandler {
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let msg: Vec<u8> = message.slice(..).to_vec();
        match self.store.read(msg).await {
            Ok(value) => match value {
                Some(data) => {
                    let _ = writer.send(Bytes::from(data)).await;
                }
                None => {
                    let _ = writer
                        .send(Bytes::from("can't find signature, please wait"))
                        .await;
                }
            },
            Err(e) => {
                let _ = writer
                    .send(Bytes::from("can't read database, please wait"))
                    .await;
                error!("can't read database, {}", e)
            }
        }
        // Give the change to schedule other tasks.
        //   tokio::task::yield_now().await;
        Ok(())
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct DvfDutyCheckMessage {
    pub operator_id: u64,
    pub domain_hash: Hash256,
    pub check_type: DvfType,
    pub data: Vec<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
}

impl DvfDutyCheckMessage {
    pub fn get_digest(&self) -> Digest {
        let mut msg = self.clone();
        msg.sign_hex = None;
        let ser_json = serde_json::to_string(&msg).unwrap();
        Digest::from(keccak(ser_json.as_bytes()).as_fixed_bytes())
    }
}

impl SignDigest for DvfDutyCheckMessage {}

#[derive(Clone)]
pub struct DvfDutyCheckHandler<E: EthSpec> {
    pub store: Store,
    pub slashing_protection: SlashingDatabase,
    pub validator_pk: BlsPublicKey,
    pub operator_pks: HashMap<u64, hscrypto::PublicKey>,
    pub keypair: Keypair,
    _phantom: PhantomData<E>,
}

impl<E: EthSpec> DvfDutyCheckHandler<E> {
    pub async fn sign_block<Payload: AbstractExecPayload<E>>(
        &self,
        writer: &mut Writer,
        block: BeaconBlock<E, Payload>,
        domain_hash: Hash256,
    ) {
        match self.slashing_protection.check_and_insert_block_proposal(
            &self.validator_pk.compress(),
            &block.block_header(),
            domain_hash,
        ) {
            Ok(Safe::Valid) => {
                let signable_msg = SignableMessage::BeaconBlock(&block);
                let signing_root = signable_msg.signing_root(domain_hash);
                info!("valid block duty, local sign and store {}", &signing_root);
                let sig = self.keypair.sk.sign(signing_root);
                let serialized_signature = bincode::serialize(&sig).unwrap();
                // save to local db
                let key = signing_root.as_bytes().into();
                self.store.write(key, serialized_signature).await;
                let _ = writer
                    .send(Bytes::from(format!(
                        "successfully consensus proposal on {}",
                        signing_root
                    )))
                    .await;
            }
            Ok(Safe::SameData) => {
                let _ = writer
                    .send(Bytes::from("Skipping signing of previously signed block"))
                    .await;
                info!("Skipping signing of previously signed block");
            }
            Err(NotSafe::UnregisteredValidator(pk)) => {
                let _ = writer
                    .send(Bytes::from(format!(
                        "Not signing block for unregistered validator public_key {:?}",
                        pk
                    )))
                    .await;
                warn!(
                    "Not signing block for unregistered validator public_key {}",
                    format!("{:?}", pk)
                );
            }
            Err(e) => {
                let _ = writer
                    .send(Bytes::from(format!(
                        "Not signing slashable block error {:?}",
                        e
                    )))
                    .await;
                error!("Not signing slashable block error {}", format!("{:?}", e));
            }
        }
    }
}

#[async_trait]
impl<E: EthSpec> MessageHandler for DvfDutyCheckHandler<E> {
    async fn dispatch(&self, writer: &mut Writer, message: Bytes) -> Result<(), Box<dyn Error>> {
        let check_msg: DvfDutyCheckMessage = match bincode::deserialize(&message.slice(..)) {
            Ok(m) => m,
            Err(_) => {
                let _ = writer
                    .send(Bytes::from("failed to deserialize duty check msg"))
                    .await;
                error!("failed to deserialize duty check msg");
                return Ok(());
            }
        };
        let digest = check_msg.get_digest();
        let op_pk = match self.operator_pks.get(&check_msg.operator_id) {
            Some(pk) => pk,
            None => {
                return {
                    let _ = writer.send(Bytes::from("failed to find operator")).await;
                    error!("failed to find operator");
                    Ok(())
                }
            }
        };
        match check_msg.sign_hex {
            Some(s) => {
                match hex::decode(s) {
                    Ok(s) => {
                        if s.len() != 64 {
                            let _ = writer
                                .send(Bytes::from(
                                    "the length of the signature is not 64, ignore the message",
                                ))
                                .await;
                            error!("the length of the signature is not 64, ignore the message");
                            return Ok(());
                        }
                        let sig = hscrypto::Signature::from_bytes(&s);
                        match sig.verify(&digest, &op_pk) {
                            Ok(_) => {
                                info!("successfully verified duty message");
                            }
                            Err(_) => {
                                let _ = writer
                                    .send(Bytes::from(
                                        "failed to verify the signature of the duty message",
                                    ))
                                    .await;
                                error!("failed to verify the signature of the duty message");
                                return Ok(());
                            }
                        }
                    }
                    Err(_) => {
                        let _ = writer
                            .send(Bytes::from(
                                "failed to decode signature, ignore the message",
                            ))
                            .await;
                        error!("failed to decode signature, ignore the message");
                        return Ok(());
                    }
                };
            }
            None => {
                let _ = writer
                    .send(Bytes::from("empty signature, ignore the message"))
                    .await;
                error!("empty signature, ignore the message");
                return Ok(());
            }
        }
        match check_msg.check_type {
            DvfType::Attester => {
                let attestation_data: AttestationData =
                    match serde_json::from_slice(&check_msg.data) {
                        Ok(a) => a,
                        Err(_) => {
                            let _ = writer
                                .send(Bytes::from("failed to deserialize attestation data"))
                                .await;
                            error!("failed to deserialize attestation data");
                            return Ok(());
                        }
                    };
                match self.slashing_protection.check_and_insert_attestation(
                    &self.validator_pk.compress(),
                    &attestation_data,
                    check_msg.domain_hash,
                ) {
                    Ok(Safe::Valid) => {
                        let signable_msg = SignableMessage::<E, BlindedPayload<E>>::AttestationData(
                            &attestation_data,
                        );
                        let signing_root = signable_msg.signing_root(check_msg.domain_hash);
                        info!(
                            "valid attestation duty, local sign and store {}",
                            &signing_root
                        );
                        let sig = self.keypair.sk.sign(signing_root);
                        let serialized_signature = bincode::serialize(&sig).unwrap();
                        // save to local db
                        let key = signing_root.as_bytes().into();
                        self.store.write(key, serialized_signature).await;
                        let _ = writer
                            .send(Bytes::from(format!(
                                "successfully consensus attestation on {}",
                                &signing_root
                            )))
                            .await;
                    }
                    Ok(Safe::SameData) => {
                        info!("Skipping signing of previously signed attestation");
                        let _ = writer
                            .send(Bytes::from(
                                "Skipping signing of previously signed attestation",
                            ))
                            .await;
                    }
                    Err(NotSafe::UnregisteredValidator(pk)) => {
                        let _ = writer.send(Bytes::from(format!("Not signing attestation for unregistered validator public_key {:?}", pk))).await;
                        warn!(
                            "Not signing attestation for unregistered validator public_key {}",
                            format!("{:?}", pk)
                        );
                    }
                    Err(e) => {
                        let _ = writer
                            .send(Bytes::from(format!(
                                "Not signing slashable attestation {:?}",
                                e
                            )))
                            .await;
                        error!("Not signing slashable attestation {}", format!("{:?}", e));
                    }
                }
            }
            DvfType::Proposer(block_type) => {
                match block_type {
                    BlockType::Full => {
                        let block: BeaconBlock<E, FullPayload<E>> =
                            match serde_json::from_slice(&check_msg.data) {
                                Ok(b) => b,
                                Err(_) => {
                                    let _ = writer
                                        .send(Bytes::from(
                                            "failed to deserialize full proposal block",
                                        ))
                                        .await;
                                    error!("failed to deserialize full proposal block");
                                    return Ok(());
                                }
                            };
                        self.sign_block(writer, block, check_msg.domain_hash).await;
                    }
                    BlockType::Blinded => {
                        let block: BeaconBlock<E, BlindedPayload<E>> =
                            match serde_json::from_slice(&check_msg.data) {
                                Ok(b) => b,
                                Err(_) => {
                                    let _ = writer
                                        .send(Bytes::from(
                                            "failed to deserialize blinded proposal block",
                                        ))
                                        .await;
                                    error!("failed to deserialize blinded proposal block");
                                    return Ok(());
                                }
                            };
                        self.sign_block(writer, block, check_msg.domain_hash).await;
                    }
                };
            }
        }
        Ok(())
    }
}

pub struct DvfSigner {
    pub signal: Option<exit_future::Signal>,
    pub operator_id: u64,
    pub operator_committee: OperatorCommittee,
    pub local_keypair: Keypair,
    pub store: Store,
    pub node_secret: hscrypto::SecretKey,
}

impl Drop for DvfSigner {
    fn drop(&mut self) {
        if let Some(signal) = self.signal.take() {
            info!("Shutting down dvf signer");
            let _ = signal.fire();
        }
    }
}

impl DvfSigner {
    pub async fn spawn<T: EthSpec>(
        node_para: Arc<RwLock<Node<T>>>,
        keypair: Keypair,
        committee_def: OperatorCommitteeDefinition,
        slashing_protection: SlashingDatabase,
    ) -> Result<Self, DvfError> {
        let node_tmp = Arc::clone(&node_para);
        let node = node_tmp.read().await;
        let node_secret = node.secret.secret.clone();
        let validator_id = committee_def.validator_id;
        // find operator id from operatorCommitteeDefinition
        let operator_index: Vec<usize> = committee_def
            .node_public_keys
            .iter()
            .enumerate()
            .filter(|&(_i, x)| node.secret.name == *x)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(operator_index.len(), 1);
        let operator_id = committee_def.operator_ids[operator_index[0]];
        // Construct the committee for validator signing
        let mut operator_committee =
            OperatorCommittee::from_definition(committee_def.clone()).await;
        let local_operator = Arc::new(RwLock::new(LocalOperator::new(
            validator_id,
            operator_id,
            Arc::new(keypair.clone()),
            node.config.base_address,
        )));
        operator_committee
            .add_operator(operator_id, local_operator)
            .await;

        // Construct the committee for hotstuff protocol
        // let epoch = 1;
        // let stake = 1;
        // let mempool_committee = MempoolCommittee::new(
        //     committee_def
        //         .node_public_keys
        //         .iter()
        //         .enumerate()
        //         .map(|(i, pk)| {
        //             let addr = committee_def.base_socket_addresses[i].unwrap_or(invalid_addr());
        //             (
        //                 pk.clone(),
        //                 stake,
        //                 base_to_transaction_addr(addr),
        //                 base_to_mempool_addr(addr),
        //                 base_to_signature_addr(addr),
        //             )
        //         })
        //         .collect(),
        //     epoch,
        // );
        // let consensus_committee = ConsensusCommittee::new(
        //     committee_def
        //         .node_public_keys
        //         .iter()
        //         .enumerate()
        //         .map(|(i, pk)| {
        //             let addr = committee_def.base_socket_addresses[i].unwrap_or(invalid_addr());
        //             (pk.clone(), stake, base_to_consensus_addr(addr))
        //         })
        //         .collect(),
        //     epoch,
        // );
        // let hotstuff_committee = HotstuffCommittee {
        //     mempool: mempool_committee,
        //     consensus: consensus_committee,
        // };

        let store_path = node
            .config
            .base_store_path
            .join(validator_id.to_string())
            .join(operator_id.to_string());
        let store = Store::new(&store_path.to_str().unwrap())
            .map_err(|e| DvfError::StoreError(format!("Failed to create store: {:?}", e)))?;

        let (signal, exit) = exit_future::signal();
        Node::spawn_committee_ip_monitor(node_para, committee_def.clone(), exit);

        node.signature_handler_map.write().await.insert(
            validator_id,
            DvfSignatureReceiverHandler {
                store: store.clone(),
            },
        );
        info!("Insert signature handler for validator: {}", validator_id);
        let operator_pks: HashMap<u64, hscrypto::PublicKey> = committee_def
            .operator_ids
            .into_iter()
            .zip(committee_def.node_public_keys.into_iter())
            .collect();

        node.duties_handler_map.write().await.insert(
            validator_id,
            DvfDutyCheckHandler {
                store: store.clone(),
                slashing_protection: slashing_protection,
                validator_pk: operator_committee.get_validator_pk(),
                operator_pks,
                keypair: keypair.clone(),
                _phantom: PhantomData,
            },
        );
        info!("Insert duties handler for validator: {}", validator_id);

        // DvfCore::spawn(
        //     operator_id,
        //     node_para.clone(),
        //     committee_def.validator_id,
        //     hotstuff_committee,
        //     keypair.clone(),
        //     tx_consensus,
        //     store.clone(),
        //     exit.clone(),
        // )
        // .await;

        Ok(Self {
            signal: Some(signal),
            operator_id,
            operator_committee,
            local_keypair: keypair,
            store,
            node_secret,
        })
    }

    pub async fn threshold_sign(
        &self,
        message: Hash256,
    ) -> Result<(Signature, Vec<u64>), DvfError> {
        self.operator_committee.sign(message).await
    }

    pub fn local_sign(&self, message: Hash256) -> Signature {
        self.local_keypair.sk.sign(message)
    }

    pub async fn local_sign_and_store(&self, message: Hash256) {
        let sig = self.local_sign(message);
        let serialized_signature = bincode::serialize(&sig).unwrap();
        // save to local db
        let key = message.as_bytes().into();
        self.store.write(key, serialized_signature).await;
    }

    pub async fn is_aggregator(&self, nonce: u64) -> bool {
        self.operator_committee.get_leader(nonce).await == self.operator_id
            || self.operator_committee.get_leader(nonce + 1).await == self.operator_id
    }

    pub async fn consensus_on_duty(&self, domain_hash: Hash256, check_type: DvfType, data: &[u8]) {
        let mut msg = DvfDutyCheckMessage {
            operator_id: self.operator_id,
            domain_hash,
            check_type,
            data: data.to_vec(),
            sign_hex: None,
        };
        match msg.sign_digest(&self.node_secret) {
            Ok(sign_hex) => msg.sign_hex = Some(sign_hex),
            Err(_) => {
                error!("failed to sign msg");
                return;
            }
        }
        self.operator_committee
            .consensus_on_duty(&bincode::serialize(&msg).unwrap())
            .await;
    }

    pub fn validator_public_key(&self) -> BlsPublicKey {
        self.operator_committee.get_validator_pk()
    }

    pub fn operator_id(&self) -> u64 {
        self.operator_id
    }
}

pub struct DvfCore {
    pub store: Store,
    // pub commit: Receiver<Block>,
    pub validator_id: u64,
    pub operator_id: u64,
    pub bls_keypair: Keypair,
    pub tx_consensus: MonitoredSender<Hash256>,
    pub exit: exit_future::Exit,
}

unsafe impl Send for DvfCore {}

unsafe impl Sync for DvfCore {}

impl DvfCore {
    pub async fn spawn<T: EthSpec>(
        operator_id: u64,
        _node: Arc<RwLock<Node<T>>>,
        validator_id: u64,
        _committee: HotstuffCommittee,
        _keypair: Keypair,
        _tx_consensus: MonitoredSender<Hash256>,
        _store: Store,
        _exit: exit_future::Exit,
    ) {
        // let node = node.read().await;

        // let (tx_commit, rx_commit) =
        //     MonitoredChannel::new(DEFAULT_CHANNEL_CAPACITY, "dvf-commit".to_string(), "info");
        // let (tx_consensus_to_mempool, rx_consensus_to_mempool) =
        //     MonitoredChannel::new(DEFAULT_CHANNEL_CAPACITY, "dvf-cs2mp".to_string(), "info");
        // let (tx_mempool_to_consensus, rx_mempool_to_consensus) =
        //     MonitoredChannel::new(DEFAULT_CHANNEL_CAPACITY, "dvf-mp2cs".to_string(), "info");

        // let parameters = Parameters::default();

        // Run the signature service.
        // let signature_service = SignatureService::new(node.secret.secret.clone());

        // node.signature_handler_map.write().await.insert(
        //     validator_id,
        //     DvfSignatureReceiverHandler {
        //         store: store.clone(),
        //     },
        // );
        // info!("Insert signature handler for validator: {}", validator_id);

        // Mempool::spawn(
        //     node.secret.name,
        //     committee.mempool,
        //     parameters.mempool,
        //     store.clone(),
        //     rx_consensus_to_mempool,
        //     tx_mempool_to_consensus,
        //     validator_id,
        //     Arc::clone(&node.tx_handler_map),
        //     Arc::clone(&node.mempool_handler_map),
        //     exit.clone(),
        // )
        // .await;

        // Consensus::spawn(
        //     node.secret.name,
        //     committee.consensus,
        //     parameters.consensus,
        //     signature_service,
        //     store.clone(),
        //     rx_mempool_to_consensus,
        //     tx_consensus_to_mempool,
        //     tx_commit,
        //     validator_id,
        //     Arc::clone(&node.consensus_handler_map),
        //     exit.clone(),
        // )
        // .await;

        info!("[Dvf {}/{}] successfully booted", operator_id, validator_id);

        // tokio::spawn(async move {
        //     Self {
        //         store: store,
        //         // commit: rx_commit,
        //         validator_id: validator_id,
        //         operator_id: operator_id,
        //         bls_keypair: keypair,
        //         tx_consensus,
        //         exit,
        //     }
        //     .run()
        //     .await
        // });
    }

    // pub async fn run(&mut self) {
    //     info!(
    //         "[Dvf {}/{}] start receiving committed consensus blocks",
    //         self.operator_id, self.validator_id
    //     );
    //     loop {
    //         let exit = self.exit.clone();
    //         tokio::select! {
    //             Some(block) = self.commit.recv() => {
    //                 // This is where we can further process committed block.
    //                 if block.payload.is_empty() {
    //                     continue;
    //                 }
    //                 debug!("[Dvf {}/{}] received a non-empty committed block", self.operator_id, self.validator_id);
    //                 for payload in block.payload {
    //                     match self.store.read(payload.to_vec()).await {
    //                         Ok(value) => {
    //                             match value {
    //                                 Some(data) => {
    //                                     let message: MempoolMessage = bincode::deserialize(&data[..]).unwrap();
    //                                     match message {
    //                                         MempoolMessage::Batch(batches) => {
    //                                             for batch in batches {
    //                                                 // construct hash256
    //                                                 let msg = Hash256::from_slice(&batch[..]);
    //                                                 if let Err(e) = self.tx_consensus.send(msg).await {
    //                                                     error!("Failed to notify consensus status: {}", e);
    //                                                 }
    //                                                 else {
    //                                                     debug!("[Dvf {}/{}] Sent out 1 consensus notification for msg: {}", self.operator_id, self.validator_id, msg);
    //                                                 }
    //                                             }
    //                                         }
    //                                         MempoolMessage::BatchRequest(_, _) => { }
    //                                     }
    //                                 }
    //                                 None => {
    //                                     warn!("block is empty");
    //                                 }
    //                             }
    //                         },
    //                         Err(e) => {
    //                             error!("can't read database, {}", e)
    //                         }
    //                     }
    //                 }
    //             }
    //             () = exit => {
    //                 break;
    //             }
    //         }
    //     }
    //     self.store.exit().await;
    //     info!(
    //         "[Dvf {}/{}] exit dvf core",
    //         self.operator_id, self.validator_id
    //     );
    // }
}
