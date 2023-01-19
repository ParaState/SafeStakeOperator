//! Reference: lighthouse/validator_client/signing_method.rs
//!
//! Provides methods for obtaining validator signatures, including:
//!
//! - Via a local `Keypair`.
//! - Via a remote signer (Web3Signer)
//! - Via a distributed operator committee

use crate::validation::http_metrics::metrics;
use eth2_keystore::Keystore;
use lockfile::Lockfile;
use parking_lot::Mutex;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use task_executor::TaskExecutor;
use types::*;
use url::Url;
use web3signer::{ForkInfo, SigningRequest, SigningResponse};
use crate::node::dvfcore::{DvfSigner, DvfPerformanceRequest};
use crate::node::config::{API_ADDRESS, COLLECT_PERFORMANCE_URL};
use crate::node::utils::request_to_web_server;
pub use web3signer::Web3SignerObject;
use chrono::prelude::*;
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use std::time::Duration;
use tokio::time::sleep;
mod web3signer;

#[derive(Debug, PartialEq)]
pub enum Error {
    InconsistentDomains {
        message_type_domain: Domain,
        domain: Domain,
    },
    Web3SignerRequestFailed(String),
    Web3SignerJsonParsingFailed(String),
    ShuttingDown,
    TokioJoin(String),
    MergeForkNotSupported,
    CommitteeSignFailed(String),

    NotLeader,
}

/// Enumerates all messages that can be signed by a validator.
pub enum SignableMessage<'a, T: EthSpec, Payload: ExecPayload<T> = FullPayload<T>> {
    RandaoReveal(Epoch),
    BeaconBlock(&'a BeaconBlock<T, Payload>),
    AttestationData(&'a AttestationData),
    SignedAggregateAndProof(&'a AggregateAndProof<T>),
    SelectionProof(Slot),
    SyncSelectionProof(&'a SyncAggregatorSelectionData),
    SyncCommitteeSignature {
        beacon_block_root: Hash256,
        slot: Slot,
    },
    SignedContributionAndProof(&'a ContributionAndProof<T>),
}

impl<'a, T: EthSpec, Payload: ExecPayload<T>> SignableMessage<'a, T, Payload> {
    /// Returns the `SignedRoot` for the contained message.
    ///
    /// The actual `SignedRoot` trait is not used since it also requires a `TreeHash` impl, which is
    /// not required here.
    pub fn signing_root(&self, domain: Hash256) -> Hash256 {
        match self {
            SignableMessage::RandaoReveal(epoch) => epoch.signing_root(domain),
            SignableMessage::BeaconBlock(b) => b.signing_root(domain),
            SignableMessage::AttestationData(a) => a.signing_root(domain),
            SignableMessage::SignedAggregateAndProof(a) => a.signing_root(domain),
            SignableMessage::SelectionProof(slot) => slot.signing_root(domain),
            SignableMessage::SyncSelectionProof(s) => s.signing_root(domain),
            SignableMessage::SyncCommitteeSignature {
                beacon_block_root, ..
            } => beacon_block_root.signing_root(domain),
            SignableMessage::SignedContributionAndProof(c) => c.signing_root(domain),
        }
    }
}

/// A method used by a validator to sign messages.
pub enum SigningMethod {
    /// A validator that is defined by an EIP-2335 keystore on the local filesystem.
    LocalKeystore {
        voting_keystore_path: PathBuf,
        voting_keystore_lockfile: Mutex<Option<Lockfile>>,
        voting_keystore: Keystore,
        voting_keypair: Arc<Keypair>,
    },
    /// A validator that defers to a Web3Signer server for signing.
    ///
    /// See: https://docs.web3signer.consensys.net/en/latest/
    Web3Signer {
        signing_url: Url,
        http_client: Client,
        voting_public_key: PublicKey,
    },
    /// A validator whose key is distributed among a set of operators.
    DistributedKeystore {
        voting_keystore_share_path: PathBuf,
        voting_keystore_share_lockfile: Mutex<Option<Lockfile>>,
        voting_keystore_share: KeystoreShare,
        voting_public_key: PublicKey,
        dvf_signer: DvfSigner,
    },
}

/// The additional information used to construct a signature. Mostly used for protection from replay
/// attacks.
pub struct SigningContext {
    pub domain: Domain,
    pub epoch: Epoch,
    pub fork: Fork,
    pub genesis_validators_root: Hash256,
}

impl SigningContext {
    /// Returns the `Hash256` to be mixed-in with the signature.
    pub fn domain_hash(&self, spec: &ChainSpec) -> Hash256 {
        spec.get_domain(
            self.epoch,
            self.domain,
            &self.fork,
            self.genesis_validators_root,
        )
    }
}

impl SigningMethod {
    /// Return the signature of `signable_message`, with respect to the `signing_context`.
    pub async fn get_signature<T: EthSpec, Payload: ExecPayload<T>>(
        &self,
        signable_message: SignableMessage<'_, T, Payload>,
        signing_context: SigningContext,
        spec: &ChainSpec,
        executor: &TaskExecutor,
    ) -> Result<Signature, Error> {
        let domain_hash = signing_context.domain_hash(spec);
        let SigningContext {
            fork,
            genesis_validators_root,
            ..
        } = signing_context;

        let signing_root = signable_message.signing_root(domain_hash);

        match self {
            SigningMethod::LocalKeystore { voting_keypair, .. } => {
                let _timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::LOCAL_KEYSTORE]);

                let voting_keypair = voting_keypair.clone();
                // Spawn a blocking task to produce the signature. This avoids blocking the core
                // tokio executor.
                let signature = executor
                    .spawn_blocking_handle(
                        move || voting_keypair.sk.sign(signing_root),
                        "local_keystore_signer",
                    )
                    .ok_or(Error::ShuttingDown)?
                    .await
                    .map_err(|e| Error::TokioJoin(e.to_string()))?;
                Ok(signature)
            }
            SigningMethod::Web3Signer {
                signing_url,
                http_client,
                ..
            } => {
                let _timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::WEB3SIGNER]);

                // Map the message into a Web3Signer type.
                let object = match signable_message {
                    SignableMessage::RandaoReveal(epoch) => {
                        Web3SignerObject::RandaoReveal { epoch }
                    }
                    SignableMessage::BeaconBlock(block) => Web3SignerObject::beacon_block(block)?,
                    SignableMessage::AttestationData(a) => Web3SignerObject::Attestation(a),
                    SignableMessage::SignedAggregateAndProof(a) => {
                        Web3SignerObject::AggregateAndProof(a)
                    }
                    SignableMessage::SelectionProof(slot) => {
                        Web3SignerObject::AggregationSlot { slot }
                    }
                    SignableMessage::SyncSelectionProof(s) => {
                        Web3SignerObject::SyncAggregatorSelectionData(s)
                    }
                    SignableMessage::SyncCommitteeSignature {
                        beacon_block_root,
                        slot,
                    } => Web3SignerObject::SyncCommitteeMessage {
                        beacon_block_root,
                        slot,
                    },
                    SignableMessage::SignedContributionAndProof(c) => {
                        Web3SignerObject::ContributionAndProof(c)
                    }
                };

                // Determine the Web3Signer message type.
                let message_type = object.message_type();

                // The `fork_info` field is not required for deposits since they sign across the
                // genesis fork version.
                let fork_info = if let Web3SignerObject::Deposit { .. } = &object {
                    None
                } else {
                    Some(ForkInfo {
                        fork,
                        genesis_validators_root,
                    })
                };

                let request = SigningRequest {
                    message_type,
                    fork_info,
                    signing_root,
                    object,
                };

                // Request a signature from the Web3Signer instance via HTTP(S).
                let response: SigningResponse = http_client
                    .post(signing_url.clone())
                    .json(&request)
                    .send()
                    .await
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| Error::Web3SignerRequestFailed(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| Error::Web3SignerJsonParsingFailed(e.to_string()))?;

                Ok(response.signature)
            }
            SigningMethod::DistributedKeystore { dvf_signer, .. } => {
                let _timer =
                    metrics::start_timer_vec(&metrics::SIGNING_TIMES, &[metrics::LOCAL_KEYSTORE]);
                // if dvf_signer.is_leader(SigningMethod::convert_signingroot_to_u64(&signing_root)).await {
                if dvf_signer.is_leader(signing_context.epoch.as_u64()).await {
                    let (slot, duty) = match signable_message {
                        SignableMessage::RandaoReveal(_) => {
                            (Slot::new(0 as u64), "RANDAO")
                        }
                        SignableMessage::AttestationData(a) => {
                            (a.slot, "ATTESTER")
                        },
                        SignableMessage::BeaconBlock(b) => {
                            (b.slot(), "PROPOSER")
                        },
                        SignableMessage::SignedAggregateAndProof(x) => {
                            (x.aggregate.data.slot, "AGGREGATE")
                        }
                        SignableMessage::SelectionProof(s) => {
                            (s, "SELECT")
                        }
                        SignableMessage::SyncSelectionProof(_) => {
                            (Slot::new(0 as u64), "SYNC_SELECT")
                        }
                        SignableMessage::SyncCommitteeSignature{..} => {
                            (Slot::new(0 as u64), "SYNC_COMMITTEE")
                        }
                        SignableMessage::SignedContributionAndProof(_) => {
                            (Slot::new(0 as u64), "CONTRIB")
                        }
                    };

                    log::info!("[Dvf {}/{}] Signing\t-\tSlot: {}.\tEpoch: {}.\tType: {}.\tRoot: {:?}.", 
                               dvf_signer.operator_id, 
                               dvf_signer.operator_committee.validator_id(),
                               slot,
                               signing_context.epoch.as_u64(),
                               duty,
                               signing_root
                            );

                    let validator_pk = dvf_signer.validator_public_key();
                    let operator_id = dvf_signer.operator_id();
                    let dt : DateTime<Utc> = Utc::now();

                    // Should NOT take more than a slot duration for two reasons:
                    // 1. if longer than slot duration, it might affect duty retrieval for other VAs (for example, previously,
                    // I set this to be the epoch remaining time for selection proof, so bad committee (VA) might take several mintues
                    // to timeout, making duties of other VAs outdated.)
                    // 2. most duties should complete in a slot
                    let task_timeout = Duration::from_secs(spec.seconds_per_slot / 2);

                    let work = dvf_signer.sign(signing_root);
                    let timeout = sleep(task_timeout);
                    tokio::select!{
                        result = work => {
                            match result {
                                Ok((signature, ids)) => {
                                    if duty ==  "ATTESTER" || duty == "PROPOSER" {
                                        let request_body = DvfPerformanceRequest {
                                            validator_pk,
                                            operator_id,
                                            operators: ids, 
                                            slot: slot.as_u64(),
                                            epoch: signing_context.epoch.as_u64(),
                                            duty: duty.to_string(),
                                            time: Utc::now().signed_duration_since(dt).num_milliseconds()
                                        };
                                        log::info!("[Dvf Request] Body: {:?}", &request_body);
                                        let url_str = API_ADDRESS.get().unwrap().to_owned() + COLLECT_PERFORMANCE_URL;
                                        request_to_web_server(request_body, &url_str).await.map_err(|e| Error::Web3SignerRequestFailed(e))?;
                                    }
                                    Ok(signature)
                                },
                                Err(e) => {
                                    Err(Error::CommitteeSignFailed(format!("{:?}", e)))
                                }
                            }
                        }
                        _ = timeout => {
                            Err(Error::CommitteeSignFailed(format!("Timeout")))
                        }
                    }
                }
                else {
                    Err(Error::NotLeader)
                }
            }
        }
    }

    pub fn convert_signingroot_to_u64(signing_root: &types::Hash256) -> u64 {
        let mut little_endian: [u8; 8] = [0; 8];
        let mut i = 0;
        for elem in little_endian.iter_mut() {
            *elem = signing_root.0[i];
            i = i + 1;
        } 
        let nonce = u64::from_le_bytes(little_endian);
        nonce 
    }
}

