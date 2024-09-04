//! Reference: lighthouse/validator_client/signing_method.rs
//!
//! Provides methods for obtaining validator signatures, including:
//!
//! - Via a local `Keypair`.
//! - Via a remote signer (Web3Signer)
//! - Via a distributed operator committee

use crate::node::config::{API_ADDRESS, COLLECT_PERFORMANCE_URL};
use crate::node::dvfcore::DvfSigner;
use crate::node::utils::{request_to_web_server, DvfPerformanceRequest, SignDigest};
use crate::validation::eth2_keystore_share::keystore_share::KeystoreShare;
use crate::validation::http_metrics::metrics;
use chrono::prelude::*;
use eth2_keystore::Keystore;
use lockfile::Lockfile;
use parking_lot::Mutex;
use reqwest::Client;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use task_executor::TaskExecutor;
use tokio::time::sleep;
use types::*;
use url::Url;
pub use web3signer::Web3SignerObject;
use web3signer::{ForkInfo, SigningRequest, SigningResponse};
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
    GenesisForkVersionRequired,
    CommitteeSignFailed(String),
    SignDigestFailed(String),
    NotLeader,
}

/// Enumerates all messages that can be signed by a validator.
pub enum SignableMessage<'a, T: EthSpec, Payload: AbstractExecPayload<T> = FullPayload<T>> {
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
    ValidatorRegistration(&'a ValidatorRegistrationData),
    VoluntaryExit(&'a VoluntaryExit),
}

impl<'a, T: EthSpec, Payload: AbstractExecPayload<T>> SignableMessage<'a, T, Payload> {
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
            SignableMessage::ValidatorRegistration(v) => v.signing_root(domain),
            SignableMessage::VoluntaryExit(exit) => exit.signing_root(domain),
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
    pub async fn get_signature<T: EthSpec, Payload: AbstractExecPayload<T>>(
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
            epoch,
            ..
        } = signing_context;

        let signing_root = signable_message.signing_root(domain_hash);

        let fork_info = Some(ForkInfo {
            fork,
            genesis_validators_root,
        });
        let seconds_per_slot = spec.seconds_per_slot;
        self.get_signature_from_root(
            signable_message,
            signing_root,
            executor,
            fork_info,
            epoch,
            seconds_per_slot,
        )
        .await
    }

    /// Return the signature of `signable_message`, with respect to the `signing_context`.
    pub async fn get_signature_from_root<T: EthSpec, Payload: AbstractExecPayload<T>>(
        &self,
        signable_message: SignableMessage<'_, T, Payload>,
        signing_root: Hash256,
        executor: &TaskExecutor,
        fork_info: Option<ForkInfo>,
        signing_epoch: Epoch,
        seconds_per_slot: u64,
    ) -> Result<Signature, Error> {
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
                    SignableMessage::ValidatorRegistration(v) => {
                        Web3SignerObject::ValidatorRegistration(v)
                    }
                    SignableMessage::VoluntaryExit(e) => Web3SignerObject::VoluntaryExit(e),
                };

                // Determine the Web3Signer message type.
                let message_type = object.message_type();

                if matches!(
                    object,
                    Web3SignerObject::Deposit { .. } | Web3SignerObject::ValidatorRegistration(_)
                ) && fork_info.is_some()
                {
                    return Err(Error::GenesisForkVersionRequired);
                }

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
                let _timer = metrics::start_timer_vec(
                    &metrics::SIGNING_TIMES,
                    &[metrics::DISTRIBUTED_KEYSTORE],
                );

                let (slot, duty, only_aggregator) = match signable_message {
                    SignableMessage::RandaoReveal(e) => {
                        // Every operator should be able to get randao signature,
                        // otherwise if, e.g, only 2 out of 4 gets the randao signature,
                        // then the committee wouldn't be able to get enough partial signatuers for
                        // aggregation, because the other 2 operations who don't get the randao
                        // will NOT enter the next phase of signing block.
                        (e.start_slot(T::slots_per_epoch()), "RANDAO", false)
                    }
                    SignableMessage::AttestationData(a) => (a.slot, "ATTESTER", true),
                    SignableMessage::BeaconBlock(b) => (b.slot(), "PROPOSER", true),
                    SignableMessage::SignedAggregateAndProof(x) => {
                        (x.aggregate.data.slot, "AGGREGATE", true)
                    }
                    SignableMessage::SelectionProof(s) => {
                        // Every operator should be able to get selection proof signature,
                        // otherwise operators who don't get selection proof signature will
                        // NOT be able to insert the ATTESTER duties into their local cache,
                        // hence will NOT enter the corresponding phase of signing attestation.
                        (s, "SELECT", false)
                    }
                    SignableMessage::SyncSelectionProof(s) => (s.slot, "SYNC_SELECT", false),
                    SignableMessage::SyncCommitteeSignature {
                        beacon_block_root: _,
                        slot,
                    } => (slot, "SYNC_COMMITTEE", true),
                    SignableMessage::SignedContributionAndProof(c) => {
                        (c.contribution.slot, "CONTRIB", true)
                    }
                    SignableMessage::ValidatorRegistration(_) => (
                        signing_epoch.start_slot(T::slots_per_epoch()),
                        "VA_REG",
                        false,
                    ),
                    SignableMessage::VoluntaryExit(e) => {
                        (e.epoch.start_slot(T::slots_per_epoch()), "VA_EXIT", true)
                    }
                };
                let is_aggregator = dvf_signer
                    .is_propose_aggregator(
                        signing_epoch.as_u64() + dvf_signer.operator_committee.validator_id(),
                    )
                    .await;
                log::info!(
                    "[Dvf {}/{}] Signing\t-\tSlot: {}.\tEpoch: {}.\tType: {}.\tRoot: {:?}. Is aggregator {}",
                    dvf_signer.operator_id,
                    dvf_signer.operator_committee.validator_id(),
                    slot,
                    signing_epoch.as_u64(),
                    duty,
                    signing_root,
                    is_aggregator
                );

                // Following LocalKeystore, if the code logic reaches here, then it has already passed all checks of this duty, and
                // it is safe (from this operator's point of view) to sign it locally.
                dvf_signer.local_sign_and_store(signing_root).await;

                if !only_aggregator || (only_aggregator && is_aggregator) {
                    
                    // if duty == "PROPOSER" && dvf_signer.is_propose_aggregator(signing_epoch.as_u64() + dvf_signer.operator_committee.validator_id()).await {
                    //     return Err(Error::NotLeader);
                    // }

                    log::info!("[Dvf {}/{}] Leader trying to achieve {} consensus and aggregate duty signatures",
                        dvf_signer.operator_id,
                        dvf_signer.operator_committee.validator_id(),
                        duty
                    );
                    // Should NOT take more than a slot duration for two reasons:
                    // 1. if longer than slot duration, it might affect duty retrieval for other VAs (for example, previously,
                    // I set this to be the epoch remaining time for selection proof, so bad committee (VA) might take several mintues
                    // to timeout, making duties of other VAs outdated.)
                    // 2. most duties should complete in a slot
                    let task_timeout = Duration::from_secs(seconds_per_slot * 2 / 3);
                    let timeout = sleep(task_timeout);
                    let work = dvf_signer.threshold_sign(signing_root);
                    let dt: DateTime<Utc> = Utc::now();
                    tokio::select! {
                        result = work => {
                            match result {
                                Ok((signature, ids)) => {
                                    // [Issue] Several same reports will be sent to server from different aggregators
                                    Self::dvf_report::<T>(slot, duty, dvf_signer.validator_public_key(), dvf_signer.operator_id(), ids, dt, &dvf_signer.node_secret).await?;
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
                } else {
                    Err(Error::NotLeader)
                }
            }
        }
    }

    async fn dvf_report<E: EthSpec>(
        slot: Slot,
        duty: &str,
        validator_pk: String,
        operator_id: u64,
        ids: Vec<u64>,
        dt: DateTime<Utc>,
        secret: &hscrypto::SecretKey,
    ) -> Result<(), Error> {
        let signing_epoch = slot.epoch(E::slots_per_epoch());

        if duty == "ATTESTER" || duty == "PROPOSER" {
            let mut request_body = DvfPerformanceRequest {
                validator_pk,
                operator_id,
                operators: ids,
                slot: slot.as_u64(),
                epoch: signing_epoch.as_u64(),
                duty: duty.to_string(),
                time: Utc::now().signed_duration_since(dt).num_milliseconds(),
                sign_hex: None,
            };
            request_body.sign_hex = Some(
                request_body
                    .sign_digest(secret)
                    .map_err(|e| Error::SignDigestFailed(e))?,
            );
            log::debug!("[Dvf Request] Body: {:?}", &request_body);
            let url_str = API_ADDRESS.get().unwrap().to_owned() + COLLECT_PERFORMANCE_URL;
            tokio::spawn(async move {
                _ = request_to_web_server(request_body, &url_str)
                    .await
                    .map_err(|e| Error::Web3SignerRequestFailed(e));
            });
        }
        Ok(())
    }
}
