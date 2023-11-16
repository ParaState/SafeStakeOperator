use types::{EthSpec, SignedVoluntaryExit, ChainSpec, Epoch, Fork, VoluntaryExit, Domain, SignedRoot};
use eth2::types::{ValidatorData, ValidatorId, ValidatorStatus, StateId};
use bls::PublicKey;
use crate::utils::error::DvfError;
use crate::crypto::dkg::SimpleDistributedSigner;
use crate::network::io_committee::{IOCommittee, IOChannel};
use slot_clock::{SystemTimeSlotClock, SlotClock};
use eth2::BeaconNodeHttpClient;
use std::time::Duration;
use sensitive_url::SensitiveUrl;
use log::error;
use super::deposit::get_valid_beacon_node_http_client;
use safe_arith::SafeArith;

/// Calculates the current epoch from the genesis time and current time.
fn get_current_epoch<E: EthSpec>(genesis_time: u64, spec: &ChainSpec) -> Option<Epoch> {
    let slot_clock = SystemTimeSlotClock::new(
        spec.genesis_slot,
        Duration::from_secs(genesis_time),
        Duration::from_secs(spec.seconds_per_slot),
    );
    slot_clock.now().map(|s| s.epoch(E::slots_per_epoch()))
}

/// Returns the validator data by querying the beacon node client.
async fn get_validator_data(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
) -> Result<ValidatorData, DvfError> {
    Ok(client
        .get_beacon_states_validator_id(
            StateId::Head,
            &ValidatorId::PublicKey(validator_pubkey.into()),
        )
        .await
        .map_err(|e| DvfError::BeaconNodeValidatorError(format!("Failed to get validator details: {:?}", e)))?
        .ok_or_else(|| {
            DvfError::BeaconNodeValidatorError(format!(
                "Validator {} is not present in the beacon state. \
                Please ensure that your beacon node is synced and the validator has been deposited.",
                validator_pubkey
            ))
        })?
        .data)
}

/// Get the validator index of a given the validator public key by querying the beacon node endpoint.
///
/// Returns an error if the beacon endpoint returns an error or given validator is not eligible for an exit.
async fn get_validator_index_for_exit(
    client: &BeaconNodeHttpClient,
    validator_pubkey: &PublicKey,
    epoch: Epoch,
    spec: &ChainSpec,
) -> Result<u64, DvfError> {
    let validator_data = get_validator_data(client, validator_pubkey).await?;

    match validator_data.status {
        ValidatorStatus::ActiveOngoing => {
            let eligible_epoch = validator_data
                .validator
                .activation_epoch
                .safe_add(spec.shard_committee_period)
                .map_err(|e| DvfError::BeaconNodeValidatorError(format!("Failed to calculate eligible epoch, validator activation epoch too high: {:?}", e)))?;

            if epoch >= eligible_epoch {
                Ok(validator_data.index)
            } else {
                Err(DvfError::BeaconNodeValidatorError(format!(
                    "Validator {:?} is not eligible for exit. It will become eligible on epoch {}",
                    validator_pubkey, eligible_epoch
                )))
            }
        }
        status => Err(DvfError::BeaconNodeValidatorError(format!(
            "Validator {:?} is not eligible for voluntary exit. Validator status: {:?}",
            validator_pubkey, status
        ))),
    }
}

/// Get fork object for the current state by querying the beacon node client.
async fn get_beacon_state_fork(client: &BeaconNodeHttpClient) -> Result<Fork, DvfError> {
    Ok(client
        .get_beacon_states_fork(StateId::Head)
        .await
        .map_err(|e| DvfError::BeaconNodeStateForkError(format!("Failed to get get fork: {:?}", e)))?
        .ok_or(DvfError::BeaconNodeStateForkError("Failed to get fork, state not found".to_string()))?
        .data)
}

pub async fn get_distributed_voluntary_exit<T: IOCommittee<U>, U: IOChannel, E: EthSpec>(
    signer: &SimpleDistributedSigner<T, U>,
    beacon_nodes_urls: &Vec<SensitiveUrl>,
    validator_pubkey: &PublicKey
) -> Result<SignedVoluntaryExit, DvfError> {
    let spec = E::default_spec();
    // query genesis_time fron beacon node
    let client = get_valid_beacon_node_http_client(beacon_nodes_urls, &spec).await?;
    let genesis_data = client.get_beacon_genesis().await.map_err(|e| {
        error!("Failed to get beacon genesis data {:?}", e);
        DvfError::BeaconNodeGenesisError
    })?.data;
    let epoch = get_current_epoch::<E>(genesis_data.genesis_time, &spec).ok_or(DvfError::BeaconNodeGenesisError)?;
    let validator_index = get_validator_index_for_exit(&client, validator_pubkey, epoch, &spec).await?;
    let fork = get_beacon_state_fork(&client).await?;
    let voluntary_exit = VoluntaryExit {
        epoch,
        validator_index
    };
    let domain = spec.get_domain(epoch, Domain::VoluntaryExit, &fork, genesis_data.genesis_validators_root);
    let message = voluntary_exit.signing_root(domain);
    let signature = signer.sign(message).await?;
    let signed_voluntary_exit = SignedVoluntaryExit {
        message: voluntary_exit,
        signature: signature
    };
    // info!("{:?}", serde_json::to_string(&signed_voluntary_exit));
    Ok(signed_voluntary_exit)
}

#[tokio::test(flavor = "multi_thread")]
pub async fn test_distrubuted_voluntary_exit() {
    use std::net::SocketAddr;
    use crate::network::io_committee::{SecureNetIOCommittee, SecureNetIOChannel};
    use super::crypto::dkg::{DKGMalicious, DKGTrait};
    use std::sync::Arc;
    use futures::future::join_all;
    use std::collections::HashMap;
    use bls::Keypair;
    use log::info;
    use types::MainnetEthSpec;
    const T: usize = 3;
    const IDS: [u64; 4] = [1, 2, 3, 4];
    
    let args = std::env::args().collect::<Vec<String>>();
    let beacon_node = &args[1].clone();
    let mut logger = env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"));
    logger.format_timestamp_millis();
    logger.init();

    let ports: Vec<u16> = IDS.iter().map(|id| (25000 + *id) as u16).collect();
    let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

    let ports_ref = &ports;
    let addrs_ref = &addrs;

    // Use dkg to generate secret-shared keys
    let futs = (0..IDS.len()).map(|i| async move {
        let io = Arc::new(SecureNetIOCommittee::new(IDS[i], ports_ref[i], IDS.as_slice(), addrs_ref.as_slice()).await);
        let dkg = DKGMalicious::new(IDS[i], io, T);
        let result = dkg.run().await;
        match result {
            Ok(v) => Ok((IDS[i], v)),
            Err(e) => {
                println!("Error in Dkg of party {}: {:?}", IDS[i], e);
                Err(e)
            }
        }
    });

    let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<u64, (Keypair, PublicKey, HashMap<u64, PublicKey>)>>();
    let res = &results;
    let futs = (0..IDS.len()).map(|i| async move {
        let io = Arc::new(SecureNetIOCommittee::new(IDS[i], ports_ref[i], IDS.as_slice(), addrs_ref.as_slice()).await);
        let (keypair, va_pk, shared_pks) = res.get(&IDS[i]).unwrap();
        let signer = SimpleDistributedSigner::new(IDS[i], keypair.clone(), va_pk.clone(), shared_pks.clone(), io, T);
        let signed_voluntary_exit = get_distributed_voluntary_exit::<SecureNetIOCommittee, SecureNetIOChannel, MainnetEthSpec>(&signer, &vec![SensitiveUrl::parse(beacon_node).unwrap()], va_pk).await.unwrap();
        info!("{:?}", serde_json::to_string(&signed_voluntary_exit));
    });
    let _ = join_all(futs).await;
    
}