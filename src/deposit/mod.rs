use types::{EthSpec, SignedRoot, ChainSpec, DepositData};
use bls::{Hash256, Signature, SignatureBytes, PublicKeyBytes};
use crate::utils::error::DvfError;
use crate::crypto::dkg::SimpleDistributedSigner;
use crate::network::io_committee::{IOCommittee, IOChannel};
use eth2::{BeaconNodeHttpClient, Timeouts};
use std::time::Duration;
use sensitive_url::SensitiveUrl;
use log::{error, info};

/// Gets syncing status from beacon node client and returns true if syncing and false otherwise.
async fn is_syncing(client: &BeaconNodeHttpClient) -> Result<bool, String> {
    Ok(client
        .get_node_syncing()
        .await
        .map_err(|e| format!("Failed to get sync status: {:?}", e))?
        .data
        .is_syncing)
}

/// Return a valid BeaconNodeHttpClient.
pub async fn get_valid_beacon_node_http_client(beacon_nodes_urls: &Vec<SensitiveUrl>, spec: &ChainSpec) -> Result<BeaconNodeHttpClient, DvfError> {
    for i in 0..beacon_nodes_urls.len() {
        let client = BeaconNodeHttpClient::new(beacon_nodes_urls[i].clone(), Timeouts::set_all(Duration::from_secs(spec.seconds_per_slot)));
        match is_syncing(&client).await {
            Ok(b) => {
                if b {
                    error!("beacon node is syncing!");
                } else {
                    info!("beacon node is fully synchronized!");
                    return Ok(client);
                }
            },
            Err(e) => {
                error!("Failed to get sync status {}", e)
            }
        }  
    }
    Err(DvfError::BeaconNodeClientError)
}

/// Refer to `/lighthouse/common/deposit_contract/src/lib.rs`
pub async fn get_distributed_deposit<T: IOCommittee<U>, U: IOChannel, E: EthSpec>(
    signer: &SimpleDistributedSigner<T, U>,
    withdrawal_credentials: &[u8; 32],
    amount: u64,
    beacon_nodes_urls: &Vec<SensitiveUrl>
) -> Result<DepositData, DvfError> {
    let mut deposit_data = DepositData {
        pubkey: PublicKeyBytes::from(signer.mpk()),
        withdrawal_credentials: Hash256::from_slice(withdrawal_credentials),
        amount: amount,
        signature: Signature::empty().into(),
    };
    let mut spec = E::default_spec();
    // query genesis fork version from beacon node
    let client = get_valid_beacon_node_http_client(beacon_nodes_urls, &spec).await?;
    let genesis_data = client.get_beacon_genesis().await.map_err(|e| {
        error!("Failed to get beacon genesis data {:?}", e);
        DvfError::BeaconNodeGenesisError
    })?.data;
    spec.genesis_fork_version = genesis_data.genesis_fork_version;
    // spec.genesis_fork_version = [00, 00, 16, 32];    //this value is for goerli testnet
    let domain = spec.get_deposit_domain();
    let msg = deposit_data.as_deposit_message().signing_root(domain);

    let sig = signer.sign(msg).await?;
    deposit_data.signature = SignatureBytes::from(sig);

    Ok(deposit_data)
}

#[test]
pub fn get_deposit_test() {
    let sk = bls::SecretKey::deserialize(&hex::decode("12a660e5a304e3386c0fff53ced385faa25e305cc047aaac0b446f0c2053d4be").unwrap()).unwrap();
    let pk = sk.public_key();
    assert_eq!("0x9200c374d5349e7aa3c145c5f6cb7e973a7257277e0e2024d48318cb8a6d6ca105b517346d9915aed8835defd94b6b5e", pk.as_hex_string());
    let mut deposit_data = DepositData {
        pubkey: pk.into(),
        withdrawal_credentials: Hash256::from_slice(&hex::decode("00076bd8b841544ab6335ae084849141dfd84155a1980d178ac1b96ef1040915").unwrap()),
        amount: 32000000000,
        signature: Signature::empty().into()
    };
    type E = types::MinimalEthSpec;
    let mut spec = E::default_spec().clone();
    spec.genesis_fork_version = [00,00,16,32];
    println!("{:?}", spec.genesis_fork_version);
    deposit_data.signature = deposit_data.create_signature(&sk, &spec);
    println!("{:?}", deposit_data.signature);
}