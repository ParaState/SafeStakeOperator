use std::fs::File;
use std::path::Path;

use reqwest::Client;
use serde::de::DeserializeOwned;
use serde::Serialize;
use log::{error, info};
use types::DepositData;
use url::Url;
use web3::types::H160;


pub trait FromFile<T: DeserializeOwned> {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<T, String> {
        let file = File::options()
            .read(true)
            .open(path)
            .map_err(|e| format!("can't open file {:?}", e))?;
        serde_yaml::from_reader(file).map_err(|e| format!("can't deserialize file {:?}", e))
    }
}

pub trait ToFile {
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String>
        where
            Self: Serialize,
    {
        let file = File::options()
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)
            .map_err(|e| format!("can't open file {:?}", e))?;
        serde_yaml::to_writer(file, self).map_err(|e| format!("can't serialize to file {:?}", e))
    }
}

// all binary data is encoded in hex
#[derive(Debug, Serialize)]
pub struct ValidatorPkRequest {
    #[serde(rename = "validatorPk")]
    pub validator_pk: String,
    #[serde(rename = "initializerId")]
    pub initiator_id: u32,
    #[serde(rename = "initializerAddress")]
    pub initializer_address: String,
    pub operators: Vec<u64>,
    #[serde(rename = "operatorId")]
    pub operator_id: u32,
    #[serde(rename = "encryptedSharedKey")]
    pub encrypted_shared_key: String,
    #[serde(rename = "sharedPublicKey")]
    pub shared_public_key: String
}

#[derive(Debug, Serialize)]
pub struct DepositRequest {
    #[serde(rename = "validatorPk")]
    pub validator_pk: String,
    #[serde(rename = "withdrawalCredentials")]
    pub withdrawal_credentials: String,
    pub amount: u32,
    pub signature: String,
}

impl DepositRequest {
    pub fn convert(deposit: DepositData) -> Self {
        let pk_str: String = deposit.pubkey.as_hex_string()[2..].to_string();
        Self {
            validator_pk: pk_str,
            withdrawal_credentials: format!("{0:0x}", deposit.withdrawal_credentials),
            amount: deposit.amount as u32,
            signature: hex::encode(deposit.signature.serialize()),
        }
    }
}

pub async fn request_to_web_server<T: Serialize>(body: T, url_str: &str) -> Result<(), String> {
    let client = Client::new();
    let url = Url::parse(url_str).map_err(|_e| format!("Can't parse url {}", url_str))?;
    match client.post(url).json(&body).send().await {
        Ok(result) => {
            info!("{:?}", result);
        }
        Err(e) => {
            error!("Can't send request: {}", e);
        }
    };
    Ok(())
}

pub fn convert_va_pk_to_u64(pk: &[u8]) -> u64 {
    let mut little_endian: [u8; 8] = [0; 8];
    let mut i = 0;
    for elem in little_endian.iter_mut() {
        *elem = pk[i];
        i = i + 1;
    }
    let id = u64::from_le_bytes(little_endian);
    id
}

pub fn convert_address_to_withdraw_crendentials(address: H160) -> [u8; 32] {
    let mut credentials = [0; 32];
    credentials[0] = 0x01;
    let address_bytes = address.as_bytes();
    for i in 12..32 {
        credentials[i] = address_bytes[i - 12];
    }
    credentials
}

#[test]
fn request_signature_test() {
    use crate::node::dvfcore::DvfPerformanceRequest;
    use hsconfig::Secret;
    use hscrypto::{PublicKey, SecretKey};
    use keccak_hash::keccak;
    let request = DvfPerformanceRequest {
        validator_pk: "b5e172c2d0eac645da9266a42cadcfda25845effccd01c084f5047ed208d89ff1229bbb54ae43bd74dbdbacc756fead7".to_string(),
        operator_id: 14185842736627717,
        operators: vec![1, 2, 3, 4],
        slot: 6450597,
        epoch: 201581,
        duty: "ATTESTER".to_string(),
        time: 0
    };
    let test_secret = Secret {
        name: PublicKey::decode_base64("Au8M2eERK1GCyt6njUQG1Bt0RYbWlJbZlcGFklDYbvVN").unwrap(),
        secret: SecretKey::decode_base64("AQ+PCzHRx/bLEwhJhd8FjGR+88/CUO1RljqmDKn5Rds=").unwrap()
    };
    let res = serde_json::to_string(&request).unwrap();
    // let hash = keccak(&res.as_bytes());
    let hash = keccak(res.as_bytes());
    println!("{}", res);
    println!("{:?}", hash);
    
}
