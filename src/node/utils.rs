use crate::node::contract::SELF_OPERATOR_ID;
use hscrypto::{Digest, SecretKey, Signature};
use keccak_hash::keccak;
use log::{error, info};
use reqwest::{Client, Error};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::{fs::File, time::Duration};
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

pub trait SignDigest {
    fn sign_digest(&self, secret: &SecretKey) -> Result<String, String>
    where
        Self: Serialize,
    {
        let ser_json =
            serde_json::to_string(self).map_err(|e| format!("error serialize {:?}", e))?;
        let digest = keccak(ser_json.as_bytes());
        let sig = Signature::new(&Digest::from(digest.as_fixed_bytes()), secret);
        Ok(hex::encode(sig.flatten()))
    }
}

#[derive(Debug, PartialEq, Serialize)]
pub struct DvfPerformanceRequest {
    #[serde(rename = "publicKey")]
    pub validator_pk: String,
    #[serde(rename = "operatorId")]
    pub operator_id: u64,
    pub operators: Vec<u64>,
    pub slot: u64,
    pub epoch: u64,
    pub duty: String,
    pub time: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
}

impl SignDigest for DvfPerformanceRequest {}

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
    pub shared_public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
}

impl SignDigest for ValidatorPkRequest {}

#[derive(Debug, Serialize)]
pub struct DepositRequest {
    #[serde(rename = "validatorPk")]
    pub validator_pk: String,
    #[serde(rename = "withdrawalCredentials")]
    pub withdrawal_credentials: String,
    pub amount: u64,
    pub signature: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sign_hex: Option<String>,
    #[serde(rename = "operatorId")]
    pub operator_id: u32,
}

impl SignDigest for DepositRequest {}

impl DepositRequest {
    pub fn convert(deposit: DepositData) -> Self {
        let pk_str: String = deposit.pubkey.as_hex_string()[2..].to_string();
        Self {
            validator_pk: pk_str,
            withdrawal_credentials: format!("{0:0x}", deposit.withdrawal_credentials),
            amount: deposit.amount,
            signature: hex::encode(deposit.signature.serialize()),
            sign_hex: None,
            operator_id: *SELF_OPERATOR_ID.get().unwrap(),
        }
    }
}

#[derive(Deserialize, Serialize)]
struct Response {
    code: usize,
    message: String,
}

pub async fn request_to_web_server<T: Serialize>(body: T, url_str: &str) -> Result<(), String> {
    let client = Client::builder()
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let url = Url::parse(url_str).map_err(|_e| format!("Can't parse url {}", url_str))?;
    for _ in 0..3 {
        match client.post(url.clone()).json(&body).send().await {
            Ok(result) => {
                let response: Result<Response, Error> = result.json().await;
                match response {
                    Ok(res) => {
                        if res.code == 200 {
                            info!(
                                "Successfully send request {}",
                                serde_json::to_string(&body).unwrap()
                            );
                            break;
                        } else {
                            error!(
                                "Can't send request, response: {:?}, retrying",
                                serde_json::to_string(&res).unwrap()
                            )
                        }
                    }
                    Err(e) => {
                        error!("Can't send request: {:?}, retrying", e);
                    }
                }
            }
            Err(e) => {
                error!("Can't send request: {}", e);
            }
        };
    }
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
    use hsconfig::Secret;
    use hscrypto::{PublicKey, SecretKey};
    #[derive(Debug, PartialEq, Serialize)]
    pub struct DvfPerformanceRequestTest {
        #[serde(rename = "publicKey")]
        pub validator_pk: String,
        #[serde(rename = "operatorId")]
        pub operator_id: u64,
        pub operators: Vec<u64>,
        pub slot: u64,
        pub epoch: u64,
        pub duty: String,
        pub time: i64,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub sign_hex: Option<String>,
    }

    impl SignDigest for DvfPerformanceRequestTest {}

    let request = DvfPerformanceRequestTest {
        validator_pk: "0xb5e172c2d0eac645da9266a42cadcfda25845effccd01c084f5047ed208d89ff1229bbb54ae43bd74dbdbacc756fead7".to_string(),
        operator_id: 1,
        operators: vec![1, 2, 3],
        slot: 5739801,
        epoch: 179368,
        duty: "ATTESTER".to_string(),
        time: 0,
        sign_hex: None
    };
    let test_secret = Secret {
        name: PublicKey::decode_base64("Au8M2eERK1GCyt6njUQG1Bt0RYbWlJbZlcGFklDYbvVN").unwrap(),
        secret: SecretKey::decode_base64("AQ+PCzHRx/bLEwhJhd8FjGR+88/CUO1RljqmDKn5Rds=").unwrap(),
    };
    assert_eq!("9bf90a6ce2da00518db91042d38b1bbca479d2479ae0b0c5fc8b10a21d95036c5b601d9c4efdc7541fe92ebdadfebb628f05399a960f47df5c9015c29e57835d".to_string(), request.sign_digest(&test_secret.secret).unwrap());
}
