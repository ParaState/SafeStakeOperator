use reqwest::Client;
use url::Url;
use serde::Serialize;
use tokio::sync::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use crate::node::contract::OperatorPublicKeys;
use log::error;
use std::collections::HashMap;
use serde::de::DeserializeOwned;
use std::fs::File;
use std::path::Path;
use web3::types::H160;
use types::DepositData;
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
    pub initializer_id: u32,
    #[serde(rename = "initializerAddress")]
    pub initializer_address: String,
    pub operators: Vec<u64>,
}

#[derive(Debug, Serialize)]
pub struct DepositRequest {
    #[serde(rename = "validatorPk")]
    pub validator_pk: String,
    #[serde(rename = "withdrawalCredentials")]
    pub withdrawal_credentials: String,
    pub amount: u32,
    pub signature: String
}

impl DepositRequest {
    pub fn convert(deposit: DepositData) -> Self{
        Self {
            validator_pk: deposit.pubkey.as_hex_string(),
            withdrawal_credentials: format!("{0:0x}", deposit.withdrawal_credentials),
            amount: deposit.amount as u32,
            signature: hex::encode(deposit.signature.serialize())
        }
    }
}

pub async fn request_to_web_server<T: Serialize>(body: T, url_str: &str) -> Result<(), String> {
    let client = Client::new();
    let url = Url::parse(url_str).map_err(|e| format!("Can't parse url {}", url_str))?;
    let _ = client.post(url).json(&body).send().await.map_err(|e|"Can't send request".to_string())?;
    Ok(())
}

pub async fn get_operator_ips(
    operator_key_ip_map: Arc<RwLock<HashMap<String, IpAddr>>>,
    operator_public_keys: &OperatorPublicKeys,
    base_port: u16
) -> Result<Vec<SocketAddr>, String> {
    let key_ip_map = operator_key_ip_map.read().await;

    let operator_base_address: Vec<Option<IpAddr>> = operator_public_keys
        .iter()
        .map(|op_pk| {
            let op_pk_str = base64::encode(op_pk);
            key_ip_map.get(&op_pk_str).map_or_else(
                || {
                    error!("Can't discovery operator: {}", op_pk_str);
                    None
                },
                |ip| Some(ip.clone()),
            )
        })
        .collect();
    if operator_base_address.iter().any(|x| x.is_none()) {
        return Err("Insufficient operators discovered".to_string());
    }
    Ok(operator_base_address
        .into_iter()
        .map(|x| SocketAddr::new(x.unwrap(), base_port))
        .collect())
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

pub fn convert_address_to_withdraw_crendentials (address: H160) -> [u8;32] {
    let mut credentials = [0;32];
    credentials[0] = 0x01;
    let address_bytes = address.as_bytes();
    for i in 12..32 {
        credentials[i] = address_bytes[i-12];
    } 
    credentials
}