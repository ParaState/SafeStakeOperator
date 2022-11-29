use reqwest::Client;
use url::Url;
use serde::{Serialize};
use tokio::sync::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use crate::node::new_contract::OperatorPublicKeys;
use log::error;
use std::collections::HashMap;

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