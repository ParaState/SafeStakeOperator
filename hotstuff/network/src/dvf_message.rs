use serde::{Deserialize, Serialize};
use std::fmt::Debug;

pub use dvf_version::{VERSION};

#[derive(Debug, Serialize, Deserialize)]
pub struct DvfMessage {
    pub version: u64,
    pub validator_id: u64,
    pub message: Vec<u8> 
}

// #[derive(Debug, Serialize, Deserialize, Clone)]
// pub enum DvfMessage {
//   VaMsg {version: u64, va_id: u64, msg: Vec<u8>},
//   AckMsg {},
// }
