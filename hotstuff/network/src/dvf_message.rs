use serde::{Deserialize, Serialize};
use std::fmt::Debug;

#[derive(Debug, Serialize, Deserialize)]
pub struct DvfMessage {
  pub validator_id: u64,
  pub message: Vec<u8> 
}
