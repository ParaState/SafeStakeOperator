use serde::{Deserialize, Serialize};
#[derive(Serialize, Deserialize)]
pub struct DvfMessage {
  pub validator_id: u64,
  pub message: Vec<u8> 
}