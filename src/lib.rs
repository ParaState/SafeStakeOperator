#[macro_use]
extern crate downcast_rs;
pub mod crypto;
pub mod math;
pub mod utils;
pub mod simulator;
pub mod validation;
pub mod node;

pub type DvfCommitteeIndex = u64;

/// The id of the operator in a threshold signature instance 
pub type DvfOperatorTsid = u64;

pub const DEFAULT_DVF_ROOT_DIR: &str = ".dvf";


