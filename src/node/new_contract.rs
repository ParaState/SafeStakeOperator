use serde::{Serialize};
use serde::de::DeserializeOwned;
use web3::{
    types::{Address}
};
use serde_derive::{Deserialize as DeriveDeserialize, Serialize as DeriveSerialize};
use std::path::{Path};
use std::fs::File;
use crate::node::db::Database;
const CONTRACT_CONFIG_FILE: &str = "contract_config/configs.yml";
const CONTRACT_RECORD_FILE: &str = "contract_record.yml";
const CONTRACT_DATABASE_FILE: &str = "contract_database.db";
#[derive(Clone, Debug)]
pub struct Operator {
    pub id: u32,
    pub name: String,
    pub address: Address,
    pub public_key: [u8;33] // ecc256 public key
}

#[derive(Clone, Debug)]
pub struct Validator {
    pub id: u64,
    pub owner_address: Address,
    pub public_key: [u8;48],    // bls public key
    pub releated_operators: Vec<u32>
}

pub trait FromFile<T: DeserializeOwned> {
    fn from_file<P: AsRef<Path>>(path: P) -> Result<T, String> {
        let file = File::options().read(true).open(path).map_err(|e| { format!("can't open file {:?}", e) } )?;
        serde_yaml::from_reader(file).map_err(|e| { format!("can't deserialize file {:?}", e) })
    }
}

pub trait ToFile<> {
    fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), String> where Self: Serialize{
        let file = File::options().write(true).create(true).truncate(true).open(path).map_err(|e| { format!("can't open file {:?}", e) } )?;
        serde_yaml::to_writer(file, self).map_err(|e| { format!("can't serialize to file {:?}", e) })
    }
}

#[derive(Debug, DeriveSerialize, DeriveDeserialize)]
pub struct ContractConfig {
    pub validator_registration_topic: String, 
    pub validatro_removal_topic: String,
    pub operator_registration_topic: String, 
    pub operator_removal_topic: String,
    pub transport_url: String,
    pub safestake_network_address: String,
    pub safestake_registry_address: String,
    pub safestake_network_abi_path: String,
    pub safestake_registry_abi_path: String
}
impl FromFile<ContractConfig> for ContractConfig {}
impl ToFile for ContractConfig {}

#[derive(Clone, DeriveSerialize, DeriveDeserialize)]
pub struct ContractRecord {
    pub block_num: u64
}

impl FromFile<ContractRecord> for ContractRecord {}
impl ToFile for ContractRecord {}


pub struct Contract {
    pub config: ContractConfig,
    pub record: ContractRecord,
    pub db: Database
}


impl Contract {
    pub fn new<P: AsRef<Path>>(base_dir: P) -> Result<Self, String> {
        let config = ContractConfig::from_file(CONTRACT_CONFIG_FILE)?;
        let record = ContractRecord::from_file(base_dir.as_ref().join(CONTRACT_RECORD_FILE))?;
        let db = Database::new(base_dir.as_ref().join(CONTRACT_DATABASE_FILE)).map_err(|e| format!("can't create contract database {:?}", e))?;
        Ok(Self { config, record, db })
    }

}
