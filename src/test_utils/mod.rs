use crate::crypto::{ThresholdSignature};
// use validator_dir::{ValidatorDir, BuilderError};
// use std::path::{Path, PathBuf};
// use validator_dir::insecure_keys::{INSECURE_PASSWORD,};
use types::test_utils::generate_deterministic_keypair;
// use std::iter::zip;
use std::collections::HashMap;
use bls::Keypair;

pub struct ThresholdKeyPack {
    pub kp: Keypair,
    pub kps: HashMap<u64, Keypair>,
    pub threshold: u64,
}

pub fn generate_deterministic_threshold_keypairs(validator_id: u64, node_ids: &[u64], threshold: usize) -> ThresholdKeyPack {
    let kp = generate_deterministic_keypair(validator_id as usize);

    let mut m_threshold = ThresholdSignature::new(threshold);  
    let kps = m_threshold.deterministic_key_split(&kp.sk, node_ids).unwrap();

    ThresholdKeyPack {
        kp,
        kps,
        threshold: threshold as u64,
    }
}
