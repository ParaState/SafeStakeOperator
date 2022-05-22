use bls::{Signature, PublicKey, SecretKey, Keypair, SECRET_KEY_BYTES_LEN};
use types::{Hash256}; 
use crate::utils::error::{DvfError};
use crate::crypto::define::{MODULUS};
use num_bigint::ToBigInt;
use crate::math::polynomial::Polynomial;
use num_bigint::{BigInt, Sign};
use crate::math::bigint_ext::Ring;
use crate::utils::rand_utils::RandUtilsRng;
use crate::utils::rand_utils::Sample;
use std::collections::HashSet;


pub trait TThresholdSignature: Sized + Clone {
    fn infinity(threshold: usize) -> Self;

    fn threshold(&self) -> usize;

    fn unsafe_aggregate(&self, sigs: &[&Signature], ids: &[u64]) -> Signature;

    fn threshold_aggregate(&self, sigs: &[&Signature], pks: &[&PublicKey], msg: Hash256) -> Result<Signature, DvfError>;
}

pub struct GenericThresholdSignature<ThresholdSig> {
    point: ThresholdSig
}

impl<ThresholdSig> GenericThresholdSignature<ThresholdSig> 
where
    ThresholdSig: TThresholdSignature
{
    pub fn new(threshold: usize) -> Self {
        Self::infinity(threshold)
    }

    pub fn infinity(threshold: usize) -> Self {
        Self {
            point: ThresholdSig::infinity(threshold) 
        }
    }

    pub fn threshold(&self) -> usize {
        self.point.threshold()
    }

    pub fn key_gen(&mut self, n: usize) -> (Keypair, Vec<Keypair>, Vec<u64>) {
        let kp = Keypair::random();
        let (kps, ids) = self.key_split(&kp.sk, n);
        (kp, kps, ids)
    }

    pub fn key_split(&mut self, sk: &SecretKey, n: usize) -> (Vec<Keypair>, Vec<u64>) {
        let mut rng = RandUtilsRng::new();

        let mut coeffs: Vec<BigInt> = rng.sample_vec(self.threshold(), &MODULUS);
        coeffs[0] = BigInt::from_bytes_be(Sign::Plus, &sk.serialize().as_bytes()); 
        let poly = Polynomial::new(coeffs);

        let mut kps: Vec<Keypair> = Vec::new();
        let mut ids: Vec<u64> = Vec::new();
        for i in 0..n {
            let (_, mut sk_share) = poly.eval(&(i+1).to_bigint().unwrap()).reduce(&MODULUS).to_bytes_be();
            if sk_share.len() < SECRET_KEY_BYTES_LEN {
                (0..SECRET_KEY_BYTES_LEN-sk_share.len()).for_each(|_| sk_share.insert(0, 0));
            }
            let sk_share = SecretKey::deserialize(&sk_share[..]).unwrap();
            kps.push(Keypair::from_components(sk_share.public_key(), sk_share));
            ids.push((i + 1) as u64);
        }
        (kps, ids)
    }

    /// Split the key in a deterministic way.  
    ///
    /// **NEVER** use this in production! 
    pub fn deterministic_key_split(&mut self, sk: &SecretKey, n: usize) -> (Vec<Keypair>, Vec<u64>) {
        let seed: [u8; 32] = [0; 32];
        let mut rng = RandUtilsRng::from_seed(&seed);

        let mut coeffs: Vec<BigInt> = rng.sample_vec(self.threshold(), &MODULUS);
        coeffs[0] = BigInt::from_bytes_be(Sign::Plus, &sk.serialize().as_bytes()); 
        let poly = Polynomial::new(coeffs);

        let mut kps: Vec<Keypair> = Vec::new();
        let mut ids: Vec<u64> = Vec::new();
        for i in 0..n {
            let (_, mut sk_share) = poly.eval(&(i+1).to_bigint().unwrap()).reduce(&MODULUS).to_bytes_be();
            if sk_share.len() < SECRET_KEY_BYTES_LEN {
                (0..SECRET_KEY_BYTES_LEN-sk_share.len()).for_each(|_| sk_share.insert(0, 0));
            }
            let sk_share = SecretKey::deserialize(&sk_share[..]).unwrap();
            kps.push(Keypair::from_components(sk_share.public_key(), sk_share));
            ids.push((i + 1) as u64);
        }
        (kps, ids)
    }

    pub fn threshold_aggregate(&self, sigs: &[&Signature], pks: &[&PublicKey], ids: &[u64], msg: Hash256) -> Result<Signature, DvfError> {
        if sigs.len() != pks.len() {
            return Err(DvfError::DifferentLength{x: sigs.len(), y: pks.len()}); 
        }
        if sigs.len() != ids.len() {
            return Err(DvfError::DifferentLength{x: sigs.len(), y: ids.len()}); 
        }
        if sigs.len() < self.threshold() {
            return Err(DvfError::InsufficientSignatures{got: sigs.len(), expected: self.threshold()}); 
        }

        let mut pks_valid: Vec<&PublicKey> = Vec::new();
        let mut sigs_valid: Vec<&Signature> = Vec::new();
        let mut ids_valid: Vec<u64> = Vec::new();
        let mut valid_set: HashSet<u64> = HashSet::new();

        let total = sigs.len();
        for i in 0..total {
            if valid_set.contains(&ids[i]) {
                continue;
            }
            let status = sigs[i].verify(pks[i], msg);
            if status {
                pks_valid.push(pks[i]);
                sigs_valid.push(sigs[i]);
                ids_valid.push(ids[i]);
                valid_set.insert(ids[i]);
                if pks_valid.len() >= self.threshold() {
                    break
                }
            }
        }
        if pks_valid.len() < self.threshold() {
            return Err(DvfError::InsufficientSignatures{got: pks_valid.len(), expected: self.threshold()}); 
        }

        Ok(self.unsafe_aggregate(&sigs_valid, &ids_valid[..]))
    }

    pub fn unsafe_aggregate(&self, sigs: &[&Signature], ids: &[u64]) -> Signature {
        self.point.unsafe_aggregate(sigs, ids)
    }
}

