use bls::{Signature, PublicKey, SecretKey, Keypair};
use types::{Hash256}; 
use crate::utils::error::{DvfError};
use crate::crypto::define::{MODULUS};
use num_bigint::ToBigInt;
use crate::math::polynomial::Polynomial;
use num_bigint::{BigInt, Sign};
use crate::math::bigint_ext::Ring;
use crate::utils::rand_utils::RandUtilsRng;
use crate::utils::rand_utils::Sample;


pub trait TThresholdSignature: Sized + Clone {
    fn infinity(threshold: usize) -> Self;

    fn threshold(&self) -> usize;

    fn unsafe_aggregate(&self, sigs: &[&Signature], ids: &[u32]) -> Signature;

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

    pub fn key_gen(&mut self, n: usize) -> (Keypair, Vec<Keypair>, Vec<u32>) {
        let kp = Keypair::random();
        let (kps, ids) = self.key_split(&kp.sk, n);
        (kp, kps, ids)
    }

    pub fn key_split(&mut self, sk: &SecretKey, n: usize) -> (Vec<Keypair>, Vec<u32>) {
        let mut rng = RandUtilsRng::new();

        let mut coeffs: Vec<BigInt> = rng.sample_vec(self.threshold(), &MODULUS);
        coeffs[0] = BigInt::from_bytes_be(Sign::Plus, &sk.serialize().as_bytes()); 
        let poly = Polynomial::new(coeffs);

        let mut kps: Vec<Keypair> = Vec::new();
        let mut ids: Vec<u32> = Vec::new();
        for i in 0..n {
            let (_, sk_share) = poly.eval(&(i+1).to_bigint().unwrap()).reduce(&MODULUS).to_bytes_be();
            let sk_share = SecretKey::deserialize(&sk_share[..]).unwrap();
            kps.push(Keypair::from_components(sk_share.public_key(), sk_share));
            ids.push((i + 1) as u32);
        }
        (kps, ids)
    }

    pub fn threshold_aggregate(&self, sigs: &[&Signature], pks: &[&PublicKey], ids: &[u32], msg: Hash256) -> Result<Signature, DvfError> {
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
        let mut ids_valid: Vec<u32> = Vec::new();

        let total = sigs.len();
        for i in 0..total {
            let status = sigs[i].verify(pks[i], msg);
            if status {
                pks_valid.push(pks[i]);
                sigs_valid.push(sigs[i]);
                ids_valid.push(ids[i]);
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

    pub fn unsafe_aggregate(&self, sigs: &[&Signature], ids: &[u32]) -> Signature {
        self.point.unsafe_aggregate(sigs, ids)
    }
}

