use  miracl_core::bls12381::bls;
use rand::{RngCore};
use crate::crypto::define::{MB};


#[derive(Debug)]
pub struct Bls {
    pub sk: [u8; MB],
    pub pk: [u8; 2*MB + 1]
}

impl Bls {
    pub fn new() -> Bls {
        Bls {
            sk: [0; MB],
            pk: [0; 2*MB + 1]
        }
    }

    pub fn set_sk(&mut self, sk: &[u8; MB]) {
        self.sk = sk.clone();
    }

    pub fn set_pk(&mut self, pk: &[u8; 2*MB+1]) {
        self.pk = pk.clone();
    }
    
    pub fn keygen(&mut self) -> isize {
        let mut salt: [u8; 64] = [0; 64];
        rand::thread_rng().fill_bytes(&mut salt); 
        bls::key_pair_generate(&salt, &mut self.sk[..], &mut self.pk[..]) 
    }

    pub fn sign(&self, sig: &mut [u8], m: &[u8]) -> isize {
        bls::core_sign(sig, m, &self.sk[..])
    }

    pub fn verify(&self, sig: &[u8], m: &[u8]) -> isize {
        bls::core_verify(sig, m, &self.pk[..])
    }
}
