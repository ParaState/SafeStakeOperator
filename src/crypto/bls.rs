use miracl_core::bls12381::bls;
use miracl_core::bls12381::ecp2::{ECP2};
use miracl_core::bls12381::pair;
use miracl_core::bls12381::big::{BIG};
use rand::{RngCore};
use crate::crypto::define::{MB};


#[derive(Debug)]
pub struct Bls {
    pub sk: [u8; MB],
    pub pk: [u8; 2*MB + 1]
}

pub struct BlsSecret {
    pub sk: [u8; MB]
}

impl Bls {
    pub fn new() -> Self {
        Self {
            sk: [0; MB],
            pk: [0; 2*MB + 1]
        }
    }

    pub fn from_sk(sk: &[u8; MB]) -> Self {
        let sc = BIG::frombytes(sk);
        let g = ECP2::generator();
        let mut w: [u8; 2*MB + 1] = [0; 2*MB + 1];
        pair::g2mul(&g, &sc).tobytes(&mut w,true);
        Self {
            sk: sk.clone(),
            pk: w
        }
    }

    pub fn from_pk(pk: &[u8; 2*MB+1]) -> Self {
        Self {
            sk: [0; MB],
            pk: pk.clone() 
        }
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
