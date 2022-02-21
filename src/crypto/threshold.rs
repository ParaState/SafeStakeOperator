use num_bigint::{BigInt, Sign, ToBigInt};
use crate::crypto::bls::Bls;
use crate::crypto::define::{MODULUS, BigNum, MB};
use crate::utils::rand_utils::{RandUtilsRng, Sample};
use crate::math::polynomial::Polynomial;
use crate::math::bigint_ext::{ToBigNum};


pub struct ThresholdBls {
    pub master_bls: Bls,
    pub t: usize,
    pub n: usize,
}

impl ThresholdBls {
    pub fn new(t: usize, n: usize) -> Self {
        ThresholdBls {
            master_bls: Bls::new(),
            t: t,
            n: n
        }
    }

    pub fn create(&mut self, bls_shares: &mut [[u8; MB]]) -> isize {
        let mut rng = RandUtilsRng::new();

        self.master_bls.keygen();
        let mut coeffs: Vec<BigInt> = rng.sample_vec(self.t, &MODULUS);
        coeffs[0] = BigInt::from_bytes_be(Sign::Plus, &self.master_bls.sk[..]); 
        let poly = Polynomial::new(coeffs);
        for i in 0..self.n {
            poly.eval(&i.to_bigint().unwrap()).to_big_num().tobytes(&mut bls_shares[i]);
        }
        return 0;
    }
}
