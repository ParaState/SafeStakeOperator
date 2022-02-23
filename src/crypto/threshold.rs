use num_bigint::{BigInt, Sign, ToBigInt};
use miracl_core::bls12381::big::BIG;
use miracl_core::bls12381::bls::{BLS_OK};
use miracl_core::bls12381::pair;
use crate::crypto::bls::Bls;
use crate::crypto::define::{CURVE_ORDER, MODULUS, MB, G1};
use crate::utils::rand_utils::{RandUtilsRng, Sample};
use crate::utils::error::{require};
use crate::math::polynomial::Polynomial;
use crate::math::bigint_ext::{ToBIG};


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

    pub fn generate(&mut self, sk_shares: &mut [[u8; MB]], ids: &mut [isize]) -> isize {
        let mut rng = RandUtilsRng::new();

        self.master_bls.keygen();
        let mut coeffs: Vec<BigInt> = rng.sample_vec(self.t, &MODULUS);
        coeffs[0] = BigInt::from_bytes_be(Sign::Plus, &self.master_bls.sk[..]); 
        let poly = Polynomial::new(coeffs);
        for i in 0..self.n {
            poly.eval(&(i+1).to_bigint().unwrap()).to_BIG().tobytes(&mut sk_shares[i]);
            ids[i] = (i + 1) as isize;
        }
        BLS_OK 
    }

    pub fn aggregate(&self, agg_sig: &mut [u8], pk: &[[u8; 2*MB + 1]], sig: &[[u8; MB + 1]], id: &[isize], m: &[u8]) {
        let mut pk_valid: Vec<[u8; 2*MB+1]> = Vec::new();
        let mut sig_valid: Vec<[u8; MB+1]> = Vec::new();
        let mut id_valid: Vec<isize> = Vec::new();

        let total = id.len();
        for i in 0..total {
            let status = Bls::from_pk(&pk[i]).verify(&sig[i], m);
            if status == BLS_OK {
                pk_valid.push(pk[i].clone());
                sig_valid.push(sig[i].clone());
                id_valid.push(id[i]);
                if pk_valid.len() >= self.t {
                    break
                }
            }
        }
        require(pk_valid.len() >= self.t, "Insufficient valid signatures");
        let mut coeffs = vec![BIG::new_int(0); self.t];
        Self::lagrange_coeffs(&mut coeffs, &id_valid);

        let mut agg = G1::new();
        agg.inf();
        for i in 0..self.t {
            let d = G1::frombytes(&sig[i]);
            let d = pair::g1mul(&d, &coeffs[i]); 
            agg.add(&d);
        }
        agg.tobytes(agg_sig, true);
    }

    fn lagrange_coeffs(coeffs: &mut [BIG], x: &[isize]) {
        require(coeffs.len() == x.len(), "Different length");
        let n = coeffs.len();
        for i in 0..n {
            let mut p = BIG::new_int(1);
            let xi = BIG::modneg(&BIG::new_int(x[i]), &CURVE_ORDER);
            for j in 0..n {
                if i!=j {
                    let xj = BIG::new_int(x[j]); 
                    let mut tmp = BIG::modadd(&xj, &xi, &CURVE_ORDER); 
                    tmp.invmodp(&CURVE_ORDER); 
                    tmp = BIG::modmul(&xj, &tmp, &CURVE_ORDER);
                    p = BIG::modmul(&p, &tmp, &CURVE_ORDER);
                }
            }
            coeffs[i] = p;
        }
    }

    pub fn recover_sk(&self, sk: &mut [u8; MB], sk_shares: &[[u8; MB]], id: &[isize]) {
        require(sk_shares.len() == id.len(), "Different length");
        require(id.len() >= self.t, "Insufficient shares");

        let mut coeffs = vec![BIG::new_int(0); self.t];
        Self::lagrange_coeffs(&mut coeffs, &id[0..self.t]);

        let mut s = BIG::new_int(0); 
        for i in 0..self.t {
            let share = BIG::frombytes(&sk_shares[i]);
            let share = BIG::modmul(&share, &coeffs[i], &CURVE_ORDER);
            s = BIG::modadd(&s, &share, &CURVE_ORDER);
        }
        s.tobytes(sk);
    }
}
