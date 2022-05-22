use bls::{Signature, PublicKey, Hash256};
use crate::{
    crypto::generic_threshold::{TThresholdSignature},
};
use bls::{INFINITY_SIGNATURE};
use crate::utils::error::{require, DvfError};
pub use blst::min_pk as blst_core;
use blst::{blst_scalar, blst_p2, blst_p2_affine};

pub const DST: &[u8] = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
pub const RAND_BITS: usize = 64;

/// Provides the externally-facing, core BLS types.
pub mod types {
    pub use super::BlstThresholdSignature as ThresholdSignature;
}


fn u64_to_blst_scalar (v: u64) -> blst_scalar {
    let mut x = std::mem::MaybeUninit::<blst_scalar>::uninit();
    unsafe {
        blst::blst_scalar_from_uint64(x.as_mut_ptr(), vec![v, 0, 0, 0].as_ptr());
        x.assume_init()
    }
}

fn lagrange_coeffs(coeffs: &mut [blst_scalar], x: &[u64]) {
    require(coeffs.len() == x.len(), "Different length");
    let n = coeffs.len();
    for i in 0..n {
        let mut p = u64_to_blst_scalar(1);
        let xi = u64_to_blst_scalar(x[i]);
        for j in 0..n {
            if i!=j {
                let xj = u64_to_blst_scalar(x[j]); 
                let mut tmp = std::mem::MaybeUninit::<blst_scalar>::uninit();
                unsafe {
                    blst::blst_sk_sub_n_check(tmp.as_mut_ptr(), &xj, &xi);
                    blst::blst_sk_inverse(tmp.as_mut_ptr(), tmp.as_ptr());
                    blst::blst_sk_mul_n_check(tmp.as_mut_ptr(), &xj, tmp.as_ptr());
                    blst::blst_sk_mul_n_check(&mut p, &p, tmp.as_ptr());
                }
            }
        }
        coeffs[i] = p;
    }
}

pub struct BlstThresholdSignature(blst_core::AggregateSignature, usize);

impl Clone for BlstThresholdSignature {
    fn clone(&self) -> Self {
        Self(
            blst_core::AggregateSignature::from_signature(&self.0.to_signature()),
            self.1
        )
    }
}


impl TThresholdSignature for BlstThresholdSignature {
    fn infinity(threshold: usize) -> Self {
        Self ( 
            blst_core::Signature::from_bytes(&INFINITY_SIGNATURE)
                .map(|sig| blst_core::AggregateSignature::from_signature(&sig))
                .expect("should decode infinity signature"),
            threshold
        )
    }

    fn threshold(&self) -> usize {
        self.1
    }

    fn unsafe_aggregate(&self, sigs: &[&Signature], ids: &[u64]) -> Signature {
        let mut coeffs = vec![blst_scalar::default(); self.threshold()];
        lagrange_coeffs(&mut coeffs, &ids);

        let mut agg = Self::infinity(self.1);
        for i in 0..self.threshold() {
            let mut sig_in: [u8; 192] = [0; 192];
            unsafe {
                let mut d: blst_p2 = Default::default(); 
                let mut tmp: blst_p2_affine = Default::default();
                blst::blst_p2_deserialize(&mut tmp, sigs[i].serialize().as_ptr());
                blst::blst_p2_from_affine(&mut d, &tmp);
                blst::blst_p2_mult(&mut d, &d, coeffs[i].b.as_ptr(), 255);

                blst::blst_p2_serialize(sig_in.as_mut_ptr(), &d);
            }
            let sig = blst_core::Signature::deserialize(&sig_in);
            agg.0.add_signature(&sig.unwrap(), false);
        }
        Signature::deserialize(&agg.0.to_signature().to_bytes()).unwrap()
    }

    fn threshold_aggregate(&self, sigs: &[&Signature], pks: &[&PublicKey], msg: Hash256) -> Result<Signature, DvfError> {
        Ok(self.unsafe_aggregate(sigs, &[0, 2]))
    }
}
