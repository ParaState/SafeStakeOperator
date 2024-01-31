use bls::PUBLIC_KEY_BYTES_LEN;
use blst::{blst_p1, blst_p1_affine, blst_scalar};
use num_bigint::BigInt;
use num_traits::Zero;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::ops::{AddAssign, Index, MulAssign};

pub const BLST_SCALAR_LEN: usize = 32;

/// A simple polynomial implementation by referring to: polynomial-ring (https://lib.rs/crates/polynomial-ring)
/// Their implementation requires trait 'Sized' for the coefficient type, which is not good for BigInt.
pub struct Polynomial<T: Zero> {
    coeffs: Vec<T>,
}

impl<T: Zero> Polynomial<T> {
    pub fn new(coeffs: Vec<T>) -> Self {
        Self { coeffs }
    }

    pub fn len(&self) -> usize {
        self.coeffs.len()
    }

    pub fn deg(&self) -> Option<usize> {
        if self.coeffs.is_empty() {
            None
        } else {
            Some(self.len() - 1)
        }
    }

    pub fn lc(&self) -> Option<&T> {
        self.deg().map(|d| &self.coeffs[d])
    }

    pub fn eval<'a>(&self, x: &'a T) -> T
    where
        T: Zero + Clone + for<'x> AddAssign<&'x T> + MulAssign<&'a T>,
    {
        if self.coeffs.is_empty() {
            return T::zero();
        }
        let mut sum = self.lc().unwrap().clone();
        for i in (0..self.len() - 1).rev() {
            sum *= x;
            sum += &self.coeffs[i];
        }
        sum
    }
}

impl<T: Zero> Index<usize> for Polynomial<T> {
    type Output = T;

    fn index(&self, i: usize) -> &Self::Output {
        &self.coeffs[i]
    }
}

#[derive(PartialEq, Debug, Clone)]
pub struct CommittedPoly {
    pub commitments: Vec<blst_p1>,
}

impl CommittedPoly {
    pub fn eval(&self, x: &blst_scalar) -> blst_p1 {
        let mut y = self.commitments[0].clone();
        let mut x_power = x.clone();
        for i in 1..self.commitments.len() {
            unsafe {
                let mut term = blst_p1::default();
                blst::blst_p1_mult(&mut term, &self.commitments[i], x_power.b.as_ptr(), 255);
                blst::blst_p1_add(&mut y, &y, &term);
                blst::blst_sk_mul_n_check(&mut x_power, &x_power, x);
            }
        }
        y
    }

    pub fn bytes_len(&self) -> usize {
        std::mem::size_of::<u32>() + PUBLIC_KEY_BYTES_LEN * self.commitments.len()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ser_cms: Vec<u8> = (self.commitments.len() as u32).to_be_bytes().into();
        for cm in self.commitments.iter() {
            let mut ser_cm: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
            unsafe {
                blst::blst_p1_compress(ser_cm.as_mut_ptr(), cm);
            }
            ser_cms.append(&mut Vec::from(ser_cm));
        }
        ser_cms
    }

    pub fn from_bytes(bytes: &[u8]) -> Self {
        let size_bytes = &bytes[0..std::mem::size_of::<u32>()];
        let mut index = std::mem::size_of::<u32>();
        let size = u32::from_be_bytes(size_bytes.try_into().unwrap());
        let mut commitments = Vec::with_capacity(size as usize);
        for _i in 0..size {
            let ser_cm = &bytes[index..index + PUBLIC_KEY_BYTES_LEN];
            let mut cm = blst_p1::default();
            unsafe {
                let mut cm_affine = blst_p1_affine::default();
                blst::blst_p1_uncompress(&mut cm_affine, ser_cm.as_ptr());
                blst::blst_p1_from_affine(&mut cm, &cm_affine);
            }
            commitments.push(cm);
            index += PUBLIC_KEY_BYTES_LEN;
        }
        Self { commitments }
    }
}

impl Serialize for CommittedPoly {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for CommittedPoly {
    fn deserialize<D>(deserializer: D) -> Result<CommittedPoly, D::Error>
    where
        D: Deserializer<'de>,
    {
        Ok(CommittedPoly::from_bytes(
            Vec::<u8>::deserialize(deserializer)?.as_slice(),
        ))
    }
}

pub trait Commitable<T, G> {
    fn commit(&self, g: &G) -> T;
}

impl Commitable<CommittedPoly, blst_p1> for Polynomial<BigInt> {
    fn commit(&self, g: &blst_p1) -> CommittedPoly {
        let mut commitments = Vec::with_capacity(self.len());
        for i in 0..self.len() {
            let coeff = &self[i];
            let (_, mut coeff_bytes) = coeff.to_bytes_le();
            if coeff_bytes.len() < BLST_SCALAR_LEN {
                (0..BLST_SCALAR_LEN - coeff_bytes.len()).for_each(|_| coeff_bytes.push(0));
            }
            let mut cm = blst_p1::default();
            unsafe {
                blst::blst_p1_mult(&mut cm, g, coeff_bytes.as_ptr(), 255);
            }
            commitments.push(cm);
        }
        CommittedPoly { commitments }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::blst_utils::{
        bigint_to_blst_scalar, blst_p1_mult, blst_scalar_to_bigint, fixed_p1_generator,
        random_blst_scalar, u64_to_blst_scalar,
    };

    #[test]
    fn test_commit() {
        let g = fixed_p1_generator();
        let coeffs: Vec<BigInt> = vec![3.into(), 5.into(), 4.into(), 2.into()];
        let poly = Polynomial::new(coeffs);
        let committed_poly = poly.commit(&g);

        let ser = committed_poly.to_bytes();
        let committed_poly_ = CommittedPoly::from_bytes(&ser);

        assert_eq!(
            committed_poly, committed_poly_,
            "Serialization/Deserialization error"
        );

        let x = u64_to_blst_scalar(7);
        let y = committed_poly_.eval(&x);

        let exponent = bigint_to_blst_scalar(poly.eval(&(7.into())));

        let y_ = blst_p1_mult(&g, &exponent);

        assert_eq!(y, y_, "Verification failed");
    }

    #[test]
    fn test_commit2() {
        let g = fixed_p1_generator();
        let coeffs: Vec<BigInt> = vec![
            blst_scalar_to_bigint(&random_blst_scalar()),
            blst_scalar_to_bigint(&random_blst_scalar()),
            blst_scalar_to_bigint(&random_blst_scalar()),
            blst_scalar_to_bigint(&random_blst_scalar()),
        ];
        let poly = Polynomial::new(coeffs);
        let committed_poly = poly.commit(&g);

        let ser = committed_poly.to_bytes();
        let committed_poly_ = CommittedPoly::from_bytes(&ser);

        assert_eq!(
            committed_poly, committed_poly_,
            "Serialization/Deserialization error"
        );

        let x = random_blst_scalar();
        let y = committed_poly_.eval(&x);

        let exponent = bigint_to_blst_scalar(poly.eval(&(blst_scalar_to_bigint(&x))));

        let y_ = blst_p1_mult(&g, &exponent);

        assert_eq!(y, y_, "Verification failed");
    }
}
