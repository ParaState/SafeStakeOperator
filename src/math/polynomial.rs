use num_traits::Zero;
use std::ops::{MulAssign, AddAssign, Index};
use num_bigint::BigInt;
use blst::{blst_p1, blst_scalar, blst_p1_affine};
use bls::{PUBLIC_KEY_BYTES_LEN};

pub const BLST_SCALAR_LEN: usize = 32;

/// A simple polynomial implementation by referring to: polynomial-ring (https://lib.rs/crates/polynomial-ring)
/// Their implementation requires trait 'Sized' for the coefficient type, which is not good for BigInt.
pub struct Polynomial<T: Zero> {
    coeffs: Vec<T>
}

impl <T: Zero> Polynomial<T> {
    pub fn new(coeffs: Vec<T>) -> Self {
        Self {
            coeffs
        }
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
        where T: Zero + Clone + for<'x> AddAssign<&'x T> + MulAssign<&'a T> 
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

pub struct CommittedPoly {
    commitments: Vec<blst_p1>,
}

impl CommittedPoly {
    pub fn eval(&self, x: blst_scalar) -> blst_p1 {
        blst_p1::default()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut ser_cms : Vec<u8> = (self.commitments.len() as u32).to_be_bytes().into();
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
        let (size_bytes, bytes) = bytes.split_at(std::mem::size_of::<u32>());
        let size = u32::from_be_bytes(size_bytes.try_into().unwrap());
        let mut commitments = Vec::with_capacity(size as usize);
        for i in 0..size {
            let (ser_cm, bytes) = bytes.split_at(PUBLIC_KEY_BYTES_LEN);
            let mut cm = blst_p1::default();
            unsafe {
                let mut cm_affine = blst_p1_affine::default();
                blst::blst_p1_uncompress(&mut cm_affine, ser_cm.as_ptr());
                blst::blst_p1_from_affine(&mut cm, &cm_affine);
            }
            commitments.push(cm);
        }
        Self {
            commitments,
        }
    }
}

pub trait Commitable<T, G> {
    fn commit(&self, g: G) -> T;
}

impl Commitable<CommittedPoly, blst_p1> for Polynomial<BigInt> {
    fn commit(&self, g: blst_p1) -> CommittedPoly {
        let mut commitments = Vec::with_capacity(self.len());
        for i in 0..commitments.len() {
            let coeff = &self[i];
            let (_, mut coeff_bytes) = coeff.to_bytes_le();
            if coeff_bytes.len() < BLST_SCALAR_LEN {
                (0..BLST_SCALAR_LEN-coeff_bytes.len()).for_each(|_| coeff_bytes.push(0));
            }
            let mut cm = blst_p1::default();
            unsafe {
                blst::blst_p1_mult(&mut cm, &g, coeff_bytes.as_ptr(), 255);
            }
            commitments.push(cm);
        }
        CommittedPoly {
            commitments,
        }
    }
}