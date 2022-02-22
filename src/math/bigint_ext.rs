use num_bigint::{BigInt, Sign};
use miracl_core::bls12381::big::{BIG};
use crate::crypto::define::{MODULUS};

pub trait Ring {
    fn reduce(&self, m: &BigInt) -> Self;
}

impl Ring for BigInt {
    fn reduce(&self, m: & BigInt) -> BigInt {
        let mut result = self.clone();
        result %= m;
        if result.sign() == Sign::Minus {
            result += m;
        }
        result
    }
}

#[allow(non_snake_case)]
pub trait ToBIG {
    fn to_BIG(&self) -> BIG;
}

impl ToBIG for BigInt {
    fn to_BIG(&self) -> BIG {
        let reduced = self.reduce(&MODULUS);
        BIG::fromstring(reduced.to_str_radix(16)) 
    }
}
