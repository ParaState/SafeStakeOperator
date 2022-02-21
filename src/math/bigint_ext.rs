use num_bigint::{BigInt, Sign};
use crate::crypto::define::{BigNum, MODULUS};

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

pub trait ToBigNum {
    fn to_big_num(&self) -> BigNum;
}

impl ToBigNum for BigInt {
    fn to_big_num(&self) -> BigNum {
        let reduced = self.reduce(&MODULUS);
        BigNum::fromstring(reduced.to_str_radix(16)) 
    }
}
