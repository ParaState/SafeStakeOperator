use num_traits::Zero;
use std::ops::{MulAssign, AddAssign};

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
