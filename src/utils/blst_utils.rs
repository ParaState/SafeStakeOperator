use blst::{blst_scalar, blst_p1, blst_p2, blst_p2_affine};
use num_bigint::BigInt;

pub fn u64_to_blst_scalar (v: u64) -> blst_scalar {
    let mut x = std::mem::MaybeUninit::<blst_scalar>::uninit();
    unsafe {
        blst::blst_scalar_from_uint64(x.as_mut_ptr(), vec![v, 0, 0, 0].as_ptr());
        x.assume_init()
    }
}

pub fn bigint_to_blst_scalar (v: BigInt) -> blst_scalar {
    let (_, v_bytes) = v.to_bytes_be();
    let mut x = blst_scalar::default();
    unsafe {
        blst::blst_scalar_from_be_bytes(&mut x, v_bytes.as_ptr(), v_bytes.len());
    }
    x
}

pub fn fixed_p1_generator() -> blst_p1 {
    let mut g = blst_p1::default();
    unsafe {
        let x = blst::blst_p1_generator();
        g = *x;
    }
    g
}

pub fn blst_p1_mult(a: &blst_p1, b: &blst_scalar) -> blst_p1 {
    let mut y = blst_p1::default();
    unsafe {
        blst::blst_p1_mult(&mut y, a, b.b.as_ptr(), 255);
    }
    y
}