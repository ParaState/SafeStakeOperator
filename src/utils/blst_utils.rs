use blst::{blst_scalar, blst_p1, blst_p1_affine, blst_p2, blst_p2_affine};
use num_bigint::BigInt;
use bytes::Bytes;
use bls::{PUBLIC_KEY_BYTES_LEN};
use rand::RngCore;
use std::ptr;

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

pub fn bytes_to_blst_p1_affine(b: Bytes) -> blst_p1_affine {
    let mut r: blst_p1_affine = Default::default();
    unsafe {
        blst::blst_p1_uncompress(&mut r, b.as_ptr());
    };
    r
}

pub fn blst_p1_to_bytes(x: &blst_p1) -> Bytes {
    let mut x_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
    unsafe {
        blst::blst_p1_compress(x_bytes.as_mut_ptr(), x);
    }
    Bytes::copy_from_slice(&x_bytes)
}

pub fn bytes_to_blst_p1(b: Bytes) -> blst_p1 {
    let mut x = blst_p1::default();
    unsafe {
        let mut r: blst_p1_affine = Default::default();
        blst::blst_p1_uncompress(&mut r, b.as_ptr());
        blst::blst_p1_from_affine(&mut x, &r);
    };
    x
}

pub fn blst_ecdh_shared_secret(other_pk: &blst_p1, self_sk: &blst_scalar) -> blst_p1 {
    blst_p1_mult(other_pk, self_sk)
}

pub fn blst_sk_to_pk_with_generator(generator: &blst_p1, sk: &blst_scalar) -> blst_p1 {
    blst_p1_mult(generator, sk)
}

pub fn blst_sk_to_pk(sk: &blst_scalar) -> blst_p1 {
    let mut pk = blst_p1::default();
    unsafe {
        blst::blst_sk_to_pk_in_g1(&mut pk, sk)
    }
    pk
}

pub fn random_blst_scalar() -> blst_scalar {
    let mut rng = rand::thread_rng();
    let mut ikm = [0; 32];
    rng.fill_bytes(&mut ikm);
    let mut r = blst_scalar::default();
    unsafe {
        blst::blst_keygen(&mut r, ikm.as_slice().as_ptr(), 32, ptr::null(), 0);
    }
    r
}