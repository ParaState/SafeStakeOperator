use blst::{blst_scalar, blst_p1, blst_p1_affine, blst_p2, blst_p2_affine};
use num_bigint::BigInt;
use bytes::{Bytes, BytesMut};
use bls::{PUBLIC_KEY_BYTES_LEN};
use rand::RngCore;
use std::ptr;
use blst::min_pk::{SecretKey, PublicKey};

/// !NOTE: in the `blst` library,
///  `blst_scalar` stores data (the internal field `b`) in little endian,
/// but SecretKey serializes data (the `to_bytes` API) in big endian!
/// In our following utils, to unify things, the input or output `Bytes` always serialize 
/// integers (both `blst_scalar` and `SecretKey`) in LITTLE endian.

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

pub fn another_p1_generator() -> blst_p1 {
    let mut h = std::mem::MaybeUninit::<blst_p1>::uninit();
    let msg = "dvf another generator";

    // TODO: remove this `unsafe` code-block once we get a safe option from `blst`.
    //
    // https://github.com/sigp/lighthouse/issues/1720
    let h = unsafe {
        blst::blst_hash_to_g1(h.as_mut_ptr(), msg.as_ptr(), msg.len(), ptr::null(), 0, ptr::null(), 0);
        h.assume_init()
    };
    h
}

pub fn blst_scalar_mult(a: &blst_scalar, b: &blst_scalar) -> blst_scalar {
    let mut c = blst_scalar::default();
    unsafe {
        blst::blst_sk_mul_n_check(&mut c, a, b);
    }
    c
}

pub fn blst_scalar_sub(a: &blst_scalar, b: &blst_scalar) -> blst_scalar {
    let mut c = blst_scalar::default();
    unsafe {
        blst::blst_sk_sub_n_check(&mut c, a, b);
    }
    c
}

pub fn blst_scalar_add(a: &blst_scalar, b: &blst_scalar) -> blst_scalar {
    let mut c = blst_scalar::default();
    unsafe {
        blst::blst_sk_add_n_check(&mut c, a, b);
    }
    c
}

pub fn blst_p1_mult(a: &blst_p1, b: &blst_scalar) -> blst_p1 {
    let mut y = blst_p1::default();
    unsafe {
        blst::blst_p1_mult(&mut y, a, b.b.as_ptr(), 255);
    }
    y
}

pub fn blst_p1_add(a: &blst_p1, b: &blst_p1) -> blst_p1 {
    let mut y = blst_p1::default();
    unsafe {
        blst::blst_p1_add(&mut y, a, b);
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

pub fn blst_p1_affine_to_bytes(x: &blst_p1_affine) -> Bytes {
    let mut x_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
    unsafe {
        blst::blst_p1_affine_compress(x_bytes.as_mut_ptr(), x);
    };
    Bytes::copy_from_slice(&x_bytes)
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

pub fn blst_p1_affines_add(points: &[blst_p1_affine]) -> blst_p1 {
    let mut res = blst_p1::default();
    unsafe {
        let pks = points.iter().map(|x| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
        blst::blst_p1s_add(&mut res, pks.as_ptr(), pks.len());
    };
    res
}

pub fn blst_p1s_add(points: &[blst_p1]) -> blst_p1 {
    let mut res = blst_p1::default();
    let mut affine_points = Vec::<blst_p1_affine>::with_capacity(points.len());
    unsafe {
        let pks = points.iter().map(|x| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1>>();
        blst::blst_p1s_to_affine(affine_points.as_mut_ptr(), pks.as_ptr(), pks.len());
        let pks = affine_points.iter().map(|x| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
        blst::blst_p1s_add(&mut res, pks.as_ptr(), pks.len());
    };
    res
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

// pub fn blst_scalar_to_p1(sk: &blst_scalar) -> blst_p1 {
//     let mut pk = blst_p1::default();
//     unsafe {
//         blst::blst_sk_to_pk_in_g1(&mut pk, sk)
//     }
//     pk
// }

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

pub fn blst_scalar_to_blst_sk(v: &blst_scalar) -> SecretKey {
    let mut bytes = Vec::from(v.b.as_slice());
    bytes.reverse();
    SecretKey::from_bytes(&bytes).unwrap()
}

pub fn blst_p1_to_pk(p: &blst_p1) -> PublicKey {
    let mut p_bytes = [0; 96];
    unsafe {
        blst::blst_p1_serialize(p_bytes.as_mut_slice().as_mut_ptr(), p);
    }
    PublicKey::deserialize(p_bytes.as_slice()).unwrap()
}

/// Serialize a SecretKey into bytes in little endian.
pub fn blst_sk_to_bytes(sk: &SecretKey) -> Bytes {
    let mut bytes = sk.to_bytes().to_vec();
    bytes.reverse();
    bytes.into()
}

/// Deserialize bytes into a SecretKey.
/// 
/// # Arguments
/// * b - Little endian
pub fn bytes_to_blst_sk(b: Bytes) -> SecretKey {
    let mut be_bytes = b.to_vec();
    be_bytes.reverse();
    SecretKey::from_bytes(&be_bytes).unwrap()
}

pub fn bytes_to_blst_scalar(b: Bytes) -> blst_scalar {
    let mut x = blst_scalar::default();
    unsafe {
        blst::blst_scalar_from_be_bytes(&mut x, b.as_ptr(), b.len());
    }
    x
}

pub fn blst_scalar_to_bytes(x: &blst_scalar) -> Bytes {
    Bytes::copy_from_slice(&x.b)
}

pub fn hash_points_to_blst_scalar(vec: &[blst_p1]) -> blst_scalar {
    let material: Vec<Bytes> = vec.iter().map(blst_p1_to_bytes).collect();
    let mut bytes = BytesMut::default();
    bytes.extend(material);
    bytes_to_blst_scalar(bytes.freeze())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endian() {
        let x = random_blst_scalar();
        let a = blst_scalar_to_bytes(&x);
        let y = bytes_to_blst_sk(a.clone());
        let y1 = blst_scalar_to_blst_sk(&x);
        let b = blst_sk_to_bytes(&y);

        println!("x: {:?}", x);
        println!("y: {:?}", y);
        println!("y1: {:?}", y1);
        println!("a: {:?}", a);
        println!("b: {:?}", b);

        let x = u64_to_blst_scalar(5);
        let a = blst_scalar_to_bytes(&x);
        let mut b: u32 = 0;
        unsafe {
            blst::blst_uint32_from_scalar(&mut b, &x);
        }
        println!("x: {:?}", x);
        println!("a: {:?}", a);
        println!("b: {:?}", b);
    }
}