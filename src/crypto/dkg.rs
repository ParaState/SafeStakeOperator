use crate::crypto::ThresholdSignature;
use crate::crypto::define::{MODULUS};
use lazy_static::lazy_static;
use std::ptr;
use bls::{SecretKey, PublicKey, Keypair, PUBLIC_KEY_BYTES_LEN};
use num_bigint::{BigInt, Sign};
use num_bigint::ToBigInt;
use crate::math::bigint_ext::Ring;
use std::sync::Arc;
use blst::blst_p1;
use crate::network::io_committee::{IOCommittee, IOChannel};
use futures::future::join_all;
use bytes::Bytes;
use crate::utils::error::DvfError;
use std::marker::PhantomData;


pub struct DKG<T, U> {
    party: u64,
    io: T,
    threshold: usize,
    h: blst_p1,
    _phantom: PhantomData<U>,
}

impl<T, U> DKG<T, U> 
where 
    U: IOChannel,
    T: IOCommittee<U> {

    pub fn new(party: u64, io: T, threshold: usize) -> Self {
        let mut h = std::mem::MaybeUninit::<blst_p1>::uninit();
        let msg = "dvf another generator";
    
        // TODO: remove this `unsafe` code-block once we get a safe option from `blst`.
        //
        // https://github.com/sigp/lighthouse/issues/1720
        let h = unsafe {
            blst::blst_hash_to_g1(h.as_mut_ptr(), msg.as_ptr(), msg.len(), ptr::null(), 0, ptr::null(), 0);
            h.assume_init()
        };

        Self {
            party,
            io,
            threshold,
            h,
            _phantom: PhantomData,
        }
    }

    pub async fn run(&self) -> Result<Keypair, DvfError> {
        let mut threshold_sig = ThresholdSignature::new(self.threshold);
        let ids = self.io.ids();
        let (kp, kps) = threshold_sig.key_gen(ids)?;

        let kps_ref = &kps; // Take reference so that it can be used in async move
        let futs = ids.iter().map(|id| async move {
            self.io.channel(self.party, *id)
                .write()
                .await
                .send(Bytes::copy_from_slice(kps_ref.get(id).unwrap().sk.serialize().as_bytes())).await;
            let s = self.io.channel(self.party, *id)
                .write()
                .await
                .recv().await;
            let s = BigInt::from_bytes_be(Sign::Plus, s.as_ref());
            (*id, s)
        });
        let results = join_all(futs)
            .await
            .into_iter()
            .collect::<Vec<(u64, BigInt)>>();
        let mut gsk = 0.to_bigint().unwrap();
        for (id, s) in results.iter() {
            gsk += s;
        }
        gsk = gsk.reduce(&MODULUS);
        let (_, gsk_bytes) = gsk.to_bytes_be();        
        let gsk = SecretKey::deserialize(&gsk_bytes[..]).unwrap();
        let kp = Keypair::from_components(gsk.public_key(), gsk);
        Ok(kp)
    }
}

#[cfg(test)]
mod tests {
    use crate::network::io_committee::MemIOCommittee;

    const ids: Vec<u64> = vec![1, 2, 3, 4];

    #[test]
    fn test_dkg() {
        let io = Arc::new(MemIOCommittee::new(ids.as_slice()));
        let futs = ids.iter().map(|id| async move {
            let mut dkg = DKG::new(id, io);
            (id, dkg.run().await)
        });
    }
}