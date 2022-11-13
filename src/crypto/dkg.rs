// use crate::crypto::ThresholdSignature;
// use crate::crypto::define::{MODULUS};
// use lazy_static::lazy_static;
// use std::ptr;
// use bls::{SecretKey, PublicKey, Keypair, PUBLIC_KEY_BYTES_LEN};
// use num_bigint::{BigInt, Sign};
// use num_bigint::ToBigInt;
// use crate::math::bigint_ext::Ring;
// use std::sync::Arc;
// use blst::{blst_p1, blst_p1_affine};
// use crate::network::io_committee::{IOCommittee, IOChannel};
// use futures::future::join_all;
// use bytes::Bytes;
// use crate::utils::error::DvfError;
// use std::marker::PhantomData;


// pub struct DKG<T, U> {
//     party: u64,
//     io: Arc<T>,
//     threshold: usize,
//     h: blst_p1,
//     _phantom: PhantomData<U>,
// }

// impl<T, U> DKG<T, U> 
// where 
//     U: IOChannel,
//     T: IOCommittee<U> {

//     pub fn new(party: u64, io: Arc<T>, threshold: usize) -> Self {
//         let mut h = std::mem::MaybeUninit::<blst_p1>::uninit();
//         let msg = "dvf another generator";
    
//         // TODO: remove this `unsafe` code-block once we get a safe option from `blst`.
//         //
//         // https://github.com/sigp/lighthouse/issues/1720
//         let h = unsafe {
//             blst::blst_hash_to_g1(h.as_mut_ptr(), msg.as_ptr(), msg.len(), ptr::null(), 0, ptr::null(), 0);
//             h.assume_init()
//         };

//         Self {
//             party,
//             io,
//             threshold,
//             h,
//             _phantom: PhantomData,
//         }
//     }

//     pub async fn run(&self) -> Result<(Keypair, PublicKey), DvfError> {
//         let mut threshold_sig = ThresholdSignature::new(self.threshold);
//         let ids = self.io.ids();
//         let (kp, kps) = threshold_sig.key_gen(ids)?;

//         let kps_ref = &kps; // Take reference so that it can be used in async move
//         let kp_ref = &kp;
//         let futs = ids.iter().map(|id| async move {
//             let mut send_channel = self.io.channel(self.party, *id);
//             let mut recv_channel = self.io.channel(*id, self.party);
//             // Send a share of my secret to party `id`
//             send_channel.send(Bytes::copy_from_slice(kps_ref.get(id).unwrap().sk.serialize().as_bytes())).await;
//             // Recv a share of party `id`'s secret
//             let s = recv_channel.recv().await;
//             let s = BigInt::from_bytes_be(Sign::Plus, s.as_ref());
//             // Publish public key corresponding to my secret to party `id`
//             send_channel.send(Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice())).await;
//             // Recv public key corresponding to the secret of party `id`
//             let pk_bytes = recv_channel.recv().await;
//             let mut pk: blst_p1_affine = Default::default();
//             unsafe {
//                 blst::blst_p1_uncompress(&mut pk, pk_bytes.as_ptr());
//             };

//             (*id, s, pk)
//         });
//         let results = join_all(futs)
//             .await
//             .into_iter()
//             .collect::<Vec<(u64, BigInt, blst_p1_affine)>>();
//         let mut gsk = 0.to_bigint().unwrap();
//         // let mut mpk: blst_p1 = Default::default();
//         for (id, s, _) in results.iter() {
//             gsk += s;
//         }
//         gsk = gsk.reduce(&MODULUS);
//         let (_, gsk_bytes) = gsk.to_bytes_be();        
//         let gsk = SecretKey::deserialize(&gsk_bytes[..]).unwrap();
//         let kp = Keypair::from_components(gsk.public_key(), gsk);

//         let pks = results.iter().map(|(_, _, x)| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
//         let mut mpk_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
//         unsafe {
//             let mut mpk: blst_p1 = Default::default();
//             blst::blst_p1s_add(&mut mpk, pks.as_ptr(), pks.len());
//             blst::blst_p1_compress(mpk_bytes.as_mut_ptr(), &mpk);
//         };
//         let mpk = PublicKey::deserialize(&mpk_bytes).unwrap();

//         Ok((kp, mpk))
//     }
// }

// #[cfg(test)]
// mod tests {
//     use super::*;
//     use crate::network::io_committee::MemIOCommittee;
//     use crate::crypto::ThresholdSignature;
//     use types::{Hash256}; 
//     use eth2_hashing::{Context, Sha256Context};
//     use futures::future::join_all;
//     use futures::executor::block_on;
//     use bls::{Signature, PublicKey};

//     const ids: [u64; 4] = [1, 2, 3, 4];

//     #[test]
//     fn test_dkg() {
//         let t = 3;
//         // Use dkg to generate secret-shared keys
//         let io = &Arc::new(MemIOCommittee::new(ids.as_slice()));
//         let futs = ids.iter().map(|id| async move {
//             let mut dkg = DKG::new(*id, io.clone(), t);
//             dkg.run().await
//         });

//         let results = block_on(join_all(futs))
//             .into_iter()
//             .flatten()
//             .collect::<Vec<(Keypair, PublicKey)>>();
        
//         // Verify master public keys
//         for i in 1..results.len() {
//             assert_eq!(results[i].1, results[i-1].1, "Master public keys are not the same");
//         }

//         // Sign something with the shared keys
//         let kps: Vec<Keypair> = results.iter().map(|(kp, _)| kp.clone()).collect();
//         let pks: Vec<&PublicKey> = kps.iter().map(|kp| &kp.pk).collect();
//         let message = "hello world";
//         let mut context = Context::new();
//         context.update(message.as_bytes());
//         let message = Hash256::from_slice(&context.finalize());

//         let mut sigs: Vec<Signature> = Vec::new();
//         for kp in kps.iter() {
//             sigs.push(kp.sk.sign(message));
//         }
//         let sigs_ref: Vec<&Signature> = sigs.iter().map(|s| s).collect();
//         let mut m_threshold = ThresholdSignature::new(t);
//         let agg_sig = m_threshold.threshold_aggregate(&sigs_ref[..], &pks[..], &ids[..], message).unwrap();

//         // Verification with the master public key
//         let status1 = agg_sig.verify(&results[0].1, message);
        
//         assert!(status1, "Signature verification failed");
//     }
// }