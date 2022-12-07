use crate::crypto::ThresholdSignature;
use crate::crypto::define::{MODULUS};
use std::ptr;
use bls::{Hash256, Signature, SecretKey, PublicKey, Keypair, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN};
use num_bigint::{BigInt, Sign};
use num_bigint::ToBigInt;
use crate::math::bigint_ext::Ring;
use std::sync::Arc;
use blst::{blst_p1, blst_p1_affine};
use crate::network::io_committee::{IOCommittee, IOChannel};
use futures::future::join_all;
use bytes::Bytes;
use crate::utils::error::DvfError;
use std::marker::PhantomData;
use std::collections::HashMap;

/// Distributed key generation.
/// NOTE: DKG and the corresponding IO committee are not thread-safe if multiple instances for
/// one party are running at the same time, so users should make sure that DKG requests are created 
/// and processed one by one sequentially, instead of concurrently.
/// 
/// For example, if there are two committees X: (A, B, C, D) and Y: (A, B, E, F),
/// then we should make sure that either:
/// - X runs first, and then Y runs;
/// - Y runs first, and then X runs.
/// 
/// Such a restriction is mainly due to the fact that each party is listening on a single port for DKG, 
/// so multiple concurrent DKG instances would cause chaos in the connections among parties.
pub struct DKG<T, U> {
    party: u64,
    io: Arc<T>,
    threshold: usize,
    _h: blst_p1,
    _phantom: PhantomData<U>,
}

impl<T, U> DKG<T, U> 
where 
    U: IOChannel,
    T: IOCommittee<U> {

    pub fn new(party: u64, io: Arc<T>, threshold: usize) -> Self {
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
            _h: h,
            _phantom: PhantomData,
        }
    }

    /// Returns:
    /// 1. Self's key pair
    /// 2. Master public key
    /// 3. A hashmap from a party's ID to its shared public key
    pub async fn run(&self) -> Result<(Keypair, PublicKey, HashMap<u64, PublicKey>), DvfError> {
        let mut threshold_sig = ThresholdSignature::new(self.threshold);
        let ids = self.io.ids();
        let (kp, kps) = threshold_sig.key_gen(ids)?;

        let kps_ref = &kps; // Take reference so that it can be used in async move
        let kp_ref = &kp;
        let futs = ids.iter().map(|id| async move {
            let s_ij = Bytes::copy_from_slice(kps_ref.get(id).unwrap().sk.serialize().as_bytes());
            let pk_i = Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice());
            let (s_ji, pk_j) = {
                if *id == self.party {
                    (s_ij, pk_i)
                }
                else {
                    let send_channel = self.io.channel(self.party, *id);
                    let recv_channel = self.io.channel(*id, self.party);
                    // Send a share of my secret to party `id`
                    send_channel.send(s_ij).await;
                    // Recv a share of party `id`'s secret
                    let s = recv_channel.recv().await;
                    // Publish public key corresponding to my secret to party `id`
                    send_channel.send(pk_i).await;
                    // Recv public key corresponding to the secret of party `id`
                    let pk_bytes = recv_channel.recv().await;
                    (s, pk_bytes)
                }
            };

            let s = BigInt::from_bytes_be(Sign::Plus, s_ji.as_ref());
            let mut pk: blst_p1_affine = Default::default();
            unsafe {
                blst::blst_p1_uncompress(&mut pk, pk_j.as_ptr());
            };

            (*id, s, pk)
        });
        let results = join_all(futs)
            .await
            .into_iter()
            .collect::<Vec<(u64, BigInt, blst_p1_affine)>>();
        
        // 1. Construct self's individual group key pair
        let mut gsk = 0.to_bigint().unwrap();
        for (_id, s, _) in results.iter() {
            gsk += s;
        }
        gsk = gsk.reduce(&MODULUS);
        let (_, mut gsk_bytes) = gsk.to_bytes_be();
        if gsk_bytes.len() < SECRET_KEY_BYTES_LEN {
            (0..SECRET_KEY_BYTES_LEN - gsk_bytes.len()).for_each(|_| gsk_bytes.insert(0, 0));
        }  
        let gsk = SecretKey::deserialize(&gsk_bytes[..]).unwrap();
        let kp = Keypair::from_components(gsk.public_key(), gsk);

        // 2. Construct master public key
        
        let mut mpk_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
        unsafe {
            let pks = results.iter().map(|(_, _, x)| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
            let mut mpk: blst_p1 = Default::default();
            blst::blst_p1s_add(&mut mpk, pks.as_ptr(), pks.len());
            blst::blst_p1_compress(mpk_bytes.as_mut_ptr(), &mpk);
        };
        let mpk = PublicKey::deserialize(&mpk_bytes).unwrap();

        // 3. Exchange individual group public key
        let kp_ref = &kp;
        let futs = ids.iter().map(|id| async move {
            let pk_bytes = Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice());
            let (id, pk) = {
                if *id == self.party {
                    (*id, kp_ref.pk.clone())
                }
                else {
                    let send_channel = self.io.channel(self.party, *id);
                    let recv_channel = self.io.channel(*id, self.party);
                    // Send my pk to party `id`
                    send_channel.send(pk_bytes).await;
                    // Recv pk of party `id`
                    let pk_bytes = recv_channel.recv().await;
                    let pk = PublicKey::deserialize(pk_bytes.as_ref()).unwrap();
                    (*id, pk)
                }
            };

            (id, pk)
        });
        let pks = join_all(futs)
            .await
            .into_iter()
            .collect::<HashMap<u64, PublicKey>>();

        Ok((kp, mpk, pks))
    }

}

pub struct SimpleDistributedSigner<T, U> {
    party: u64,  // self id
    kp: Keypair,  // individual shared private key
    mpk: PublicKey,  // master public key
    pks: HashMap<u64, PublicKey>,  // id --> invidividual shared public key
    io: Arc<T>,
    threshold: usize,
    _phantom: PhantomData<U>,
}

impl<T, U> SimpleDistributedSigner<T, U> 
where 
    U: IOChannel,
    T: IOCommittee<U> {

    pub fn new(party: u64, kp: Keypair, mpk: PublicKey, pks: HashMap<u64, PublicKey>, io: Arc<T>, threshold: usize) -> Self {
        Self {
            party,
            kp,
            mpk,
            pks,
            io,
            threshold,
            _phantom: PhantomData,
        }
    }

    pub fn mpk(&self) -> &PublicKey {
        &self.mpk
    }

    pub async fn sign(&self, msg: Hash256) -> Result<Signature, DvfError>{
        let ids = self.io.ids();

        let my_sig = self.kp.sk.sign(msg);

        let kp_ref = &self.kp;
        let my_sig_ref = &my_sig;
        let pks_ref = &self.pks;
        let futs = ids.iter().map(|id| async move {
            let (id, pk, sig) = {
                if *id == self.party {
                    (*id, kp_ref.pk.clone(), my_sig_ref.clone())
                }
                else {
                    let send_channel = self.io.channel(self.party, *id);
                    let recv_channel = self.io.channel(*id, self.party);
                    let sig_bytes = Bytes::copy_from_slice(my_sig_ref.serialize().as_slice());
                    // Send my sig to party `id`
                    send_channel.send(sig_bytes).await;
                    // Recv sig of party `id`
                    let sig_bytes = recv_channel.recv().await;
                    let sig = Signature::deserialize(sig_bytes.as_ref()).unwrap();
                    (*id, pks_ref.get(id).unwrap().clone(), sig)
                }
            };

            Ok::<(u64, PublicKey, Signature), DvfError>((id, pk, sig))
        });

        let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<(u64, PublicKey, Signature)>>();

        let ids = results.iter().map(|x| x.0).collect::<Vec<u64>>();
        let pks = results.iter().map(|x| &x.1).collect::<Vec<&PublicKey>>();
        let sigs = results.iter().map(|x| &x.2).collect::<Vec<&Signature>>();

        let threshold_sig = ThresholdSignature::new(self.threshold);
        threshold_sig.threshold_aggregate(&sigs[..], &pks[..], &ids[..], msg)
    }
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::io_committee::{MemIOCommittee, NetIOCommittee};
    use crate::crypto::ThresholdSignature;
    use types::{Hash256}; 
    use eth2_hashing::{Context, Sha256Context};
    use futures::future::join_all;
    use futures::executor::block_on;
    use bls::{Signature, PublicKey};
    use std::net::SocketAddr;
    use std::collections::HashMap;

    const t: usize = 3;
    const ids: [u64; 4] = [1, 2, 3, 4];

    fn verify_dkg_results(results: Vec<(Keypair, PublicKey, HashMap<u64, PublicKey>)>) {
        // Verify master public keys
        for i in 1..results.len() {
            assert_eq!(results[i].1, results[i-1].1, "Master public keys are not the same");
        }

        // Sign something with the shared keys
        let kps: Vec<Keypair> = results.iter().map(|(kp, _, _)| kp.clone()).collect();
        let pks: Vec<&PublicKey> = kps.iter().map(|kp| &kp.pk).collect();
        let message = "hello world";
        let mut context = Context::new();
        context.update(message.as_bytes());
        let message = Hash256::from_slice(&context.finalize());

        let mut sigs: Vec<Signature> = Vec::new();
        for kp in kps.iter() {
            sigs.push(kp.sk.sign(message));
        }
        let sigs_ref: Vec<&Signature> = sigs.iter().map(|s| s).collect();
        let mut m_threshold = ThresholdSignature::new(t);
        let agg_sig = m_threshold.threshold_aggregate(&sigs_ref[..], &pks[..], &ids[..], message).unwrap();

        // Verification with the master public key
        let status1 = agg_sig.verify(&results[0].1, message);

        assert!(status1, "Signature verification failed");
    }

    #[test]
    fn test_dkg() {
        // Use dkg to generate secret-shared keys
        let io = &Arc::new(MemIOCommittee::new(ids.as_slice()));
        let futs = ids.iter().map(|id| async move {
            let mut dkg = DKG::new(*id, io.clone(), t);
            dkg.run().await
        });

        let results = block_on(join_all(futs))
            .into_iter()
            .flatten()
            .collect::<Vec<(Keypair, PublicKey, HashMap<u64, PublicKey>)>>();
        
        verify_dkg_results(results);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_net() {
        let ports: Vec<u16> = ids.iter().map(|id| (25000 + *id) as u16).collect();
        let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

        let ports_ref = &ports;
        let addrs_ref = &addrs;
        // Use dkg to generate secret-shared keys
        let futs = (0..ids.len()).map(|i| async move {
            let io = &Arc::new(NetIOCommittee::new(ids[i], ports_ref[i], ids.as_slice(), addrs_ref.as_slice()).await);
            let mut dkg = DKG::new(ids[i], io.clone(), t);
            dkg.run().await
        });

        let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<(Keypair, PublicKey, HashMap<u64, PublicKey>)>>();
        
        verify_dkg_results(results);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_sig_net() {
        let ports: Vec<u16> = ids.iter().map(|id| (25000 + *id) as u16).collect();
        let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

        let message = "hello world";
        let mut context = Context::new();
        context.update(message.as_bytes());
        let message = Hash256::from_slice(&context.finalize());

        let ports_ref = &ports;
        let addrs_ref = &addrs;
        // Use dkg to generate secret-shared keys
        let futs = (0..ids.len()).map(|i| async move {
            let io = &Arc::new(NetIOCommittee::new(ids[i], ports_ref[i], ids.as_slice(), addrs_ref.as_slice()).await);
            let mut dkg = DKG::new(ids[i], io.clone(), t);
            let (kp, mpk, pks) = dkg.run().await?;

            // Sign with dkg result
            let signer = SimpleDistributedSigner::new(ids[i], kp, mpk.clone(), pks, io.clone(), t);
            let sig = signer.sign(message).await?;
            Ok::<(PublicKey, Signature), DvfError>((mpk, sig))
        });

        let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<(PublicKey, Signature)>>();

        for i in 0..results.len() {
            assert!(results[i].1.verify(&results[i].0, message), "Signature verification failed");
        }
    }

}