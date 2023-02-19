use crate::crypto::ThresholdSignature;
use crate::crypto::define::{MODULUS};
use std::ptr;
use bls::{Hash256, Signature as WrapSignature, SecretKey as WrapSecretKey, PublicKey as WrapPublicKey, Keypair as WrapKeypair, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN, SIGNATURE_BYTES_LEN};
use blst::min_pk::{SecretKey, PublicKey, Signature};
use num_bigint::{BigInt, Sign};
use num_bigint::ToBigInt;
use crate::math::bigint_ext::Ring;
use std::sync::Arc;
use blst::{blst_scalar, blst_p1, blst_p1_affine};
use crate::network::io_committee::{IOCommittee, IOChannel, PrivateChannel};
use futures::future::join_all;
use bytes::Bytes;
use crate::utils::error::DvfError;
use std::marker::PhantomData;
use std::collections::HashMap;
use crate::utils::blst_utils::{u64_to_blst_scalar, bigint_to_blst_scalar,
    fixed_p1_generator, bytes_to_blst_p1_affine, blst_p1_mult,
    bytes_to_blst_scalar, random_blst_scalar, hash_points_to_blst_scalar,
    blst_scalar_mult, blst_scalar_sub, blst_p1_add, blst_p1_to_bytes,
    blst_scalar_to_bytes, bytes_to_blst_p1, another_p1_generator,
    blst_scalar_add, blst_sk_to_pk, blst_p1s_add, blst_p1_affines_add,
    blst_p1_affine_to_bytes,
};
use crate::math::polynomial::{Commitable, CommittedPoly, Polynomial};
use serde_derive::{Serialize, Deserialize};
use serde::{Serialize as SerializeTrait, Deserialize as DeserializeTrait, Serializer, Deserializer, 
    ser::{SerializeStruct}};

pub struct PlainVssShare {
    pub share: blst_scalar,
    pub committed_poly: CommittedPoly,
}

#[derive(Serialize, Deserialize)]
pub struct VssSharePayload {
    pub enc_share: Bytes,
    pub sig: WrapSignature,
    pub committed_poly: CommittedPoly,
}

impl VssSharePayload {
    pub fn to_bytes(&self) -> Bytes {
        bincode::serialize(self).unwrap().into()
    }

    pub fn from_bytes(bytes: &Bytes) -> Self {
        bincode::deserialize::<Self>(bytes.as_ref()).unwrap()
    }

    // pub async fn to_channel<T: IOChannel>(&self, channel: &T) {
    //     channel.send(self.enc_share.clone()).await;
    //     channel.send(Bytes::copy_from_slice(&self.sig.serialize())).await;
    //     channel.send(self.committed_poly.to_bytes().into()).await;
    // }
    // pub async fn from_channel<T: IOChannel>(channel: &T) -> Result<Self, DvfError> {
    //     let enc_share = channel.recv().await;
    //     let sig = Signature::deserialize(&channel.recv().await).map_err(Into::<DvfError>::into)?;
    //     let committed_poly = CommittedPoly::from_bytes(&channel.recv().await);
    //     Ok(Self {
    //         enc_share,
    //         sig,
    //         committed_poly,
    //     })
    // }
}

#[derive(Serialize, Deserialize)]
pub struct VerificationResult {
    pub results: HashMap<u64, bool>,
}

impl VerificationResult {
    pub fn to_bytes(&self) -> Bytes {
        bincode::serialize(self).unwrap().into()
    }

    pub fn from_bytes(bytes: &Bytes) -> Self {
        bincode::deserialize::<Self>(bytes.as_ref()).unwrap()
    }

    // pub async fn to_channel<T: IOChannel>(&self, channel: &T) {
    //     let mut keys = Vec::<u8>::with_capacity(self.results.len() * 8);
    //     let mut values = Vec::<u8>::with_capacity(self.results.len());
    //     for (key, val) in self.results.iter() {
    //         keys.extend_from_slice(key.to_le_bytes().as_slice());
    //         values.extend_from_slice([*val as u8].as_slice());
    //     }
    //     channel.send(keys.into()).await;
    //     channel.send(values.into()).await;
        
    // }
    // pub async fn from_channel<T: IOChannel>(channel: &T) -> Result<Self, DvfError> {
    //     let keys = channel.recv().await;
    //     let values = channel.recv().await;
    //     let mut results: HashMap<u64, bool> = Default::default();
    //     for i in 0..values.len() {
    //         let key = u64::from_le_bytes(<[u8; 8]>::try_from(keys.slice(i*8..(i+1)*8).as_ref()).unwrap());
    //         let val = values.as_ref()[i] != 0;
    //         results.insert(key, val);
    //     }
    //     Ok (Self {
    //         results,
    //     })
    // }
}

#[derive(Clone)]
pub struct DleqProof {
    c: blst_scalar,
    r: blst_scalar,
}

impl SerializeTrait for DleqProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut vec = blst_scalar_to_bytes(&self.c).to_vec();
        vec.extend_from_slice(blst_scalar_to_bytes(&self.c).as_ref());
        vec.serialize(serializer)
    }
}

impl<'de> DeserializeTrait<'de> for DleqProof {
    fn deserialize<D>(deserializer: D) -> Result<DleqProof, D::Error>
    where
        D: Deserializer<'de>,
    {
        let vec = Vec::<u8>::deserialize(deserializer)?;
        let c = bytes_to_blst_scalar(Bytes::copy_from_slice(&vec[0..32]));
        let r = bytes_to_blst_scalar(Bytes::copy_from_slice(&vec[32..]));
        Ok(
            Self {
                c,
                r,
            }
        )
    }
}

#[derive(Serialize, Deserialize)]
pub struct DisputeClaim {
    pub issue_party: u64,
    pub corrupted_party: u64,
    pub enc_share: Bytes,
    pub key: Bytes,
    pub sig: WrapSignature,
    pub committed_poly: CommittedPoly,
    pub proof: DleqProof,
}

impl DisputeClaim {
    pub fn to_bytes(&self) -> Bytes {
        bincode::serialize(self).unwrap().into()
    }

    pub fn from_bytes(bytes: &Bytes) -> Self {
        bincode::deserialize::<Self>(bytes.as_ref()).unwrap()
    }

    // pub async fn to_channel<T: IOChannel>(&self, channel: &T) {
    //     channel.send(self.enc_share.clone()).await;
    //     channel.send(self.key.clone()).await;
    //     channel.send(Bytes::copy_from_slice(&self.sig.serialize())).await;
    //     channel.send(self.committed_poly.to_bytes().into()).await;
    //     // channel.send(self.proof.to_bytes().into()).await;
    // }
    // pub async fn from_channel<T: IOChannel>(channel: &T) -> Result<Self, DvfError> {
    //     let enc_share = channel.recv().await;
    //     let key = channel.recv().await;
    //     let sig = Signature::deserialize(&channel.recv().await).map_err(Into::<DvfError>::into)?;
    //     let committed_poly = CommittedPoly::from_bytes(&channel.recv().await);
    //     // let proof = DleqProof::from_bytes(&channel.recv().await);
    //     Ok(Self {
    //         enc_share,
    //         key,
    //         sig,
    //         committed_poly,
    //     })
    // }
}

pub struct GpkPayload {
    pub gpk: blst_p1,
    pub aux_gpk: blst_p1,
    pub proof: DleqProof,
}

impl GpkPayload {
    pub fn to_bytes(&self) -> Bytes {
        bincode::serialize(self).unwrap().into()
    }

    pub fn from_bytes(bytes: &Bytes) -> Self {
        bincode::deserialize::<Self>(bytes.as_ref()).unwrap()
    }
}

impl SerializeTrait for GpkPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (blst_p1_to_bytes(&self.gpk), blst_p1_to_bytes(&self.aux_gpk), self.proof.clone()).serialize(serializer)
    }
}

impl<'de> DeserializeTrait<'de> for GpkPayload {
    fn deserialize<D>(deserializer: D) -> Result<GpkPayload, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (gpk, aux_gpk, proof) = <(Bytes, Bytes, DleqProof)>::deserialize(deserializer)?;
        let gpk = bytes_to_blst_p1(gpk);
        let aux_gpk = bytes_to_blst_p1(aux_gpk);
        Ok(
            Self {
                gpk,
                aux_gpk,
                proof,
            }
        )
    }
}

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
    h: blst_p1,
    _phantom: PhantomData<U>, // Allow to use generic type U when no concrete member is related to U
}

impl<T, U> DKG<T, U> 
where 
    U: IOChannel + PrivateChannel,
    T: IOCommittee<U> {

    pub fn new(party: u64, io: Arc<T>, threshold: usize) -> Self {
        let h = another_p1_generator();

        Self {
            party,
            io,
            threshold,
            h,
            _phantom: PhantomData,
        }
    }

    /// Returns:
    /// 1. Self's key pair
    /// 2. Master public key
    /// 3. A hashmap from a party's ID to its shared public key
    // pub async fn run(&self) -> Result<(WrapKeypair, WrapPublicKey, HashMap<u64, WrapPublicKey>), DvfError> {
    //     let mut threshold_sig = ThresholdSignature::new(self.threshold);
    //     let ids = self.io.ids();
    //     let (kp, kps, poly) = threshold_sig.key_gen_with_poly(ids)?;
    //     // Generator g
    //     let g = fixed_p1_generator();
    //     let committed_poly = poly.commit(g);

    //     // 0. Broadcast shares and commitments
    //     let kps_ref = &kps; // Take reference so that it can be used in async move
    //     let kp_ref = &kp;
    //     let committed_poly_ref = &committed_poly;
    //     let g_ref = &g;
    //     let futs = ids.iter().map(|id| async move {
    //         let s_ij = Bytes::copy_from_slice(kps_ref.get(id).unwrap().sk.serialize().as_bytes());
    //         let pk_i = Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice());
    //         let commitments = committed_poly_ref.to_bytes().into();
    //         let (s_ji, pk_j, commitments_j) = {
    //             if *id == self.party {
    //                 (s_ij, pk_i, commitments)
    //             }
    //             else {
    //                 let send_channel = self.io.channel(self.party, *id);
    //                 let recv_channel = self.io.channel(*id, self.party);
    //                 // Send a share of my secret to party `id`
    //                 send_channel.send(s_ij).await;
    //                 // Recv a share of party `id`'s secret
    //                 let s = recv_channel.recv().await;
    //                 // Publish public key corresponding to my secret to party `id`
    //                 send_channel.send(pk_i).await;
    //                 // Recv public key corresponding to the secret of party `id`
    //                 let pk_bytes = recv_channel.recv().await;
    //                 // Send commitments to party `id`
    //                 send_channel.send(commitments).await;
    //                 // Recv commitments from party `id`
    //                 let commitments_bytes = recv_channel.recv().await;
    //                 (s, pk_bytes, commitments_bytes)
    //             }
    //         };

    //         let s = BigInt::from_bytes_be(Sign::Plus, s_ji.as_ref());
    //         let pk = bytes_to_blst_p1_affine(pk_j);

    //         (*id, s, pk)
    //     });
    //     let results = join_all(futs)
    //         .await
    //         .into_iter()
    //         .collect::<Vec<(u64, BigInt, blst_p1_affine)>>();
        
    //     // 1. Construct self's individual group key pair
    //     let mut gsk = 0.to_bigint().unwrap();
    //     for (_id, s, _) in results.iter() {
    //         gsk += s;
    //     }
    //     gsk = gsk.reduce(&MODULUS);
    //     let (_, mut gsk_bytes) = gsk.to_bytes_be();
    //     if gsk_bytes.len() < SECRET_KEY_BYTES_LEN {
    //         (0..SECRET_KEY_BYTES_LEN - gsk_bytes.len()).for_each(|_| gsk_bytes.insert(0, 0));
    //     }  
    //     let gsk = WrapSecretKey::deserialize(&gsk_bytes[..]).unwrap();
    //     let kp = WrapKeypair::from_components(gsk.public_key(), gsk);

    //     // 2. Construct master public key
        
    //     let mut mpk_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
    //     unsafe {
    //         let pks = results.iter().map(|(_, _, x)| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
    //         let mut mpk: blst_p1 = Default::default();
    //         blst::blst_p1s_add(&mut mpk, pks.as_ptr(), pks.len());
    //         blst::blst_p1_compress(mpk_bytes.as_mut_ptr(), &mpk);
    //     };
    //     let mpk = WrapPublicKey::deserialize(&mpk_bytes).unwrap();

    //     // 3. Exchange individual group public key
    //     let kp_ref = &kp;
    //     let futs = ids.iter().map(|id| async move {
    //         let pk_bytes = Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice());
    //         let (id, pk) = {
    //             if *id == self.party {
    //                 (*id, kp_ref.pk.clone())
    //             }
    //             else {
    //                 let send_channel = self.io.channel(self.party, *id);
    //                 let recv_channel = self.io.channel(*id, self.party);
    //                 // Send my pk to party `id`
    //                 send_channel.send(pk_bytes).await;
    //                 // Recv pk of party `id`
    //                 let pk_bytes = recv_channel.recv().await;
    //                 let pk = WrapPublicKey::deserialize(pk_bytes.as_ref()).unwrap();
    //                 (*id, pk)
    //             }
    //         };

    //         (id, pk)
    //     });
    //     let pks = join_all(futs)
    //         .await
    //         .into_iter()
    //         .collect::<HashMap<u64, WrapPublicKey>>();

    //     Ok((kp, mpk, pks))
    // }

    /// Returns:
    /// 1. Self's key pair
    /// 2. Master public key
    /// 3. A hashmap from a party's ID to its shared public key
    pub async fn run(&self) -> Result<(WrapKeypair, WrapPublicKey, HashMap<u64, WrapPublicKey>), DvfError> {
        let (kp, kps, poly, committed_poly) = self.share_generation()?;
        let payloads: HashMap<u64, VssSharePayload> = self.share_transmission(&kps, &committed_poly).await?;
        let vrfy_result = self.share_verification(&payloads);
        let other_vrfy_results = self.exchange_verification_results(&vrfy_result).await;

        for (id, valid) in vrfy_result.results.iter() {
            if *valid {
                continue;
            }
            self.issude_dispute_claim(*id, payloads.get(&id).unwrap()).await;
        }
        let mut futs: Vec<_> = Default::default();
        for (id1, other_vrfy_result) in other_vrfy_results.iter() {
            let channel = self.io.channel(*id1, self.party);
            for (id2, valid) in other_vrfy_result.results.iter() {
                if *valid {
                    continue;
                }
                let fut = async move {
                    let claim = DisputeClaim::from_bytes(&channel.recv().await);
                    let claim_is_valid = self.verify_dispute_claim(&claim).await;
                    (*id1, *id2, claim_is_valid)
                };
                futs.push(fut);
            }
        }
        let valid_claims = join_all(futs)
            .await
            .into_iter()
            .filter(|(_, _, x)| *x)
            .map(|(a, b, c)| (a, b))
            .collect::<Vec<(u64, u64)>>();
        if valid_claims.len() > 0 {
            return Err(DvfError::InvalidDkgShare(valid_claims))
        }
        
        // Derive master public key
        let self_pk = bytes_to_blst_p1_affine(Bytes::copy_from_slice(kp.pk.serialize().as_slice()));
        let mut pks = self.exchange_public_keys(&self_pk).await;
        pks.insert(self.party, self_pk);
        let mpk = blst_p1_affines_add(&pks.into_values().collect::<Vec<blst_p1_affine>>());

        // Derive group secret key and group public key 
        let mut shares = self.reveal_shares(&payloads);
        let self_share = bytes_to_blst_scalar(
            Bytes::copy_from_slice(kps.get(&self.party).unwrap().sk.serialize().as_bytes())
        );
        shares.insert(self.party, self_share);
        let (gsk, gpk) = self.construct_group_key(&shares);

        // Exchange and verify group public keys
        let mut committed_polys = HashMap::<u64, CommittedPoly>::default();
        committed_polys.insert(self.party, committed_poly);
        for (id, share) in payloads.iter() {
            committed_polys.insert(*id, share.committed_poly.clone());
        }
        let gpks = self.exchange_group_public_keys(&gsk, &gpk, &committed_polys).await?;

        let gsk = WrapSecretKey::deserialize(blst_scalar_to_bytes(&gsk).as_ref()).map_err(Into::<DvfError>::into)?;
        let gkp = WrapKeypair::from_components(gsk.public_key(), gsk);
        let mpk = WrapPublicKey::deserialize(blst_p1_to_bytes(&mpk).as_ref()).map_err(Into::<DvfError>::into)?;
        let gpks = gpks.iter()
            .map(|(id, gpk)| (*id, WrapPublicKey::deserialize(blst_p1_to_bytes(&gpk).as_ref()).unwrap()))
            .collect::<HashMap<u64, WrapPublicKey>>();

        Ok((gkp, mpk, gpks))
        

        // // 0. Broadcast shares and commitments
        // let kps_ref = &kps; // Take reference so that it can be used in async move
        // let kp_ref = &kp;
        // let committed_poly_ref = &committed_poly;
        // let g_ref = &g;
        // let futs = ids.iter().map(|id| async move {
        //     let s_ij = Bytes::copy_from_slice(kps_ref.get(id).unwrap().sk.serialize().as_bytes());
        //     let pk_i = Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice());
        //     let commitments = committed_poly_ref.to_bytes().into();
        //     let (s_ji, pk_j, commitments_j) = {
        //         if *id == self.party {
        //             (s_ij, pk_i, commitments)
        //         }
        //         else {
        //             let send_channel = self.io.channel(self.party, *id);
        //             let recv_channel = self.io.channel(*id, self.party);
        //             // Send a share of my secret to party `id`
        //             send_channel.send(s_ij).await;
        //             // Recv a share of party `id`'s secret
        //             let s = recv_channel.recv().await;
        //             // Publish public key corresponding to my secret to party `id`
        //             send_channel.send(pk_i).await;
        //             // Recv public key corresponding to the secret of party `id`
        //             let pk_bytes = recv_channel.recv().await;
        //             // Send commitments to party `id`
        //             send_channel.send(commitments).await;
        //             // Recv commitments from party `id`
        //             let commitments_bytes = recv_channel.recv().await;
        //             (s, pk_bytes, commitments_bytes)
        //         }
        //     };

        //     let s = BigInt::from_bytes_be(Sign::Plus, s_ji.as_ref());
        //     let pk = bytes_to_blst_p1_affine(pk_j);

        //     (*id, s, pk)
        // });
        // let results = join_all(futs)
        //     .await
        //     .into_iter()
        //     .collect::<Vec<(u64, BigInt, blst_p1_affine)>>();
        
        // // 1. Construct self's individual group key pair
        // let mut gsk = 0.to_bigint().unwrap();
        // for (_id, s, _) in results.iter() {
        //     gsk += s;
        // }
        // gsk = gsk.reduce(&MODULUS);
        // let (_, mut gsk_bytes) = gsk.to_bytes_be();
        // if gsk_bytes.len() < SECRET_KEY_BYTES_LEN {
        //     (0..SECRET_KEY_BYTES_LEN - gsk_bytes.len()).for_each(|_| gsk_bytes.insert(0, 0));
        // }  
        // let gsk = WrapSecretKey::deserialize(&gsk_bytes[..]).unwrap();
        // let kp = WrapKeypair::from_components(gsk.public_key(), gsk);

        // // 2. Construct master public key
        
        // let mut mpk_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
        // unsafe {
        //     let pks = results.iter().map(|(_, _, x)| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
        //     let mut mpk: blst_p1 = Default::default();
        //     blst::blst_p1s_add(&mut mpk, pks.as_ptr(), pks.len());
        //     blst::blst_p1_compress(mpk_bytes.as_mut_ptr(), &mpk);
        // };
        // let mpk = WrapPublicKey::deserialize(&mpk_bytes).unwrap();

        // // 3. Exchange individual group public key
        // let kp_ref = &kp;
        // let futs = ids.iter().map(|id| async move {
        //     let pk_bytes = Bytes::copy_from_slice(kp_ref.pk.serialize().as_slice());
        //     let (id, pk) = {
        //         if *id == self.party {
        //             (*id, kp_ref.pk.clone())
        //         }
        //         else {
        //             let send_channel = self.io.channel(self.party, *id);
        //             let recv_channel = self.io.channel(*id, self.party);
        //             // Send my pk to party `id`
        //             send_channel.send(pk_bytes).await;
        //             // Recv pk of party `id`
        //             let pk_bytes = recv_channel.recv().await;
        //             let pk = WrapPublicKey::deserialize(pk_bytes.as_ref()).unwrap();
        //             (*id, pk)
        //         }
        //     };

        //     (id, pk)
        // });
        // let pks = join_all(futs)
        //     .await
        //     .into_iter()
        //     .collect::<HashMap<u64, WrapPublicKey>>();

        // Ok((kp, mpk, pks))
    }

    pub fn share_generation(&self) -> Result<(WrapKeypair, HashMap<u64, WrapKeypair>, Polynomial<BigInt>, CommittedPoly), DvfError> {
        let mut threshold_sig = ThresholdSignature::new(self.threshold);
        let ids = self.io.ids();
        let (kp, kps, poly) = threshold_sig.key_gen_with_poly(ids)?;
        // Generator g
        let g = fixed_p1_generator();
        let committed_poly = poly.commit(g);

        Ok((kp, kps, poly, committed_poly))
    }

    /// Broadcast shares and commitments
    pub async fn share_transmission(&self,
        kps: &HashMap<u64, WrapKeypair>,
        committed_poly: &CommittedPoly,    
    ) -> Result<HashMap<u64, VssSharePayload>, DvfError> {

        let mut futs: Vec<_> = Default::default();
        for id in self.io.ids().iter() {
            if *id == self.party {
                continue;
            }
            let send_channel = self.io.channel(self.party, *id);
            let recv_channel = self.io.channel(*id, self.party);

            // Plain share
            let s_ij = Bytes::copy_from_slice(kps.get(id).unwrap().sk.serialize().as_bytes());
            // Encrypt the share
            let enc_s_ij = send_channel.encrypt(s_ij);
            // Sign the encrypted share
            let sig = send_channel.sign(enc_s_ij.clone());
            let sig = WrapSignature::deserialize(sig.to_bytes().as_slice()).map_err(Into::<DvfError>::into)?;

            let payload = VssSharePayload {
                enc_share: enc_s_ij,
                sig,
                committed_poly: committed_poly.clone(),
            };
            let fut = async move {
                // payload.to_channel(send_channel);
                send_channel.send(payload.to_bytes()).await;
                let partner_palyload = VssSharePayload::from_bytes(&recv_channel.recv().await);
                (*id, partner_palyload)
            };
            futs.push(fut);
        }
        let results = join_all(futs)
            .await
            .into_iter()
            .collect::<HashMap<u64, VssSharePayload>>();

        Ok(results)
    }

    pub fn reveal_shares(&self, shares: &HashMap<u64, VssSharePayload>) -> HashMap<u64, blst_scalar> {
        let mut results: HashMap<u64, blst_scalar> = Default::default();
        for (id, share) in shares.iter() {
            if *id == self.party {
                continue;
            }
            let send_channel = self.io.channel(self.party, *id);

            let s = send_channel.decrypt(share.enc_share.clone());
            let s = bytes_to_blst_scalar(s);
            results.insert(*id, s);
        }
        results
    }

    pub fn share_verification(&self, shares: &HashMap<u64, VssSharePayload>) -> VerificationResult {
        let mut results: HashMap<u64, bool> = Default::default();
        let g = fixed_p1_generator();
        for id in self.io.ids().iter() {
            if *id == self.party {
                continue;
            }
            let send_channel = self.io.channel(self.party, *id);

            let share = shares.get(id).unwrap();
            let s = send_channel.decrypt(share.enc_share.clone());
            let s = bytes_to_blst_scalar(s);

            let y = blst_p1_mult(&g, &s);
            let y_ = share.committed_poly.eval(u64_to_blst_scalar(*id));

            results.insert(*id, y == y_);
        }
        VerificationResult {
            results
        }
    }

    pub async fn exchange_verification_results(&self, r: &VerificationResult) -> HashMap<u64, VerificationResult> {
        self.io.broadcast(r.to_bytes()).await;
        let mut others = HashMap::<u64, VerificationResult>::default();
        // TODO: parallelize
        for id in self.io.ids().iter() {
            if *id == self.party {
                continue;
            }
            let recv_channel = self.io.channel(*id, self.party);
            let msg = recv_channel.recv().await;
            let result = VerificationResult::from_bytes(&msg);
            others.insert(*id, result);
        }
        others
    }

    pub async fn issude_dispute_claim(&self, corrupted_party_id: u64, share: &VssSharePayload) {
        let channel = self.io.channel(self.party, corrupted_party_id);
        let g = fixed_p1_generator();
        let pk_j = channel.self_public_key();
        let pk_i = channel.partner_public_key();
        let kij = channel.shared_secret();
        let sk_j = channel.self_private_key();
        let proof = Self::dleq_prove(&g, &pk_j, &pk_i, &kij, &sk_j);
        
        let claim = DisputeClaim {
            issue_party: self.party,
            corrupted_party: corrupted_party_id,
            enc_share: share.enc_share.clone(),
            key: blst_p1_to_bytes(&kij),
            sig: share.sig.clone(),
            committed_poly: share.committed_poly.clone(),
            proof,
        };

        self.io.broadcast(claim.to_bytes()).await;
    }

    pub async fn verify_dispute_claim(&self, claim: &DisputeClaim) -> bool {
        let channel_j = self.io.channel(self.party, claim.issue_party);
        let channel_i = self.io.channel(self.party, claim.corrupted_party);

        // Verify signature on the encrypted share
        let sig = Signature::from_bytes(claim.sig.serialize().as_slice()).unwrap();
        if !channel_i.verify_partner(claim.enc_share.clone(), sig) {
            return false;
        }

        let g = fixed_p1_generator();
        let pk_j = channel_j.partner_public_key();
        let pk_i = channel_i.partner_public_key();
        let kij = bytes_to_blst_p1(claim.key.clone());
        
        // Verify kij is valid
        if !Self::dleq_verify(&g, &pk_j, &pk_i, &kij, &claim.proof) {
            return false;
        }

        // Verify whether the VSS verification condition holds
        let s = <U>::decrypt_with_key(claim.enc_share.clone(), blst_p1_to_bytes(&kij));
        let s = bytes_to_blst_scalar(s);
        let y = blst_p1_mult(&g, &s);
        let y_ = claim.committed_poly.eval(u64_to_blst_scalar(claim.issue_party));

        y != y_
    }

    pub async fn exchange_public_keys(&self, pk: &blst_p1_affine) -> HashMap<u64, blst_p1_affine> {
        self.io.broadcast(blst_p1_affine_to_bytes(pk)).await;
        let mut others = HashMap::<u64, blst_p1_affine>::default();
        // TODO: parallelize
        for id in self.io.ids().iter() {
            if *id == self.party {
                continue;
            }
            let recv_channel = self.io.channel(*id, self.party);
            let msg = recv_channel.recv().await;
            let other_pk = bytes_to_blst_p1_affine(msg);
            others.insert(*id, other_pk);
        }
        others
    }

    pub fn construct_group_key(&self, shares: &HashMap<u64, blst_scalar>) -> (blst_scalar, blst_p1) {
        let mut gsk = blst_scalar::default();
        for (id, s) in shares.iter() {
            gsk = blst_scalar_add(&gsk, s);
        }
        let gpk = blst_sk_to_pk(&gsk);
        (gsk, gpk)
    }

    pub async fn exchange_group_public_keys(&self, 
        gsk: &blst_scalar, 
        gpk: &blst_p1, 
        committed_polys: &HashMap<u64, CommittedPoly>
    ) -> Result<HashMap<u64, blst_p1>, DvfError> {
        let g = fixed_p1_generator();
        let aux_gpk = blst_p1_mult(&self.h, gsk);
        let proof = Self::dleq_prove(&g, gpk, &self.h, &aux_gpk, gsk);
        let gpk_payload = GpkPayload {
            gpk: *gpk,
            aux_gpk,
            proof
        };
        self.io.broadcast(gpk_payload.to_bytes()).await;

        let mut futs: Vec<_> = Default::default();
        for id in self.io.ids().iter() {
            if *id == self.party {
                continue;
            }
            let fut = async move {
                let recv_channel = self.io.channel(*id, self.party);
                let msg = recv_channel.recv().await;
                let other_gpk_payload = GpkPayload::from_bytes(&msg);
                let zk_verified = Self::dleq_verify(
                    &g, 
                    &other_gpk_payload.gpk, 
                    &self.h, 
                    &other_gpk_payload.aux_gpk, 
                    &other_gpk_payload.proof
                );
                if !zk_verified {
                    return None;
                }

                for (id_, poly) in committed_polys.iter() {
                    let p = poly.eval(u64_to_blst_scalar(*id));
                }
                let evals = committed_polys.iter()
                    .map(|(_, poly)| poly.eval(u64_to_blst_scalar(*id)))
                    .collect::<Vec<blst_p1>>();
                let f = blst_p1s_add(&evals);

                let commit_verified = other_gpk_payload.gpk == f;

                if !commit_verified {
                    return None;
                }

                Some((*id, other_gpk_payload.gpk))
            };
            futs.push(fut);
        }

        let mut results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<u64, blst_p1>>();
        results.insert(self.party, *gpk);
        
        Ok(results)
    }

    pub fn dleq_prove(
        x1: &blst_p1, 
        y1: &blst_p1,
        x2: &blst_p1,
        y2: &blst_p1,
        alpha: &blst_scalar,
    ) -> DleqProof {
        let w = random_blst_scalar();
        let t1 = blst_p1_mult(x1, &w);
        let t2 = blst_p1_mult(x2, &w);
        let c = hash_points_to_blst_scalar([x1.clone(), y1.clone(), x2.clone(), y2.clone(), t1, t2].as_slice());
        let r = blst_scalar_sub(
            &w,
            &blst_scalar_mult(alpha, &c)
        );
        DleqProof {
            c,
            r,
        }
    }

    pub fn dleq_verify(
        x1: &blst_p1, 
        y1: &blst_p1,
        x2: &blst_p1,
        y2: &blst_p1,
        proof: &DleqProof,
    ) -> bool {
        let t1 = blst_p1_add(
            &blst_p1_mult(x1, &proof.r),
            &blst_p1_mult(y1, &proof.c)
        );
        let t2 = blst_p1_add(
            &blst_p1_mult(x2, &proof.r),
            &blst_p1_mult(y2, &proof.c)
        );
        let c_ = hash_points_to_blst_scalar([x1.clone(), y1.clone(), x2.clone(), y2.clone(), t1, t2].as_slice());
        proof.c == c_
    }

}

pub struct SimpleDistributedSigner<T, U> {
    party: u64,  // self id
    kp: WrapKeypair,  // individual shared private key
    mpk: WrapPublicKey,  // master public key
    pks: HashMap<u64, WrapPublicKey>,  // id --> invidividual shared public key
    io: Arc<T>,
    threshold: usize,
    _phantom: PhantomData<U>,
}

impl<T, U> SimpleDistributedSigner<T, U> 
where 
    U: IOChannel,
    T: IOCommittee<U> {

    pub fn new(party: u64, kp: WrapKeypair, mpk: WrapPublicKey, pks: HashMap<u64, WrapPublicKey>, io: Arc<T>, threshold: usize) -> Self {
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

    pub fn mpk(&self) -> &WrapPublicKey {
        &self.mpk
    }

    pub async fn sign(&self, msg: Hash256) -> Result<WrapSignature, DvfError>{
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
                    let sig = WrapSignature::deserialize(sig_bytes.as_ref()).unwrap();
                    (*id, pks_ref.get(id).unwrap().clone(), sig)
                }
            };

            Ok::<(u64, WrapPublicKey, WrapSignature), DvfError>((id, pk, sig))
        });

        let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<Vec<(u64, WrapPublicKey, WrapSignature)>>();

        let ids = results.iter().map(|x| x.0).collect::<Vec<u64>>();
        let pks = results.iter().map(|x| &x.1).collect::<Vec<&WrapPublicKey>>();
        let sigs = results.iter().map(|x| &x.2).collect::<Vec<&WrapSignature>>();

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