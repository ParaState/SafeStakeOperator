use crate::crypto::ThresholdSignature;
use crate::crypto::define::{MODULUS};
use std::ptr;
use bls::{Hash256, Signature as WrapSignature, SecretKey as WrapSecretKey, PublicKey as WrapPublicKey, Keypair as WrapKeypair, PUBLIC_KEY_BYTES_LEN, SECRET_KEY_BYTES_LEN};
use blst::min_pk::{Signature};
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
use crate::utils::blst_utils::*;
use crate::math::polynomial::{Commitable, CommittedPoly, Polynomial};
use serde_derive::{Serialize, Deserialize};
use serde::{Serialize as SerializeTrait, Deserialize as DeserializeTrait, Serializer, Deserializer};
use async_trait::async_trait;

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
}

#[derive(Clone, Debug)]
pub struct DleqProof {
    c: blst_scalar,
    r: blst_scalar,
}

impl SerializeTrait for DleqProof {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (blst_scalar_to_bytes(&self.c), blst_scalar_to_bytes(&self.r)).serialize(serializer)
    }
}

impl<'de> DeserializeTrait<'de> for DleqProof {
    fn deserialize<D>(deserializer: D) -> Result<DleqProof, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (c, r) = <(Bytes, Bytes)>::deserialize(deserializer)?;
        let c = bytes_to_blst_scalar(c);
        let r = bytes_to_blst_scalar(r);
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
}

#[derive(Debug)]
pub struct PkPayload {
    pub pk: blst_p1,
    pub proof: DleqProof,
}

impl PkPayload {
    pub fn to_bytes(&self) -> Bytes {
        bincode::serialize(self).unwrap().into()
    }

    pub fn from_bytes(bytes: &Bytes) -> Self {
        bincode::deserialize::<Self>(bytes.as_ref()).unwrap()
    }
}

impl SerializeTrait for PkPayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        (blst_p1_to_bytes(&self.pk), self.proof.clone()).serialize(serializer)
    }
}

impl<'de> DeserializeTrait<'de> for PkPayload {
    fn deserialize<D>(deserializer: D) -> Result<PkPayload, D::Error>
    where
        D: Deserializer<'de>,
    {
        let (pk, proof) = <(Bytes, DleqProof)>::deserialize(deserializer)?;
        let pk = bytes_to_blst_p1(pk);
        Ok(
            Self {
                pk,
                proof,
            }
        )
    }
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
#[async_trait]
pub trait DKGTrait : Sync + Send{
    async fn run(&self) -> Result<(WrapKeypair, WrapPublicKey, HashMap<u64, WrapPublicKey>), DvfError>;
}

pub struct DKGSemiHonest<T, U> {
    party: u64,
    io: Arc<T>,
    threshold: usize,
    _phantom: PhantomData<U>, // Allow to use generic type U when no concrete member is related to U
}

impl<T, U> DKGSemiHonest<T, U> 
where 
    U: IOChannel,
    T: IOCommittee<U> {

    pub fn new(party: u64, io: Arc<T>, threshold: usize) -> Self {

        Self {
            party,
            io,
            threshold,
            _phantom: PhantomData,
        }
    }
}

#[async_trait]
impl<T, U> DKGTrait for DKGSemiHonest<T, U> 
where 
    U: IOChannel,
    T: IOCommittee<U> {

    /// Returns:
    /// 1. Self's key pair
    /// 2. Master public key
    /// 3. A hashmap from a party's ID to its shared public key
    async fn run(&self) -> Result<(WrapKeypair, WrapPublicKey, HashMap<u64, WrapPublicKey>), DvfError> {
        let mut threshold_sig = ThresholdSignature::new(self.threshold);
        let ids = self.io.ids();
        let (kp, kps, _poly) = threshold_sig.key_gen_with_poly(ids)?;

        // 0. Broadcast shares and commitments
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
            let pk = bytes_to_blst_p1_affine(pk_j);

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
        let gsk = WrapSecretKey::deserialize(&gsk_bytes[..]).unwrap();
        let kp = WrapKeypair::from_components(gsk.public_key(), gsk);

        // 2. Construct master public key
        
        let mut mpk_bytes: [u8; PUBLIC_KEY_BYTES_LEN] = [0; PUBLIC_KEY_BYTES_LEN];
        unsafe {
            let pks = results.iter().map(|(_, _, x)| ptr::addr_of!(*x)).collect::<Vec<*const blst_p1_affine>>();
            let mut mpk: blst_p1 = Default::default();
            blst::blst_p1s_add(&mut mpk, pks.as_ptr(), pks.len());
            blst::blst_p1_compress(mpk_bytes.as_mut_ptr(), &mpk);
        };
        let mpk = WrapPublicKey::deserialize(&mpk_bytes).unwrap();

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
                    let pk = WrapPublicKey::deserialize(pk_bytes.as_ref()).unwrap();
                    (*id, pk)
                }
            };

            (id, pk)
        });
        let pks = join_all(futs)
            .await
            .into_iter()
            .collect::<HashMap<u64, WrapPublicKey>>();

        Ok((kp, mpk, pks))
    }
}

pub struct DKGMalicious<T, U> {
    party: u64,
    io: Arc<T>,
    threshold: usize,
    h: blst_p1,
    _phantom: PhantomData<U>, // Allow to use generic type U when no concrete member is related to U
}

impl<T, U> DKGMalicious<T, U> 
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

    pub fn share_generation(&self) -> Result<(WrapKeypair, HashMap<u64, WrapKeypair>, Polynomial<BigInt>, CommittedPoly), DvfError> {
        let mut threshold_sig = ThresholdSignature::new(self.threshold);
        let ids = self.io.ids();
        let (kp, kps, poly) = threshold_sig.key_gen_with_poly(ids)?;
        let committed_poly = poly.commit(&self.h);

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
            let s_ij = blst_wrap_sk_to_bytes(&kps.get(id).unwrap().sk);

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
        for (id, share) in shares.iter() {
            if *id == self.party {
                continue;
            }
            let send_channel = self.io.channel(self.party, *id);
            let s = send_channel.decrypt(share.enc_share.clone());
            let s = bytes_to_blst_scalar(s);

            let y = blst_p1_mult(&self.h, &s);
            let y_ = share.committed_poly.eval(&u64_to_blst_scalar(self.party));

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

    pub async fn issude_dispute_claim(&self, corrupted_party_id: u64, share: &VssSharePayload) -> Result<(), DvfError> {
        let channel = self.io.channel(self.party, corrupted_party_id);
        let g = fixed_p1_generator();
        let pk_j = channel.self_public_key();
        let pk_i = channel.partner_public_key();
        let kij = channel.shared_secret();
        let sk_j = channel.self_private_key();
        let proof = Self::dleq_prove(&g, &pk_j, &pk_i, &kij, &sk_j)?;
        
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
        Ok(())
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
        let y = blst_p1_mult(&self.h, &s);
        let y_ = claim.committed_poly.eval(&u64_to_blst_scalar(claim.issue_party));

        y != y_
    }

    pub async fn exchange_public_keys(&self, 
        pk: &blst_p1,
        sk: &blst_scalar,
        committed_polys: &HashMap<u64, CommittedPoly>,
    ) -> Result<HashMap<u64, blst_p1>, DvfError> {

        let g = fixed_p1_generator();
        let aux_pk = &committed_polys[&self.party].commitments[0];
        let proof = Self::dleq_prove(&g, pk, &self.h, aux_pk, sk)?;
        let pk_payload = PkPayload {
            pk: *pk,
            proof
        };
        self.io.broadcast(pk_payload.to_bytes()).await;

        let mut futs: Vec<_> = Default::default();
        for id in self.io.ids().iter() {
            if *id == self.party {
                continue;
            }
            let fut = async move {
                let recv_channel = self.io.channel(*id, self.party);
                let msg = recv_channel.recv().await;
                let other_pk_payload = PkPayload::from_bytes(&msg);
                let other_aux_pk = &committed_polys[id].commitments[0];
                let zk_verified = Self::dleq_verify(
                    &g, 
                    &other_pk_payload.pk, 
                    &self.h, 
                    other_aux_pk, 
                    &other_pk_payload.proof
                );
                if !zk_verified {
                    return None;
                }

                Some((*id, other_pk_payload.pk))
            };
            futs.push(fut);
        }

        let mut results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<u64, blst_p1>>();
        results.insert(self.party, *pk);
        if results.len() < self.io.ids().len() {
            Err(DvfError::InsufficientValidPks)
        }
        else {
            Ok(results)
        }
    }

    pub fn construct_group_key(&self, shares: &HashMap<u64, blst_scalar>) -> (blst_scalar, blst_p1) {
        let mut gsk = blst_scalar::default();
        for (_id, s) in shares.iter() {
            gsk = blst_scalar_add(&gsk, s);
        }
        let gpk = blst_sk_to_pk(&gsk);
        (gsk, gpk)
    }

    pub async fn exchange_group_public_keys(&self, 
        gpk: &blst_p1, 
        gsk: &blst_scalar, 
        committed_polys: &HashMap<u64, CommittedPoly>
    ) -> Result<HashMap<u64, blst_p1>, DvfError> {
        let g = fixed_p1_generator();
        let aux_gpk = blst_p1_mult(&self.h, gsk);
        let proof = Self::dleq_prove(&g, gpk, &self.h, &aux_gpk, gsk)?;
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

                let evals = committed_polys.iter()
                    .map(|(_, poly)| poly.eval(&u64_to_blst_scalar(*id)))
                    .collect::<Vec<blst_p1>>();
                let f = blst_p1s_add(&evals);

                let commit_verified = other_gpk_payload.aux_gpk == f;

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
        if results.len() < self.io.ids().len() {
            Err(DvfError::InsufficientValidPks)
        }
        else {
            Ok(results)
        }
    }

    pub fn dleq_prove(
        x1: &blst_p1, 
        y1: &blst_p1,
        x2: &blst_p1,
        y2: &blst_p1,
        alpha: &blst_scalar,
    ) -> Result<DleqProof, DvfError> {
        let y1_ = blst_p1_mult(x1, alpha);
        let y2_ = blst_p1_mult(x2, alpha);
        if y1_ != *y1 || y2_ != *y2 {
            return Err(DvfError::ZKProofInvalidInput);
        }
        let w = random_blst_scalar();
        let t1 = blst_p1_mult(x1, &w);
        let t2 = blst_p1_mult(x2, &w);
        let c = hash_points_to_blst_scalar([x1.clone(), y1.clone(), x2.clone(), y2.clone(), t1, t2].as_slice());
        let r = blst_scalar_sub(
            &w,
            &blst_scalar_mult(alpha, &c)
        );
        Ok(DleqProof {
            c,
            r,
        })
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

#[async_trait]
impl<T, U> DKGTrait for DKGMalicious<T, U> 
where 
    U: IOChannel + PrivateChannel,
    T: IOCommittee<U> {

    /// Returns:
    /// 1. Self's key pair
    /// 2. Master public key
    /// 3. A hashmap from a party's ID to its shared public key
    async fn run(&self) -> Result<(WrapKeypair, WrapPublicKey, HashMap<u64, WrapPublicKey>), DvfError> {
        let (kp, kps, _poly, committed_poly) = self.share_generation()?;
        let payloads: HashMap<u64, VssSharePayload> = self.share_transmission(&kps, &committed_poly).await?;
        let vrfy_result = self.share_verification(&payloads);
        let other_vrfy_results = self.exchange_verification_results(&vrfy_result).await;

        // Issue dispute claim if any verification fails
        let mut self_abort = false;
        for (id, valid) in vrfy_result.results.iter() {
            if *valid {
                continue;
            }
            self_abort = true;
            self.issude_dispute_claim(*id, payloads.get(&id).unwrap()).await?;
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
            .map(|(a, b, _c)| (a, b))
            .collect::<Vec<(u64, u64)>>();
        if valid_claims.len() > 0 {
            return Err(DvfError::InvalidDkgShare(valid_claims));
        }
        if self_abort {
            return Err(DvfError::VssShareVerificationFailed);
        }

        let mut committed_polys = HashMap::<u64, CommittedPoly>::default();
        committed_polys.insert(self.party, committed_poly);
        for (id, share) in payloads.iter() {
            committed_polys.insert(*id, share.committed_poly.clone());
        }
        
        // Derive master public key
        let self_pk = bytes_to_blst_p1(Bytes::copy_from_slice(kp.pk.serialize().as_slice()));
        let self_sk = blst_wrap_sk_to_blst_scalar(&kp.sk);
        let mut pks = self.exchange_public_keys(&self_pk, &self_sk, &committed_polys).await?;
        pks.insert(self.party, self_pk);
        let mpk = blst_p1s_add(&pks.into_values().collect::<Vec<blst_p1>>());

        // Derive group secret key and group public key 
        let mut shares = self.reveal_shares(&payloads);
        let self_share = blst_wrap_sk_to_blst_scalar(&kps[&self.party].sk);
        shares.insert(self.party, self_share);
        let (gsk, gpk) = self.construct_group_key(&shares);

        // Exchange and verify group public keys
        let gpks = self.exchange_group_public_keys(&gpk, &gsk, &committed_polys).await?;

        // Convert to desired structs
        let gsk = blst_scalar_to_blst_wrap_sk(&gsk);
        let gkp = WrapKeypair::from_components(gsk.public_key(), gsk);
        let mpk = blst_p1_to_blst_wrap_pk(&mpk);
        let gpks = gpks.iter()
            .map(|(id, gpk)| (*id, blst_p1_to_blst_wrap_pk(&gpk)))
            .collect::<HashMap<u64, WrapPublicKey>>();

        Ok((gkp, mpk, gpks))
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
    use crate::network::io_committee::{MemIOCommittee, NetIOCommittee, SecureNetIOCommittee};
    use crate::crypto::ThresholdSignature;
    use types::{Hash256}; 
    use eth2_hashing::{Context, Sha256Context};
    use futures::future::join_all;
    use futures::executor::block_on;
    use bls::{Keypair, Signature, PublicKey};
    use std::net::SocketAddr;
    use std::collections::HashMap;

    const T: usize = 3;
    const IDS: [u64; 4] = [1, 2, 3, 4];

    fn verify_dkg_results(results: HashMap<u64, (Keypair, PublicKey, HashMap<u64, PublicKey>)>) {
        // Verify master public keys
        for i in 1..IDS.len() {
            assert_eq!(results[&IDS[i]].1, results[&IDS[0]].1, "Master public keys are not the same");
        }

        // Sign something with the shared keys
        let kps: Vec<Keypair> = IDS.iter().map(|id| results[id].0.clone()).collect();
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
        let m_threshold = ThresholdSignature::new(T);
        let agg_sig = m_threshold.threshold_aggregate(&sigs_ref[..], &pks[..], &IDS[..], message).unwrap();

        // Verification with the master public key
        let status1 = agg_sig.verify(&results[&IDS[0]].1, message);

        assert!(status1, "Signature verification failed");
    }

    #[test]
    fn test_dkg() {
        // Use dkg to generate secret-shared keys
        let io = &Arc::new(MemIOCommittee::new(IDS.as_slice()));
        let futs = IDS.iter().map(|id| async move {
            let dkg = DKGSemiHonest::new(*id, io.clone(), T);
            let result = dkg.run().await;
            match result {
                Ok(v) => Ok((*id, v)),
                Err(e) => {
                    println!("Error in Dkg of party {}: {:?}", id, e);
                    Err(e)
                }
            }
        });

        let results = block_on(join_all(futs))
            .into_iter()
            .flatten()
            .collect::<HashMap<u64, (Keypair, PublicKey, HashMap<u64, PublicKey>)>>();
        
        verify_dkg_results(results);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_net() {
        let ports: Vec<u16> = IDS.iter().map(|id| (25000 + *id) as u16).collect();
        let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

        let ports_ref = &ports;
        let addrs_ref = &addrs;
        // Use dkg to generate secret-shared keys
        let futs = (0..IDS.len()).map(|i| async move {
            let io = &Arc::new(NetIOCommittee::new(IDS[i], ports_ref[i], IDS.as_slice(), addrs_ref.as_slice()).await);
            let dkg = DKGSemiHonest::new(IDS[i], io.clone(), T);
            let result = dkg.run().await;
            match result {
                Ok(v) => Ok((IDS[i], v)),
                Err(e) => {
                    println!("Error in Dkg of party {}: {:?}", IDS[i], e);
                    Err(e)
                }
            }
        });

        let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<u64, (Keypair, PublicKey, HashMap<u64, PublicKey>)>>();
        
        verify_dkg_results(results);
    }
    

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_secure_net() {
        println!("enter test_dkg_secure_net");
        let ports: Vec<u16> = IDS.iter().map(|id| (25000 + *id) as u16).collect();
        let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

        let ports_ref = &ports;
        let addrs_ref = &addrs;
        // Use dkg to generate secret-shared keys
        let futs = (0..IDS.len()).map(|i| async move {
            println!("Enter thread for party {}", IDS[i]);
            let io = &Arc::new(SecureNetIOCommittee::new(IDS[i], ports_ref[i], IDS.as_slice(), addrs_ref.as_slice()).await);
            let dkg = DKGMalicious::new(IDS[i], io.clone(), T);
            let result = dkg.run().await;
            match result {
                Ok(v) => Ok((IDS[i], v)),
                Err(e) => {
                    println!("Error in Dkg of party {}: {:?}", IDS[i], e);
                    Err(e)
                }
            }
        });
        println!("after constructing futures");

        let results = join_all(futs)
            .await
            .into_iter()
            .flatten()
            .collect::<HashMap<u64, (Keypair, PublicKey, HashMap<u64, PublicKey>)>>();
        println!("after joining futures");
        
        verify_dkg_results(results);
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_dkg_sig_net() {
        let ports: Vec<u16> = IDS.iter().map(|id| (25000 + *id) as u16).collect();
        let addrs: Vec<SocketAddr> = ports.iter().map(|port| SocketAddr::new("127.0.0.1".parse().unwrap(), *port)).collect();

        let message = "hello world";
        let mut context = Context::new();
        context.update(message.as_bytes());
        let message = Hash256::from_slice(&context.finalize());

        let ports_ref = &ports;
        let addrs_ref = &addrs;
        // Use dkg to generate secret-shared keys
        let futs = (0..IDS.len()).map(|i| async move {
            let io = &Arc::new(NetIOCommittee::new(IDS[i], ports_ref[i], IDS.as_slice(), addrs_ref.as_slice()).await);
            let dkg = DKGSemiHonest::new(IDS[i], io.clone(), T);
            let (kp, mpk, pks) = dkg.run().await?;

            // Sign with dkg result
            let signer = SimpleDistributedSigner::new(IDS[i], kp, mpk.clone(), pks, io.clone(), T);
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