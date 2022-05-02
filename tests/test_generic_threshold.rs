use dvf::crypto::{ThresholdSignature};
use lighthouse_bls::{Signature, PublicKey, SecretKey};
use types::{Hash256}; 
use std::str::FromStr;
use eth2_hashing::{Context, Sha256Context};

#[test]
fn test_generic_threshold() {
    let t = 5;
    let n = 10;
    let mut m_threshold = ThresholdSignature::new(t);
    let (kp, mut kps, mut ids) = m_threshold.key_gen(n);
    
    let pks: Vec<&PublicKey> = kps.iter().map(|p| &p.pk).collect();
    let message = "hello world";
    let mut context = Context::new();
    context.update(message.as_bytes());
    let message = Hash256::from_slice(&context.finalize());

    let mut sigs: Vec<Signature> = Vec::new();
    for i in 0..n {
        sigs.push(kps[i].sk.sign(message));
    }
    let sigs_ref: Vec<&Signature> = sigs.iter().map(|s| s).collect();
    //let pks_ref: Vec<&PublicKey> = pks.iter().map(|s| s).collect();
    let mut agg_sig = m_threshold.threshold_aggregate(&sigs_ref[..], &pks[..], &ids[..], message).unwrap();

    let mut sig = kp.sk.sign(message);

    let status1 = agg_sig.verify(&kp.pk, message);
    let status2 = sig.verify(&kp.pk, message);
    
    assert!(status1, "Signature verification failed");
    assert!(status2, "Aggregate signature verification failed");
    assert_eq!(agg_sig, sig, "Signature not match");
}
