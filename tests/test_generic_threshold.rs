use dvf::crypto::{ThresholdSignature};
use bls::{Signature, PublicKey};
use types::{Hash256}; 
use ethereum_hashing::{Context, Sha256Context};

#[test]
fn test_generic_threshold() {
    let t = 5;
    let n = 10;
    let mut m_threshold = ThresholdSignature::new(t);
    let ids = (1..n+1).map(|k| k as u64).collect::<Vec<u64>>();
    let (kp, kps) = m_threshold.key_gen(&ids).unwrap();
    
    let pks: Vec<&PublicKey> = ids.iter().map(|id| &kps[id].pk).collect();
    let message = "hello world";
    let mut context = Context::new();
    context.update(message.as_bytes());
    let message = Hash256::from_slice(&context.finalize());

    let mut sigs: Vec<Signature> = Vec::new();
    for id in ids.iter() {
        sigs.push(kps[id].sk.sign(message));
    }
    let sigs_ref: Vec<&Signature> = sigs.iter().map(|s| s).collect();
    //let pks_ref: Vec<&PublicKey> = pks.iter().map(|s| s).collect();
    let agg_sig = m_threshold.threshold_aggregate(&sigs_ref[..], &pks[..], &ids[..], message).unwrap();

    let sig = kp.sk.sign(message);

    let status1 = agg_sig.verify(&kp.pk, message);
    let status2 = sig.verify(&kp.pk, message);
    
    assert!(status1, "Signature verification failed");
    assert!(status2, "Aggregate signature verification failed");
    assert_eq!(agg_sig, sig, "Signature not match");
}
