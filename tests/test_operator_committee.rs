use dvf::validation::{OperatorCommittee};
use dvf::validation::operator::{LocalOperator};
use dvf::crypto::{ThresholdSignature};
use std::sync::Arc;
use types::Hash256;
use eth2_hashing::{Context, Sha256Context};

#[cfg(feature = "fake_committee")]
#[test]
fn test_fake_operator_committee() {
    let t: usize = 5;
    let n: usize = 10;

    let mut m_threshold = ThresholdSignature::new(t);
    let (kp, kps, ids) = m_threshold.key_gen(n);

    let mut committee = OperatorCommittee::new(0, kp.pk.clone(), t);
    for i in 0..n {
        let operator = Arc::new(
            RwLock::new(LocalOperator::new(ids[i], Arc::new(kps[i].clone()))));  
        committee.add_operator(ids[i], operator);
    }

    let message = "hello world";
    let mut context = Context::new();
    context.update(message.as_bytes());
    let message = Hash256::from_slice(&context.finalize());

    let sig1 = committee.sign(message).unwrap();
    let sig2 = kp.sk.sign(message);

    let status1 = sig1.verify(&kp.pk, message);
    let status2 = sig2.verify(&kp.pk, message);

    assert!(status1, "Signature verification failed");
    assert!(status2, "Aggregate signature verification failed");
    assert_eq!(sig1, sig2, "Signature not match");

    //let a = Arc<RwLock<dyn TOperator>>> = Arc::new(RwLock::new(
            //LocalOperator::from_keypair(Arc::new(kps[0].clone()))));
}
