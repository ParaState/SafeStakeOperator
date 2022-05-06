//use miracl_core::bls12381::bls::{BLS_OK}; 
//use dvf::crypto::bls::{Bls};
//use dvf::crypto::threshold::{ThresholdBls};
//use dvf::crypto::define::{MB};


//#[test]
//fn test_threshold() {
    //let t = 5;
    //let n = 10;
    //let mut m_threshold = ThresholdBls::new(t, n);
    //let mut sk_shares = vec![[0 as u8; MB]; n]; 
    //let mut ids = vec![0; n];
    //m_threshold.generate(&mut sk_shares, &mut ids);
    
    //let mut bls_shares: Vec<Bls> = sk_shares.iter().map(|sk| Bls::from_sk(sk)).collect();
    //let pks: Vec<[u8; 2*MB+1]> = bls_shares.iter().map(|signer| signer.pk).collect();
    //let message = "hello world";

    //let mut sigs = vec![[0 as u8; MB+1]; n];
    //for i in 0..n {
        //bls_shares[i].sign(&mut sigs[i], message.as_bytes());
    //}
    //let mut agg_sig: [u8; MB+1] = [0; MB+1];
    //m_threshold.aggregate(&mut agg_sig, &pks, &sigs, &ids, message.as_bytes());

    //let mut sig: [u8; MB+1] = [0; MB+1];
    //m_threshold.master_bls.sign(&mut sig, message.as_bytes());

    //let status1 = m_threshold.master_bls.verify(&sig, message.as_bytes());
    //let status2 = m_threshold.master_bls.verify(&agg_sig, message.as_bytes());
    
    //assert_eq!(status1, BLS_OK, "Signature verification failed");
    //assert_eq!(status2, BLS_OK, "Aggregate signature verification failed");
    //assert_eq!(agg_sig, sig, "Signature not match");
//}

//#[test]
//fn test_recover_sk() {
    //let t = 5;
    //let n = 10;
    //let mut m_threshold = ThresholdBls::new(t, n);
    //let mut sk_shares = vec![[0 as u8; MB]; n]; 
    //let mut ids = vec![0; n];
    //m_threshold.generate(&mut sk_shares, &mut ids);

    //let mut sk = [0 as u8; MB];
    //m_threshold.recover_sk(&mut sk, &sk_shares, &ids);

    //assert_eq!(sk, m_threshold.master_bls.sk, "Faile to recover key");
//}

