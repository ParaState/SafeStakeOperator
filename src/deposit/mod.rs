use types::EthSpec;
use bls::{Hash256, Signature, SignatureBytes, PublicKeyBytes};
use types::DepositData;
use crate::utils::error::DvfError;
use crate::crypto::dkg::SimpleDistributedSigner;
use crate::network::io_committee::{IOCommittee, IOChannel};
use types::SignedRoot;


/// Refer to `/lighthouse/common/deposit_contract/src/lib.rs`
pub async fn get_distributed_deposit<T: IOCommittee<U>, U: IOChannel, E: EthSpec>(
    signer: &SimpleDistributedSigner<T, U>,
    withdrawal_credentials: &[u8; 32],
    amount: u64,
) -> Result<DepositData, DvfError> {
    let mut deposit_data = DepositData {
        pubkey: PublicKeyBytes::from(signer.mpk()),
        withdrawal_credentials: Hash256::from_slice(withdrawal_credentials),
        amount: amount,
        signature: Signature::empty().into(),
    };
    let mut spec = E::default_spec();
    spec.genesis_fork_version = [00, 00, 16, 32];
    let domain = spec.get_deposit_domain();
    let msg = deposit_data.as_deposit_message().signing_root(domain);

    let sig = signer.sign(msg).await?;
    deposit_data.signature = SignatureBytes::from(sig);

    Ok(deposit_data)
}

#[test]
pub fn get_deposit_test() {
    let sk = bls::SecretKey::deserialize(&hex::decode("12a660e5a304e3386c0fff53ced385faa25e305cc047aaac0b446f0c2053d4be").unwrap()).unwrap();
    let pk = sk.public_key();
    assert_eq!("0x9200c374d5349e7aa3c145c5f6cb7e973a7257277e0e2024d48318cb8a6d6ca105b517346d9915aed8835defd94b6b5e", pk.as_hex_string());
    let mut deposit_data = DepositData {
        pubkey: pk.into(),
        withdrawal_credentials: Hash256::from_slice(&hex::decode("00076bd8b841544ab6335ae084849141dfd84155a1980d178ac1b96ef1040915").unwrap()),
        amount: 32000000000,
        signature: Signature::empty().into()
    };
    type E = types::MinimalEthSpec;
    let mut spec = E::default_spec().clone();
    spec.genesis_fork_version = [00,00,16,32];
    println!("{:?}", spec.genesis_fork_version);
    deposit_data.signature = deposit_data.create_signature(&sk, &spec);
    println!("{:?}", deposit_data.signature);
}