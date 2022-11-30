use types::EthSpec;
use bls::{Hash256, Signature, SignatureBytes, PublicKeyBytes};
use types::{DepositData};
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
        amount,
        signature: Signature::empty().into(),
    };
    let spec = E::default_spec();
    let domain = spec.get_deposit_domain();
    let msg = deposit_data.as_deposit_message().signing_root(domain);

    let sig = signer.sign(msg).await?;
    deposit_data.signature = SignatureBytes::from(sig);

    Ok(deposit_data)
}