use types::{Hash256, Signature, Keypair, PublicKey};
use std::sync::Arc;
use crate::utils::error::DvfError;

pub trait TOperator: Sync + Send {
    fn sign(&self, msg: Hash256) -> Signature; 
    fn public_key(&self) -> Result<&PublicKey, DvfError>;
}

pub struct LocalOperator {
    pub voting_keypair: Arc<Keypair>
}

impl TOperator for LocalOperator {

    fn sign(&self, msg: Hash256) -> Signature {
        self.voting_keypair.sk.sign(msg)
    }

    fn public_key(&self) -> Result<&PublicKey, DvfError> {
        Ok(&self.voting_keypair.pk)
    }
}

impl LocalOperator {
    pub fn from_keypair(keypair: Arc<Keypair>) -> Self {
        Self {
            voting_keypair: keypair
        }
    }
}

pub struct RemoteOperator {
    // [Zico]TODO: to be updated
    pub voting_keypair: Arc<Keypair>
}

impl TOperator for RemoteOperator {
    fn sign(&self, msg: Hash256) -> Signature { 
        // [Zico]TODO: request remote operator to sign and return the signature
        self.voting_keypair.sk.sign(msg)
    }

    fn public_key(&self) -> Result<&PublicKey, DvfError> {
        Err(DvfError::Unknown)  
    }
}

