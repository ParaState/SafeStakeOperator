use bls::Error as BlsError;
use blst::BLST_ERROR as BlstError;

pub fn require(status: bool, msg: &'static str) {
    if !status {
        panic!("{}", msg);
    }
}


#[derive(Clone, Debug, PartialEq)]
pub enum DvfError {
    BlsError(BlsError),
    BlstError(BlstError),
    /// The consensus protocol failed.
    ConsensusFailure(String),
    /// Key generation failed.
    KeyGenError(String),
    /// Threshold signature aggregation failed due to insufficient valid signatures.
    InsufficientSignatures {got: usize, expected: usize},
    /// Threshold signature aggregation failed due to insufficient valid signatures.
    InsufficientValidSignatures {got: usize, expected: usize},
    /// Invalid operator signature
    InvalidSignatureShare {id: u64},
    /// Invalid operator id 
    InvalidOperatorId {id: u64},
    /// Different length
    DifferentLength {x: usize, y: usize},
    /// 
    InvalidLength,
    /// Should not call the function specified by the string
    UnexpectedCall(String),
    /// Vss share verification
    VssShareVerificationFailed,
    /// Dispute claim
    InvalidDkgShare(Vec<(u64, u64)>),
    /// Commitment
    CommitmentVerificationFailed,
    /// Zero knowledge proof
    ZKProofInvalidInput,
    /// Zero knowledge proof verification
    ZKVerificationFailed,
    InsufficientValidPks,
    /// Unknown error
    Unknown
}

impl From<BlsError> for DvfError {
    fn from(e: BlsError) -> DvfError {
        DvfError::BlsError(e)
    }
}

impl From<BlstError> for DvfError {
    fn from(e: BlstError) -> DvfError {
        DvfError::BlstError(e)
    }
}