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
    /// Error propogated from Store
    StoreError(String),
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
    /// Socket address is not available
    SocketAddrUnknown,
    /// Validator store is not construted yet
    ValidatorStoreNotReady,
    /// Unknown error
    Unknown,
    /// BeaconNode client error
    BeaconNodeClientError,
    /// Get beacon genesis error
    BeaconNodeGenesisError,
    /// Get beacon validator data error
    BeaconNodeValidatorError(String),
    /// Get beacon state fork error
    BeaconNodeStateForkError(String)
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