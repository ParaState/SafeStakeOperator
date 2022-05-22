
pub fn require(status: bool, msg: &'static str) {
    if !status {
        panic!("{}", msg);
    }
}


#[derive(Clone, Debug, PartialEq)]
pub enum DvfError {
    /// The consensus protocol failed.
    ConsensusFailure,
    /// Threshold signature aggregation failed due to insufficient valid signatures.
    InsufficientSignatures {got: usize, expected: usize},
    /// Invalid operator signature
    InvalidSignatureShare {id: u64},
    /// Different length
    DifferentLength {x: usize, y: usize},
    /// 
    InvalidLength,
    ///
    Unknown
}
