
/// Up to 1 million
/// !NOTE: Don't change this unless you know want you are doing. We relate this to the database storage path of dvf.
/// Changing this might essentially have the effect of cleaning all data.
pub const ROOT_VERSION: u64 = 1;
/// Up to 1 million
pub const MAJOR_VERSION: u64 = 2;
/// Up to 1 million
pub const MINOR_VERSION: u64 = 0;

pub static VERSION: u64 = ROOT_VERSION * 1000_000_000_000 + MAJOR_VERSION * 1000_000 + MINOR_VERSION;