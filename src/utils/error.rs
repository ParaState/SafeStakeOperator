
pub fn require(status: bool, msg: &'static str) {
    if !status {
        panic!("{}", msg);
    }
}
