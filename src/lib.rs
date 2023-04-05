use std::net::{SocketAddr, IpAddr, Ipv4Addr};
use lazy_static::lazy_static;

#[macro_use]
extern crate downcast_rs;
pub mod crypto;
pub mod math;
pub mod utils;
pub mod simulator;
pub mod validation;
pub mod node;
pub mod test_utils;
pub mod network;
pub mod deposit;

pub const DEFAULT_CHANNEL_CAPACITY: usize = 1_000;
lazy_static!{
    // [Issue] SocketAddr::new is not yet a const fn in stable release.
    // Can change this variable to const once it becomes stable.
    // Tracking issue: https://doc.rust-lang.org/std/net/enum.SocketAddr.html#method.new
    pub static ref INVALID_ADDR: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 0);
}

pub fn invalid_addr() -> SocketAddr {
    return *INVALID_ADDR;
}

pub fn is_addr_invalid(addr: SocketAddr) -> bool {
    if addr == *INVALID_ADDR {
        return true;
    }
    return false;
}


