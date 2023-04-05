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
