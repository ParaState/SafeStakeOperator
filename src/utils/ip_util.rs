use std::io::{stdout, Write};
use std::net::{IpAddr, UdpSocket};
use std::process::Command;

use tracing::log::{error, log};
use tracing::{info, log, warn};

pub fn get_public_ip() -> String {
    let output = Command::new("curl")
        .arg("ifconfig.me")
        .output()
        .expect("failed to execute process");

    String::from_utf8_lossy(&output.stdout).to_string()
}

pub fn get_local_ip() -> String {
    let socket = UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect("8.8.8.8:80").unwrap();
    let local_addr = socket.local_addr().unwrap();
    let ip = local_addr.ip();
    match ip {
        IpAddr::V4(ipv4) => ipv4.to_string(),
        IpAddr::V6(ipv6) => ipv6.to_string(),
    }
}

/// tracing_test https://docs.rs/tracing-test/latest/tracing_test/
/// https://stackoverflow.com/questions/72884779/how-to-print-tracing-output-in-tests
#[cfg(test)]
mod tests {
    use tracing::debug;
    use tracing_test::traced_test;

    // Note this useful idiom: importing names from outer (for mod tests) scope.
    use super::*;

    #[traced_test]
    #[test]
    fn test_get_pub_ip() {
        debug!("{}", get_public_ip());
        debug!("{}", get_local_ip());
    }
}
