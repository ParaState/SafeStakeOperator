use clap::ArgMatches;
use clap_utils::parse_required;
use directory::DEFAULT_ROOT_DIR;
use dvf_utils::ROOT_VERSION;
use serde::{Deserialize, Serialize};
use slog::{info, Logger};
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Config {
    pub ip: IpAddr,
    pub port: u16,
    pub root_dir: PathBuf,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip: IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            port: 9005,
            root_dir: dirs::home_dir()
                .unwrap_or_else(|| PathBuf::from("."))
                .join(DEFAULT_ROOT_DIR)
                .join(format!("v{}", ROOT_VERSION))
                .join("mainnet"),
        }
    }
}

impl Config {
    pub fn from_cli(cli_args: &ArgMatches, log: &Logger) -> Result<Config, String> {
        let mut config = Config::default();
        config.ip = parse_required(cli_args, "ip")?;
        info!(log, "read operator ip"; "operator ip" => %config.ip);

        config.port = parse_required(cli_args, "port")?;
        info!(log, "read port"; "port" => config.port);

        config.root_dir = dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(DEFAULT_ROOT_DIR)
            .join(format!("v{}", ROOT_VERSION));

        Ok(config)
    }
}
