use std::path::PathBuf;
use lighthouse_directory::{
    get_network_dir, DEFAULT_ROOT_DIR
};
use dvf_version::ROOT_VERSION;
use clap::ArgMatches;

pub fn get_default_base_dir(cli_args: &ArgMatches) -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(|| PathBuf::from("."))
        .join(DEFAULT_ROOT_DIR)
        .join(format!("v{}", ROOT_VERSION))
        .join(get_network_dir(cli_args))
}