use clap::Parser;
use serde::{Deserialize, Serialize};
use validator_client::cli::ValidatorClient;

#[derive(Parser, Clone, Deserialize, Serialize, Debug)]
pub enum LighthouseSubcommands {
    #[clap(name = "validator_client")]
    ValidatorClient(Box<ValidatorClient>),
}
