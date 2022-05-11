use environment::RuntimeContext;
use types::EthSpec;
use crate::validation::ProductionValidatorClient;
use super::validator_files::ValidatorFiles;

pub use beacon_node::{ClientConfig, ClientGenesis, ProductionClient};
pub use environment;
pub use eth2;
use crate::simulator::ValidatorConfig;

/// Provides a validator client that is running in the current process on a given tokio executor (it
/// is _local_ to this process).
///
/// Intended for use in testing and simulation. Not for production.
pub struct LocalValidatorClient<T: EthSpec> {
    pub client: ProductionValidatorClient<T>,
    pub files: ValidatorFiles,
}

impl<E: EthSpec> LocalValidatorClient<E> {
    /// Creates a validator client with insecure deterministic keypairs. The validator directories
    /// are created in a temp dir then removed when the process exits.
    ///
    /// The validator created is using the same types as the node we use in production.
    pub async fn production_with_insecure_keypairs(
        context: RuntimeContext<E>,
        config: ValidatorConfig,
        files: ValidatorFiles,
    ) -> Result<Self, String> {
        Self::new(context, config, files).await
    }

    /// Creates a validator client that attempts to read keys from the default data dir.
    ///
    /// - The validator created is using the same types as the node we use in production.
    /// - It is recommended to use `production_with_insecure_keypairs` for testing.
    pub async fn production(
        context: RuntimeContext<E>,
        config: ValidatorConfig,
    ) -> Result<Self, String> {
        let files = ValidatorFiles::new()?;

        Self::new(context, config, files).await
    }

    async fn new(
        context: RuntimeContext<E>,
        mut config: ValidatorConfig,
        files: ValidatorFiles,
    ) -> Result<Self, String> {
        config.validator_dir = files.validator_dir.path().into();
        config.secrets_dir = files.secrets_dir.path().into();

        ProductionValidatorClient::new(context, config)
            .await
            .map(move |mut client| {
                client
                    .start_service()
                    .expect("should start validator services");
                Self { client, files }
            })
    }
}
