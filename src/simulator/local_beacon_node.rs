use beacon_node::ProductionBeaconNode;
use environment::RuntimeContext;
use eth2::{reqwest::ClientBuilder, BeaconNodeHttpClient, Timeouts};
use sensitive_url::SensitiveUrl;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::{Builder as TempBuilder, TempDir};
use types::EthSpec;

pub use beacon_node::{ClientConfig, ClientGenesis, ProductionClient};
pub use environment;
pub use eth2;


/// The global timeout for HTTP requests to the beacon node.
const HTTP_TIMEOUT: Duration = Duration::from_secs(4);

/// Provides a beacon node that is running in the current process on a given tokio executor (it
/// is _local_ to this process).
///
/// Intended for use in testing and simulation. Not for production.
pub struct LocalBeaconNode<E: EthSpec> {
    pub client: ProductionClient<E>,
    pub datadir: TempDir,
}

impl<E: EthSpec> LocalBeaconNode<E> {
    /// Starts a new, production beacon node on the tokio runtime in the given `context`.
    ///
    /// The node created is using the same types as the node we use in production.
    pub async fn production(
        context: RuntimeContext<E>,
        mut client_config: ClientConfig,
    ) -> Result<Self, String> {
        // Creates a temporary directory that will be deleted once this `TempDir` is dropped.
        let datadir = TempBuilder::new()
            .prefix("lighthouse_node_test_rig")
            .tempdir()
            .expect("should create temp directory for client datadir");

        client_config.data_dir = datadir.path().into();
        client_config.network.network_dir = PathBuf::from(datadir.path()).join("network");

        ProductionBeaconNode::new(context, client_config)
            .await
            .map(move |client| Self {
                client: client.into_inner(),
                datadir,
            })
    }
}

impl<E: EthSpec> LocalBeaconNode<E> {
    /// Returns a `RemoteBeaconNode` that can connect to `self`. Useful for testing the node as if
    /// it were external this process.
    pub fn remote_node(&self) -> Result<BeaconNodeHttpClient, String> {
        let listen_addr = self
            .client
            .http_api_listen_addr()
            .ok_or("A remote beacon node must have a http server")?;

        let beacon_node_url: SensitiveUrl = SensitiveUrl::parse(
            format!("http://{}:{}", listen_addr.ip(), listen_addr.port()).as_str(),
        )
        .map_err(|e| format!("Unable to parse beacon node URL: {:?}", e))?;
        let beacon_node_http_client = ClientBuilder::new()
            .timeout(HTTP_TIMEOUT)
            .build()
            .map_err(|e| format!("Unable to build HTTP client: {:?}", e))?;
        Ok(BeaconNodeHttpClient::from_components(
            beacon_node_url,
            beacon_node_http_client,
            Timeouts::set_all(HTTP_TIMEOUT),
        ))
    }
}
