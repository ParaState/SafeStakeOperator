use crate::config::Committee;
use bytes::Bytes;
use crypto::{Digest, PublicKey};
use log::{error, warn};
use network::{SimpleSender, DvfMessage};
use store::Store;
use tokio::sync::mpsc::Receiver;

#[cfg(test)]
#[path = "tests/helper_tests.rs"]
pub mod helper_tests;

/// A task dedicated to help other authorities by replying to their batch requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive batch requests.
    rx_request: Receiver<(Vec<Digest>, PublicKey)>,
    /// A network sender to send the batches to the other mempools.
    network: SimpleSender,
    validator_id: u64
}

impl Helper {
    pub fn spawn(
        committee: Committee,
        store: Store,
        rx_request: Receiver<(Vec<Digest>, PublicKey)>,
        validator_id: u64
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                store,
                rx_request,
                network: SimpleSender::new(),
                validator_id: validator_id
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        while let Some((digests, origin)) = self.rx_request.recv().await {
            // TODO [issue #7]: Do some accounting to prevent bad nodes from monopolizing our resources.

            // get the requestors address.
            let address = match self.committee.mempool_address(&origin) {
                Some(x) => x,
                None => {
                    warn!("Received batch request from unknown authority: {}", origin);
                    continue;
                }
            };

            // Reply to the request (the best we can).
            for digest in digests {
                match self.store.read(digest.to_vec()).await {
                    Ok(Some(data)) => {
                        let dvf_message = DvfMessage { validator_id: self.validator_id, message: data};
                        let serialized_msg = bincode::serialize(&dvf_message).unwrap();
                        self.network.send(address, Bytes::from(serialized_msg)).await
                    },
                    Ok(None) => (),
                    Err(e) => error!("{}", e),
                }
            }
        }
    }
}
