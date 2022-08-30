use crate::config::Committee;
use crate::consensus::ConsensusMessage;
use bytes::Bytes;
use crypto::{Digest, PublicKey};
use log::{warn, debug, info};
use network::{SimpleSender, DvfMessage};
use store::Store;
use tokio::sync::mpsc::Receiver;

#[cfg(test)]
#[path = "tests/helper_tests.rs"]
pub mod helper_tests;

/// A task dedicated to help other authorities by replying to their sync requests.
pub struct Helper {
    /// The committee information.
    committee: Committee,
    /// The persistent storage.
    store: Store,
    /// Input channel to receive sync requests.
    rx_requests: Receiver<(Digest, PublicKey)>,
    /// A network sender to reply to the sync requests.
    network: SimpleSender,
    validator_id: u64,
    exit: exit_future::Exit
}

impl Helper {
    pub fn spawn(committee: Committee, store: Store, rx_requests: Receiver<(Digest, PublicKey)>, validator_id: u64, exit: exit_future::Exit) {
        tokio::spawn(async move {
            Self {
                committee,
                store,
                rx_requests,
                network: SimpleSender::new(),
                validator_id,
                exit
            }
            .run()
            .await;
        });
    }

    async fn run(&mut self) {
        loop {
            let exit = self.exit.clone();
            tokio::select! {
                Some((digest, origin)) = self.rx_requests.recv() => {
                    // TODO [issue #58]: Do some accounting to prevent bad nodes from monopolizing our resources.

                    // get the requestors address.
                    let address = match self.committee.address(&origin) {
                        Some(x) => x,
                        None => {
                            warn!("Received sync request from unknown authority: {}", origin);
                            continue;
                        }
                    };
                    debug!("[VA {}] Received sync request {}", self.validator_id, digest);
                    // Reply to the request (if we can).
                    if let Some(bytes) = self
                        .store
                        .read(digest.to_vec())
                        .await
                        .expect("Failed to read from storage")
                    {
                        debug!("[VA {}] Found {}", self.validator_id, digest);
                        let block =
                            bincode::deserialize(&bytes).expect("Failed to deserialize our own block");
                        let message = bincode::serialize(&ConsensusMessage::Propose(block))
                            .expect("Failed to serialize block");
                        let dvf_message = DvfMessage { validator_id: self.validator_id, message: message};
                        let serialized_msg = bincode::serialize(&dvf_message).unwrap();
                        debug!("[HELPER] Sending to {:?}", address);
                        self.network.send(address, Bytes::from(serialized_msg)).await;
                    }
                },
                () = exit => {
                    break;
                }
            }
        }
    }
}
