use crypto::Digest;
use ed25519_dalek::Digest as _;
use ed25519_dalek::Sha512;
use std::convert::TryInto;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use log::{info};

#[cfg(test)]
#[path = "tests/processor_tests.rs"]
pub mod processor_tests;

/// Indicates a serialized `MempoolMessage::Batch` message.
pub type SerializedBatchMessage = Vec<u8>;

/// Hashes and stores batches, it then outputs the batch's digest.
pub struct Processor;

impl Processor {
    pub fn spawn(
        // The persistent storage.
        store: Store,
        // Input channel to receive batches.
        mut rx_batch: Receiver<SerializedBatchMessage>,
        // Output channel to send out batches' digests.
        tx_digest: Sender<Digest>,
        exit: exit_future::Exit
    ) {
        tokio::spawn(async move {
            loop {
                let exit = exit.clone();
                tokio::select! {
                    Some(batch) = rx_batch.recv() => {
                        let digest = Digest(Sha512::digest(&batch).as_slice()[..32].try_into().unwrap());

                        // Store the batch.
                        store.write(digest.to_vec(), batch).await;

                        tx_digest.send(digest.clone()).await.expect("Failed to send digest");
                        info!("============= Mempool processor sends a digest: {:?}", digest);
                    },
                    () = exit => {
                        break;
                    }
                }
            }
        });
    }
}
