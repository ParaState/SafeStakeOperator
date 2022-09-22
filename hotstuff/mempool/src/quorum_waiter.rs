use crate::config::{Committee, Stake};
use crate::processor::SerializedBatchMessage;
use crypto::PublicKey;
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use network::CancelHandler;
use tokio::sync::mpsc::{Receiver, Sender};
use utils::monitored_channel::MonitoredSender;

#[cfg(test)]
#[path = "tests/quorum_waiter_tests.rs"]
pub mod quorum_waiter_tests;

#[derive(Debug)]
pub struct QuorumWaiterMessage {
    /// A serialized `MempoolMessage::Batch` message.
    pub batch: SerializedBatchMessage,
    /// The cancel handlers to receive the acknowledgements of our broadcast.
    pub handlers: Vec<(PublicKey, CancelHandler)>,
}

/// The QuorumWaiter waits for 2f authorities to acknowledge reception of a batch.
pub struct QuorumWaiter {
    /// The committee information.
    committee: Committee,
    /// The stake of this authority.
    stake: Stake,
    /// Input Channel to receive commands.
    rx_message: Receiver<QuorumWaiterMessage>,
    /// Channel to deliver batches for which we have enough acknowledgements.
    tx_batch: MonitoredSender<SerializedBatchMessage>,
    exit: exit_future::Exit
}

impl QuorumWaiter {
    /// Spawn a new QuorumWaiter.
    pub fn spawn(
        committee: Committee,
        stake: Stake,
        rx_message: Receiver<QuorumWaiterMessage>,
        tx_batch: MonitoredSender<Vec<u8>>,
        exit: exit_future::Exit
    ) {
        tokio::spawn(async move {
            Self {
                committee,
                stake,
                rx_message,
                tx_batch,
                exit
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let result = wait_for.await;
        if let Ok(ack) = result {
            if ack == "Ack" {
                deliver
            }
            else {
                // Not a normal ack. Something is wrong.
                0
            }
        }
        else {
            0
        }
    }

    /// Main loop.
    async fn run(&mut self) {
        loop {
            let exit = self.exit.clone();
            tokio::select! {
                Some(QuorumWaiterMessage { batch, handlers }) = self.rx_message.recv() => {
                    let mut wait_for_quorum: FuturesUnordered<_> = handlers
                        .into_iter()
                        .map(|(name, handler)| {
                            let stake = self.committee.stake(&name);
                            Self::waiter(handler, stake)
                        })
                        .collect();
        
                    // Wait for the first 2f nodes to send back an Ack. Then we consider the batch
                    // delivered and we send its digest to the consensus (that will include it into
                    // the dag). This should reduce the amount of synching.
                    let mut total_stake = self.stake;
                    
                    'wait: loop {
                        let inner_exit = self.exit.clone();
                        tokio::select! {
                            result = wait_for_quorum.next() => {
                                match result {
                                    Some(stake) => {
                                        total_stake += stake;
                                        if total_stake >= self.committee.quorum_threshold() {
                                            self.tx_batch
                                                .send(batch)
                                                .await
                                                .expect("Failed to deliver batch");
                                            break 'wait;
                                        }
                                    }
                                    None => {
                                        break 'wait;
                                    }
                                }
                            },
                            () = inner_exit => {
                                break 'wait;
                            }
                        }
                    }
                },
                () = exit => {
                    break;
                }
            }
        }
    }
}
