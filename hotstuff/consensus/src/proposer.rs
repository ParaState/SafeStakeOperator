use crate::config::{Committee, Stake};
use crate::consensus::{ConsensusMessage, Round};
use crate::messages::{Block, QC, TC};
use bytes::Bytes;
use crypto::{Digest, PublicKey, SignatureService};
use futures::stream::futures_unordered::FuturesUnordered;
use futures::stream::StreamExt as _;
use log::{debug, info};
use network::{CancelHandler, ReliableSender, DvfMessage};
use std::collections::HashSet;
use tokio::sync::mpsc::{Receiver, Sender};
use crypto::Hash;

#[derive(Debug)]
pub enum ProposerMessage {
    Make(Round, QC, Option<TC>),
    Cleanup(Vec<Digest>),
}

pub struct Proposer {
    name: PublicKey,
    committee: Committee,
    signature_service: SignatureService,
    rx_mempool: Receiver<Digest>,
    rx_message: Receiver<ProposerMessage>,
    tx_loopback: Sender<Block>,
    buffer: HashSet<Digest>,
    network: ReliableSender,
    validator_id: u64, 
    exit: exit_future::Exit
}

impl Proposer {
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        rx_mempool: Receiver<Digest>,
        rx_message: Receiver<ProposerMessage>,
        tx_loopback: Sender<Block>,
        validator_id: u64, 
        exit: exit_future::Exit
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee,
                signature_service,
                rx_mempool,
                rx_message,
                tx_loopback,
                buffer: HashSet::new(),
                network: ReliableSender::new(),
                validator_id,
                exit
            }
            .run()
            .await;
        });
    }

    /// Helper function. It waits for a future to complete and then delivers a value.
    async fn waiter(wait_for: CancelHandler, deliver: Stake) -> Stake {
        let _ = wait_for.await;
        deliver
    }

    async fn make_block(&mut self, round: Round, qc: QC, tc: Option<TC>) {
        // if self.buffer.is_empty() && tc.is_none() {
        //     return;
        // }
        // Generate a new block.
        let block = Block::new(
            qc,
            tc,
            self.name,
            round,
            /* payload */ self.buffer.drain().collect(),
            self.signature_service.clone(),
        )
        .await;

        if !block.payload.is_empty() {
            info!("[VA {}] Created {} ({})", self.validator_id, block, block.digest());

            #[cfg(feature = "benchmark")]
            for x in &block.payload {
                // NOTE: This log entry is used to compute performance.
                info!("Created {} -> {:?}", block, x);
            }
        }
        else {
            debug!("Created empty {}", block);
        }

        // Broadcast our new block.
        debug!("Broadcasting {:?}", block);
        let (names, addresses): (Vec<_>, _) = self
            .committee
            .broadcast_addresses(&self.name)
            .iter()
            .cloned()
            .unzip();
        let message = bincode::serialize(&ConsensusMessage::Propose(block.clone()))
            .expect("Failed to serialize block");
        let dvf_message = DvfMessage { validator_id: self.validator_id, message: message};
        let serialized_msg = bincode::serialize(&dvf_message).unwrap();
        let handles = self
            .network
            .broadcast(addresses, Bytes::from(serialized_msg))
            .await;

        debug!("[VA {}] makeblock before loopback", self.validator_id);

        // Send our block to the core for processing.
        self.tx_loopback
            .send(block)
            .await
            .expect("Failed to send block");

        debug!("[VA {}] makeblock after loopback", self.validator_id);

        // Control system: Wait for 2f+1 nodes to acknowledge our block before continuing.
        let mut wait_for_quorum: FuturesUnordered<_> = names
            .into_iter()
            .zip(handles.into_iter())
            .map(|(name, handler)| {
                let stake = self.committee.stake(&name);
                Self::waiter(handler, stake)
            })
            .collect();

        let mut total_stake = self.committee.stake(&self.name);
        while let Some(stake) = wait_for_quorum.next().await {
            total_stake += stake;
            if total_stake >= self.committee.quorum_threshold() {
                break;
            }
        }
        debug!("[VA {}] makeblock end of block broadcast", self.validator_id);
    }

    async fn run(&mut self) {
        loop {
            let exit = self.exit.clone();
            tokio::select! {
                Some(digest) = self.rx_mempool.recv() => {
                    //if self.buffer.len() < 155 {
                        self.buffer.insert(digest);
                    //}
                },
                Some(message) = self.rx_message.recv() => match message {
                    ProposerMessage::Make(round, qc, tc) => self.make_block(round, qc, tc).await,
                    ProposerMessage::Cleanup(digests) => {
                        for x in &digests {
                            self.buffer.remove(x);
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
