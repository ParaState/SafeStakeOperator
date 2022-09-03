use crate::aggregator::Aggregator;
use crate::config::Committee;
use crate::consensus::{ConsensusMessage, Round};
use crate::error::{ConsensusError, ConsensusResult};
use crate::leader::LeaderElector;
use crate::mempool::MempoolDriver;
use crate::messages::{Block, Timeout, Vote, QC, TC};
use crate::proposer::ProposerMessage;
use crate::synchronizer::Synchronizer;
use crate::timer::Timer;
use async_recursion::async_recursion;
use bytes::Bytes;
use crypto::Hash as _;
use crypto::{PublicKey, SignatureService};
use log::{debug, error, info, warn};
use network::{SimpleSender, DvfMessage};
use std::cmp::max;
use std::collections::VecDeque;
use store::Store;
use tokio::sync::mpsc::{Receiver, Sender};
use std::collections::HashMap;
use crypto::Digest;

#[cfg(test)]
#[path = "tests/core_tests.rs"]
pub mod core_tests;

pub struct Core {
    name: PublicKey,
    committee: Committee,
    store: Store,
    signature_service: SignatureService,
    leader_elector: LeaderElector,
    mempool_driver: MempoolDriver,
    synchronizer: Synchronizer,
    rx_message: Receiver<ConsensusMessage>,
    rx_loopback: Receiver<Block>,
    tx_proposer: Sender<ProposerMessage>,
    tx_commit: Sender<Block>,
    round: Round,
    last_voted_round: Round,
    last_committed_round: Round,
    high_qc: QC,
    timer: Timer,
    aggregator: Aggregator,
    network: SimpleSender,
    validator_id: u64,
    exit: exit_future::Exit,
    recover_count: u64,
    high_tc: TC,
    // block_map: HashMap<Digest, Block>,
    prune_depth: u64,
}

impl Core {
    #[allow(clippy::too_many_arguments)]
    pub fn spawn(
        name: PublicKey,
        committee: Committee,
        signature_service: SignatureService,
        store: Store,
        leader_elector: LeaderElector,
        mempool_driver: MempoolDriver,
        synchronizer: Synchronizer,
        timeout_delay: u64,
        rx_message: Receiver<ConsensusMessage>,
        rx_loopback: Receiver<Block>,
        tx_proposer: Sender<ProposerMessage>,
        tx_commit: Sender<Block>,
        validator_id : u64,
        exit: exit_future::Exit
    ) {
        tokio::spawn(async move {
            Self {
                name,
                committee: committee.clone(),
                signature_service,
                store,
                leader_elector,
                mempool_driver,
                synchronizer,
                rx_message,
                rx_loopback,
                tx_proposer,
                tx_commit,
                round: 1,
                last_voted_round: 0,
                last_committed_round: 0,
                high_qc: QC::genesis(),
                timer: Timer::new(timeout_delay),
                aggregator: Aggregator::new(committee),
                network: SimpleSender::new(),
                validator_id: validator_id,
                exit,
                recover_count: 0,
                high_tc: TC::default(),
                // block_map: HashMap::new(),
                prune_depth: 10,

            }
            .run()
            .await
        });
    }

    async fn store_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        let value = bincode::serialize(block).expect("Failed to serialize block");
        self.store.write(key, value).await;
        
        // block_map.insert(key, value);
    }

    async fn remove_block(&mut self, block: &Block) {
        let key = block.digest().to_vec();
        self.store.delete(key).await;
        
        // block_map.remove(key);
    }

    async fn get_parent_block(&self, block: &Block) -> Option<Block> {
        if block.qc == QC::genesis() {
            return Some(Block::genesis());
        }
        let parent = block.parent();
        match self.store.read(parent.to_vec()).await {
            Ok(Some(bytes)) => Some(bincode::deserialize(&bytes).expect("Failed to deserialize block")),
            _ => {
                None
            }
        }
    }

    pub async fn get_ancestors(
        &mut self,
        block: &Block,
    ) -> Option<(Block, Block)> {
        let b1 = match self.get_parent_block(block).await {
            Some(b) => b,
            None => return None,
        };
        let b0 = match self.get_parent_block(&b1).await {
            Some(b) => b,
            None => return None,
        };
        Some((b0, b1))
    }

    fn increase_last_voted_round(&mut self, target: Round) {
        self.last_voted_round = max(self.last_voted_round, target);
    }

    async fn make_vote(&mut self, block: &Block) -> Option<Vote> {
        // Check if we can vote for this block.
        let safety_rule_1 = block.round > self.last_voted_round;
        let mut safety_rule_2 = block.qc.round + 1 == block.round;
        if let Some(ref tc) = block.tc {
            let mut can_extend = tc.round + 1 == block.round;
            can_extend &= block.qc.round >= *tc.high_qc_rounds().iter().max().expect("Empty TC");
            safety_rule_2 |= can_extend;
        }
        if !(safety_rule_1 && safety_rule_2) {
            return None;
        }

        // Ensure we won't vote for contradicting blocks.
        self.increase_last_voted_round(block.round);
        // TODO [issue #15]: Write to storage preferred_round and last_voted_round.
        Some(Vote::new(block, self.name, self.signature_service.clone()).await)
    }

    // async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
    //     if self.last_committed_round >= block.round {
    //         return Ok(());
    //     }

    //     // Ensure we commit the entire chain. This is needed after view-change.
    //     // zico: Should consider the case after a recovery. Reading the entire chain 
    //     // is not an option because it might be too large to put into memory
    //     // Actually, in our application case:
    //     // 1. we don't produce transactions very often, roughly 12 seconds a transaction;
    //     // 2. if a block is not committed in time (12 seconds), it is useless in the future;
    //     // 3. no need to send back commit for empty blocks

    //     let mut to_commit = VecDeque::new();
    //     let mut parent = block.clone();
    //     let mut heuristic_history_rounds = 5; // This is more than enough for us
    //     while self.last_committed_round + 1 < parent.round && heuristic_history_rounds > 0 {
    //         let ancestor = self
    //             .synchronizer
    //             .get_parent_block(&parent)
    //             .await?
    //             .expect("We should have all the ancestors by now");
    //         to_commit.push_front(ancestor.clone());
    //         parent = ancestor;
    //         heuristic_history_rounds = heuristic_history_rounds - 1;
    //     }
    //     to_commit.push_front(block.clone());

    //     // Save the last committed block.
    //     self.last_committed_round = block.round;

    //     // Send all the newly committed blocks to the node's application layer.
    //     while let Some(block) = to_commit.pop_back() {
    //         if !block.payload.is_empty() {
    //             info!("Committed {}", block);

    //             #[cfg(feature = "benchmark")]
    //             for x in &block.payload {
    //                 // NOTE: This log entry is used to compute performance.
    //                 info!("Committed {} -> {:?}", block, x);
    //             }

    //             if let Err(e) = self.tx_commit.send(block).await {
    //                 warn!("Failed to send block through the commit channel: {}", e);
    //             }
    //         }
    //         // debug!("Committed {:?}", block);
    //         // if let Err(e) = self.tx_commit.send(block).await {
    //         //     warn!("Failed to send block through the commit channel: {}", e);
    //         // }
    //     }
    //     Ok(())
    // }

    async fn prune(&mut self, block: &Block) {
        let mut i: u64 = 0;
        let mut parent = block.clone();
        loop {
            let ancestor = self
                .get_parent_block(&parent)
                .await;
            if let Some(ancestor) = ancestor {
                if parent == Block::genesis() {
                    return;
                }
                parent = ancestor;
            }
            else {
                return;
            }
            i = i + 1;
            if i >= self.prune_depth {
                self.remove_block(&parent).await;
            }
        }
    }

    async fn commit(&mut self, block: Block) -> ConsensusResult<()> {
        if self.last_committed_round >= block.round {
            return Ok(());
        }

        // Ensure we commit the entire chain. This is needed after view-change.
        // zico: Should consider the case after a recovery. Reading the entire chain 
        // is not an option because it might be too large to put into memory
        // Actually, in our application case:
        // 1. we don't produce transactions very often, roughly 12 seconds a transaction;
        // 2. if a block is not committed in time (12 seconds), it is useless in the future;
        // 3. no need to send back commit for empty blocks

        let mut to_commit = VecDeque::new();
        let mut parent = block.clone();
        let mut heuristic_history_rounds = 5; // This is more than enough for us
        while self.last_committed_round + 1 < parent.round && heuristic_history_rounds > 0 {
            let ancestor = self
                .get_parent_block(&parent)
                .await;
            if let Some(ancestor) = ancestor {
                to_commit.push_front(ancestor.clone());
                parent = ancestor;
            }
            else{
                break;
            }
            heuristic_history_rounds = heuristic_history_rounds - 1;
        }
        to_commit.push_front(block.clone());

        // Save the last committed block.
        self.last_committed_round = block.round;

        self.prune(&block).await;

        // Send all the newly committed blocks to the node's application layer.
        while let Some(block) = to_commit.pop_back() {

            if !block.payload.is_empty() {
                info!("Committed {}", block);

                #[cfg(feature = "benchmark")]
                for x in &block.payload {
                    // NOTE: This log entry is used to compute performance.
                    info!("Committed {} -> {:?}", block, x);
                }

                if let Err(e) = self.tx_commit.send(block).await {
                    warn!("Failed to send block through the commit channel: {}", e);
                }
            }
            // debug!("Committed {:?}", block);
            // if let Err(e) = self.tx_commit.send(block).await {
            //     warn!("Failed to send block through the commit channel: {}", e);
            // }
        }
        Ok(())
    }


    fn update_high_qc(&mut self, qc: &QC) {
        if qc.round > self.high_qc.round {
            self.high_qc = qc.clone();
        }
    }

    fn update_high_tc(&mut self, tc: &TC) {
        if tc.round > self.high_tc.round {
            self.high_tc = tc.clone();
        }
    }

    async fn local_timeout_round(&mut self) -> ConsensusResult<()> {
        warn!("[VA {}] Timeout reached for round {}", self.validator_id, self.round);

        // Increase the last voted round.
        self.increase_last_voted_round(self.round);

        // Make a timeout message.
        let timeout = Timeout::new(
            self.high_qc.clone(),
            self.high_tc.clone(),
            self.round,
            self.name,
            self.signature_service.clone(),
        )
        .await;
        debug!("Created {:?}", timeout);

        // Reset the timer.
        self.timer.reset();

        // Broadcast the timeout message.
        debug!("Broadcasting {:?}", timeout);
        let addresses = self
            .committee
            .broadcast_addresses(&self.name)
            .into_iter()
            .map(|(_, x)| x)
            .collect();
        let message = bincode::serialize(&ConsensusMessage::Timeout(timeout.clone()))
            .expect("Failed to serialize timeout message");
        let dvf_message = DvfMessage { validator_id: self.validator_id, message: message};
        let serialized_msg = bincode::serialize(&dvf_message).unwrap();
        debug!("[CORE] Broacasting to {:?}", addresses);
        self.network
            .broadcast(addresses, Bytes::from(serialized_msg))
            .await;

        // Process our message.
        self.handle_timeout(&timeout).await
    }

    #[async_recursion]
    async fn handle_vote(&mut self, vote: &Vote) -> ConsensusResult<()> {
        debug!("Processing {:?}", vote);
        if vote.round < self.round {
            return Ok(());
        }

        // Ensure the vote is well formed.
        vote.verify(&self.committee)?;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(qc) = self.aggregator.add_vote(vote.clone())? {
            debug!("Assembled {:?}", qc);

            // Process the QC.
            self.process_qc(&qc).await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(None).await;
            }
        }
        Ok(())
    }

    async fn handle_timeout(&mut self, timeout: &Timeout) -> ConsensusResult<()> {
        debug!("Processing {:?}", timeout);
        if timeout.round < self.round {
            return Ok(());
        }

        // Ensure the timeout is well formed.
        timeout.verify(&self.committee)?;

        // Process the QC embedded in the timeout.
        self.process_qc(&timeout.high_qc).await;

        self.process_tc(&timeout.high_tc).await;

        // Add the new vote to our aggregator and see if we have a quorum.
        if let Some(tc) = self.aggregator.add_timeout(timeout.clone())? {
            debug!("Assembled {:?}", tc);

            // Try to advance the round.
            // self.advance_round(tc.round).await;

            self.process_tc(&tc).await;

            // Broadcast the TC.
            debug!("Broadcasting {:?}", tc);
            let addresses = self
                .committee
                .broadcast_addresses(&self.name)
                .into_iter()
                .map(|(_, x)| x)
                .collect();
            let message = bincode::serialize(&ConsensusMessage::TC(tc.clone()))
                .expect("Failed to serialize timeout certificate");
            let dvf_message = DvfMessage { validator_id: self.validator_id, message: message};
            let serialized_msg = bincode::serialize(&dvf_message).unwrap();
            debug!("[CORE] Broacasting to {:?}", addresses);
            self.network
                .broadcast(addresses, Bytes::from(serialized_msg))
                .await;

            // Make a new block if we are the next leader.
            if self.name == self.leader_elector.get_leader(self.round) {
                self.generate_proposal(Some(tc)).await;
            }
        }
        Ok(())
    }

    #[async_recursion]
    async fn advance_round(&mut self, round: Round) {
        if round < self.round {
            return;
        }
        // Reset the timer and advance round.
        self.timer.reset();
        self.round = round + 1;
        debug!("Moved to round {}", self.round);

        // Cleanup the vote aggregator.
        self.aggregator.cleanup(&self.round);
    }

    #[async_recursion]
    async fn generate_proposal(&mut self, tc: Option<TC>) {
        self.tx_proposer
            .send(ProposerMessage::Make(self.round, self.high_qc.clone(), tc))
            .await
            .expect("Failed to send message to proposer");
    }

    async fn cleanup_proposer(&mut self, b0: &Block, b1: &Block, block: &Block) {
        let digests = b0
            .payload
            .iter()
            .cloned()
            .chain(b1.payload.iter().cloned())
            .chain(block.payload.iter().cloned())
            .collect();
        self.tx_proposer
            .send(ProposerMessage::Cleanup(digests))
            .await
            .expect("Failed to send message to proposer");
    }

    // async fn cleanup_proposer(&mut self, b0: &Block, block: &Block) {
    //     let digests = b0
    //         .payload
    //         .iter()
    //         .cloned()
    //         .chain(block.payload.iter().cloned())
    //         .collect();
    //     self.tx_proposer
    //         .send(ProposerMessage::Cleanup(digests))
    //         .await
    //         .expect("Failed to send message to proposer");
    // }

    async fn process_qc(&mut self, qc: &QC) {
        self.advance_round(qc.round).await;
        self.update_high_qc(qc);
    }

    async fn process_tc(&mut self, tc: &TC) {
        self.advance_round(tc.round).await;
        self.update_high_tc(tc);
    }

    // #[async_recursion]
    // async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
    //     debug!("{} Processing {}, with parent {}", self.name, block.digest(), block.parent());

    //     // Let's see if we have the last three ancestors of the block, that is:
    //     //      b0 <- |qc0; b1| <- |qc1; block|
    //     // If we don't, the synchronizer asks for them to other nodes. It will
    //     // then ensure we process both ancestors in the correct order, and
    //     // finally make us resume processing this block.
    //     let (b0, b1) = match self.synchronizer.get_ancestors(block).await? {
    //         Some(ancestors) => ancestors,
    //         None => {
    //             self.recover_count = self.recover_count + 1;
    //             debug!("Processing of {} suspended: missing parent. Count: {}", block.digest(), self.recover_count);
    //             return Ok(());
    //         }
    //     };

    //     // Store the block only if we have already processed all its ancestors.
    //     self.store_block(block).await;

    //     self.cleanup_proposer(&b0, &b1, block).await;

    //     // Check if we can commit the head of the 2-chain.
    //     // Note that we commit blocks only if we have all its ancestors.
    //     if b0.round + 1 == b1.round {
    //         self.mempool_driver.cleanup(b0.round).await;
    //         self.commit(b0).await?;
    //     }

    //     // Ensure the block's round is as expected.
    //     // This check is important: it prevents bad leaders from producing blocks
    //     // far in the future that may cause overflow on the round number.
    //     if block.round != self.round {
    //         return Ok(());
    //     }

    //     // See if we can vote for this block.
    //     if let Some(vote) = self.make_vote(block).await {
    //         debug!("Created {:?}", vote);
    //         let next_leader = self.leader_elector.get_leader(self.round + 1);
    //         if next_leader == self.name {
    //             self.handle_vote(&vote).await?;
    //         } else {
    //             debug!("[CORE] {} Sending {:?} to {}", self.name, vote, next_leader);
    //             let address = self
    //                 .committee
    //                 .address(&next_leader)
    //                 .expect("The next leader is not in the committee");
    //             let message = bincode::serialize(&ConsensusMessage::Vote(vote))
    //                 .expect("Failed to serialize vote");
    //             let dvf_message = DvfMessage { validator_id: self.validator_id, message: message};
    //             let serialized_msg = bincode::serialize(&dvf_message).unwrap();
    //             self.network.send(address, Bytes::from(serialized_msg)).await;
    //         }
    //     }
    //     Ok(())
    // }

    #[async_recursion]
    async fn process_block(&mut self, block: &Block) -> ConsensusResult<()> {
        info!("[VA {}, round {}] Processing {} ({}), with parent {}", self.validator_id, self.round, block, block.digest(), block.parent());
        // Just store it
        self.store_block(block).await;

        // If we haven't seen the block, we don't need the block. There is no need to synchronize the history.
        let (b0, b1) = match self.get_ancestors(block).await {
            Some(ancestors) => ancestors,
            None => {
                debug!("Processing of {} suspended: missing parent. Count: {}", block.digest(), self.recover_count);
                return Ok(());
            }
        };
        info!("[VA {}, round {}] Successfully get {}'s parent {} ({}) and grandparent {} ({})", 
            self.validator_id, self.round, block, b1, b1.digest(), b0, b0.digest());

        // Don't propose a block that contains any payload that have been included in previous blocks
        self.cleanup_proposer(&b0, &b1, block).await;

        // Check if we can commit the head of the 2-chain.
        // Note that we commit blocks only if we have all its ancestors.
        if b0.round + 1 == b1.round {
            self.mempool_driver.cleanup(b0.round).await;
            self.commit(b0.clone()).await?;
            info!("[VA {}, round {}] after commit {} ({})", self.validator_id, self.round, b0, b0.digest());
        }

        // Ensure the block's round is as expected.
        // This check is important: it prevents bad leaders from producing blocks
        // far in the future that may cause overflow on the round number.
        if block.round != self.round {
            return Ok(());
        }

        // See if we can vote for this block.
        if let Some(vote) = self.make_vote(block).await {
            info!("[VA {}, round {}] Created vote {:?} for block {}", self.validator_id, self.round, vote, block);
            let next_leader = self.leader_elector.get_leader(self.round + 1);
            if next_leader == self.name {
                self.handle_vote(&vote).await?;
            } else {
                debug!("[CORE] {} Sending {:?} to {}", self.name, vote, next_leader);
                let addresses = self
                    .committee
                    .broadcast_addresses(&self.name)
                    .into_iter()
                    .map(|(_, x)| x)
                    .collect();
                let message = bincode::serialize(&ConsensusMessage::Vote(vote))
                    .expect("Failed to serialize vote");
                let dvf_message = DvfMessage { validator_id: self.validator_id, message: message};
                let serialized_msg = bincode::serialize(&dvf_message).unwrap();
                self.network.broadcast(addresses, Bytes::from(serialized_msg)).await;
            }
        }
        Ok(())
    }

    async fn handle_proposal(&mut self, block: &Block) -> ConsensusResult<()> {
        let digest = block.digest();

        // Ensure the block proposer is the right leader for the round.
        ensure!(
            block.author == self.leader_elector.get_leader(block.round),
            ConsensusError::WrongLeader {
                digest,
                leader: block.author,
                round: block.round
            }
        );

        // Check the block is correctly formed.
        block.verify(&self.committee)?;

        // Process the QC. This may allow us to advance round.
        self.process_qc(&block.qc).await;

        // Process the TC (if any). This may also allow us to advance round.
        if let Some(ref tc) = block.tc {
            // self.advance_round(tc.round).await;
            self.process_tc(tc).await;
        }

        // Let's see if we have the block's data. If we don't, the mempool
        // will get it and then make us resume processing this block.
        if !self.mempool_driver.verify(block.clone()).await? {
            debug!("Processing of {} suspended: missing payload", digest);
            return Ok(());
        }

        // All check pass, we can process this block.
        self.process_block(block).await
    }

    async fn handle_tc(&mut self, tc: TC) -> ConsensusResult<()> {
        // [TODO] zico: should verify TC, otherwise bad nodes could arbitrarily advance our round
        // self.advance_round(tc.round).await;
        self.process_tc(&tc).await;
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(Some(tc)).await;
        }
        Ok(())
    }

    pub async fn run(&mut self) {
        // Upon booting, generate the very first block (if we are the leader).
        // Also, schedule a timer in case we don't hear from the leader.
        self.timer.reset();
        if self.name == self.leader_elector.get_leader(self.round) {
            self.generate_proposal(None).await;
        }

        // This is the main loop: it processes incoming blocks and votes,
        // and receive timeout notifications from our Timeout Manager.
        loop {
            let exit = self.exit.clone();
            let result = tokio::select! {
                Some(message) = self.rx_message.recv() => match message {
                    ConsensusMessage::Propose(block) => {debug!("propose");self.handle_proposal(&block).await},
                    ConsensusMessage::Vote(vote) => {debug!("vote");self.handle_vote(&vote).await},
                    ConsensusMessage::Timeout(timeout) => {debug!("timeout");self.handle_timeout(&timeout).await},
                    ConsensusMessage::TC(tc) => {debug!("tc");self.handle_tc(tc).await},
                    _ => panic!("Unexpected protocol message")
                },
                Some(block) = self.rx_loopback.recv() => {debug!("loopback");self.process_block(&block).await},
                () = &mut self.timer => {debug!("timer");self.local_timeout_round().await},
                () = exit => {break; }
            };
            match result {
                Ok(()) => (),
                Err(ConsensusError::StoreError(e)) => error!("{}", e),
                Err(ConsensusError::SerializationError(e)) => error!("Store corrupted. {}", e),
                Err(e) => warn!("{}", e),
            }
        }
    }
}
