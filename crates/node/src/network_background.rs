// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Bounded node-local execution work; publication stays on the node thread.

use crate::{
    BlockProducer,
    execution_pipeline::{ExecutionJob, ExecutionWorker},
    network::{NetworkNodeError, input, local},
    network_wire::NetworkMessage,
};
use std::collections::VecDeque;
use types::Block;

const PENDING_EXCHANGES: usize = 4;
const MESSAGE_BUDGET: usize = 32;

pub(crate) trait ExecutionHost {
    fn execution_position(&self) -> (u64, u32);
    fn execution_producer(&self) -> &BlockProducer;
    fn execution_block<'a>(&self, message: &'a NetworkMessage) -> Option<&'a Block>;
    fn process_message(&mut self, message: NetworkMessage) -> Result<(), NetworkNodeError>;
}

struct Active {
    position: (u64, u32),
    message: Option<NetworkMessage>,
}

pub(crate) struct BackgroundExecution {
    worker: ExecutionWorker,
    active: Option<Active>,
    exchanges: VecDeque<VecDeque<NetworkMessage>>,
}

impl BackgroundExecution {
    pub(crate) fn new() -> Result<Self, NetworkNodeError> {
        Ok(Self {
            worker: ExecutionWorker::spawn().map_err(local)?,
            active: None,
            exchanges: VecDeque::new(),
        })
    }

    pub(crate) fn can_receive(&self) -> bool {
        self.exchanges.len() < PENDING_EXCHANGES
    }

    pub(crate) fn enqueue(
        &mut self,
        messages: Vec<NetworkMessage>,
    ) -> Result<(), NetworkNodeError> {
        if !self.can_receive() {
            return Err(input("execution mailbox is full"));
        }
        if !messages.is_empty() {
            self.exchanges.push_back(messages.into());
        }
        Ok(())
    }

    pub(crate) fn prepare_candidate(
        &mut self,
        position: (u64, u32),
        job: ExecutionJob,
    ) -> Result<(), NetworkNodeError> {
        if !self.worker.busy() {
            self.worker.submit(job).map_err(local)?;
            self.active = Some(Active {
                position,
                message: None,
            });
        }
        Ok(())
    }

    pub(crate) fn can_prepare_candidate(&self) -> bool {
        !self.worker.busy()
    }

    pub(crate) fn drive(
        &mut self,
        host: &mut impl ExecutionHost,
    ) -> Result<usize, NetworkNodeError> {
        let mut rejected = 0;
        if let Some(result) = self.worker.try_complete() {
            let active = self
                .active
                .take()
                .ok_or_else(|| local("missing execution task"))?;
            // Received bodies remain reusable across round changes; the ordinary
            // receive path and exact producer snapshot still decide validity.
            let current = if active.message.is_some() {
                active.position.0 == host.execution_position().0
            } else {
                active.position == host.execution_position()
            };
            match result {
                Ok(completed) if current => host.execution_producer().offer_execution(completed),
                Err(error) => match NetworkNodeError::from(error) {
                    NetworkNodeError::Input(_) if current && active.message.is_some() => {
                        rejected += 1;
                        return Ok(rejected);
                    }
                    NetworkNodeError::Input(_) => {}
                    error @ NetworkNodeError::Local(_) => return Err(error),
                },
                Ok(_) => {}
            }
            if let Some(message) = active.message {
                rejected += process(host, message)?;
            }
        }
        // An imported block holds its position in the receive stream until execution
        // completes. Network propagation, RPC and the node's timer remain independent.
        if self
            .active
            .as_ref()
            .is_some_and(|active| active.message.is_some())
        {
            return Ok(rejected);
        }
        for _ in 0..MESSAGE_BUDGET {
            while self.exchanges.front().is_some_and(VecDeque::is_empty) {
                self.exchanges.pop_front();
            }
            let Some(exchange) = self.exchanges.front_mut() else {
                break;
            };
            let Some(message) = exchange.pop_front() else {
                break;
            };
            if let Some(block) = host.execution_block(&message)
                && block.header.height == host.execution_position().0
                && !host.execution_producer().has_prepared_execution(block)
            {
                if self.worker.busy() {
                    exchange.push_front(message);
                    break;
                }
                let job = host
                    .execution_producer()
                    .prepare_block_execution(block.clone());
                self.worker.submit(job).map_err(local)?;
                self.active = Some(Active {
                    position: host.execution_position(),
                    message: Some(message),
                });
                break;
            }
            rejected += process(host, message)?;
        }
        Ok(rejected)
    }
}

fn process(
    host: &mut impl ExecutionHost,
    message: NetworkMessage,
) -> Result<usize, NetworkNodeError> {
    match host.process_message(message) {
        Ok(()) => Ok(0),
        Err(NetworkNodeError::Input(_)) => Ok(1),
        Err(error) => Err(error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    struct Host {
        producer: BlockProducer,
        round: u32,
        processed: bool,
    }

    impl ExecutionHost for Host {
        fn execution_position(&self) -> (u64, u32) {
            (self.producer.height(), self.round)
        }

        fn execution_producer(&self) -> &BlockProducer {
            &self.producer
        }

        fn execution_block<'a>(&self, message: &'a NetworkMessage) -> Option<&'a Block> {
            match message {
                NetworkMessage::Finalized { block, .. } => Some(block),
                _ => None,
            }
        }

        fn process_message(&mut self, message: NetworkMessage) -> Result<(), NetworkNodeError> {
            let NetworkMessage::Finalized { block, .. } = message else {
                panic!("expected finalized body");
            };
            // Inspect the scheduling handoff before a receive path could re-execute it.
            assert!(self.producer.has_prepared_execution(&block));
            self.processed = true;
            Ok(())
        }
    }

    #[test]
    fn received_execution_survives_a_round_change_without_reexecution() {
        let mut host = Host {
            producer: BlockProducer::new(crate::ProducerConfig::default()),
            round: 0,
            processed: false,
        };
        let block = host.producer.produce_block().unwrap().block;
        let certificate = consensus::FinalityCertificate {
            chain_id: 7,
            height: block.header.height,
            round: 0,
            committee_root: block.header.committee_root,
            block: block.header.compute_hash(),
            signatures: vec![],
        };
        let mut background = BackgroundExecution::new().unwrap();
        background
            .enqueue(vec![NetworkMessage::Finalized { block, certificate }])
            .unwrap();
        assert_eq!(background.drive(&mut host).unwrap(), 0);
        assert!(!host.processed);
        host.round += 1;
        let deadline = Instant::now() + Duration::from_secs(20);
        while !host.processed {
            assert!(
                Instant::now() < deadline,
                "received execution did not finish"
            );
            assert_eq!(background.drive(&mut host).unwrap(), 0);
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}
