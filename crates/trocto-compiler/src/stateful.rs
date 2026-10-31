// Copyright (c) 2026 Ankerin
// SPDX-License-Identifier: MIT

//! Flat typed control flow and independent stateful reference semantics.

use crate::{ExecutionError, MAX_EVENTS, MAX_STATE_KEY_BYTES, MAX_STATE_KEYS, Operator};
use std::collections::BTreeSet;

/// Authenticated call metadata and statically prefixed, declared state slots.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ContractContext {
    /// Authenticated block height.
    pub height: u64,
    /// Four little-endian caller-address limbs.
    pub caller: [u64; 4],
    /// Static keys followed by sorted transaction-declared raw keys.
    pub keys: Vec<Vec<u8>>,
    /// Initial numeric values; absent keys are `None`.
    pub state: Vec<Option<u64>>,
    /// Explicit per-slot read/write authorization.
    pub access: Vec<bool>,
}

impl ContractContext {
    pub(crate) fn validate(&self, prefix: &[Vec<u8>]) -> Result<(), ExecutionError> {
        let count = self.keys.len();
        if count > MAX_STATE_KEYS
            || self.state.len() != count
            || self.access.len() != count
            || !self.keys.starts_with(prefix)
            || self
                .keys
                .iter()
                .any(|key| key.is_empty() || key.len() > MAX_STATE_KEY_BYTES)
            || self.keys[prefix.len()..]
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            || self.keys.iter().collect::<BTreeSet<_>>().len() != count
        {
            return Err(ExecutionError::InvalidContext);
        }
        Ok(())
    }
}

/// Private effects of a successful call; errors publish no partial effects.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContractExecution {
    /// Returned value.
    pub value: u64,
    /// Dynamic source/control instruction units consumed.
    pub fuel_used: u64,
    /// Final slots in the same order as the supplied context keys.
    pub state: Vec<Option<u64>>,
    /// Whether each slot was written or deleted.
    pub writes: Vec<bool>,
    /// Bounded `(topic, data)` pairs in execution order.
    pub events: Vec<(u64, u64)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Type {
    U64,
    Bool,
}

#[derive(Clone, Copy, Debug)]
pub(crate) enum Binary {
    Arithmetic(Operator),
    Equal,
    NotEqual,
    Less,
    LessEqual,
    Greater,
    GreaterEqual,
}

impl Binary {
    fn apply(self, left: u64, right: u64) -> Result<u64, ExecutionError> {
        Ok(match self {
            Self::Arithmetic(operator) => return operator.apply(left, right),
            Self::Equal => u64::from(left == right),
            Self::NotEqual => u64::from(left != right),
            Self::Less => u64::from(left < right),
            Self::LessEqual => u64::from(left <= right),
            Self::Greater => u64::from(left > right),
            Self::GreaterEqual => u64::from(left >= right),
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) enum Step {
    Constant {
        destination: usize,
        value: u64,
    },
    Input {
        destination: usize,
    },
    Load {
        destination: usize,
        local: usize,
    },
    Store {
        local: usize,
        source: usize,
        charge: bool,
    },
    Move {
        destination: usize,
        source: usize,
    },
    Binary {
        destination: usize,
        operator: Binary,
        left: usize,
        right: usize,
    },
    Not {
        destination: usize,
        source: usize,
    },
    Branch {
        condition: usize,
        yes: usize,
        no: usize,
    },
    Jump(usize),
    Return(usize),
    Height {
        destination: usize,
    },
    Caller {
        destination: usize,
        index: usize,
    },
    KeyCount {
        destination: usize,
    },
    KeyWord {
        destination: usize,
        key: usize,
        word: usize,
    },
    GetAt {
        destination: usize,
        key: usize,
    },
    SetAt {
        key: usize,
        source: usize,
    },
    DeleteAt {
        key: usize,
    },
    Get {
        destination: usize,
        key: usize,
    },
    Set {
        key: usize,
        source: usize,
    },
    Delete {
        key: usize,
    },
    Emit {
        topic: usize,
        data: usize,
    },
}

impl Step {
    pub(crate) fn charged(&self) -> bool {
        !matches!(
            self,
            Self::Store { charge: false, .. } | Self::Move { .. } | Self::Return(_)
        )
    }
}

#[derive(Clone, Debug)]
pub(crate) struct CheckedProgram {
    pub(crate) instructions: Vec<Step>,
    pub(crate) registers: usize,
    pub(crate) locals: usize,
    pub(crate) keys: Vec<Vec<u8>>,
    pub(crate) context: bool,
}

impl CheckedProgram {
    pub(crate) fn evaluate(
        &self,
        input: u64,
        context: &ContractContext,
        fuel: u64,
    ) -> Result<ContractExecution, ExecutionError> {
        self.evaluate_with_interrupt(input, context, fuel, || false)
            .map(|result| result.expect("noninterruptible evaluator completes"))
    }

    // The exhaustive dispatch mirrors LLVM lowering for differential checks.
    #[allow(clippy::too_many_lines)]
    pub(crate) fn evaluate_with_interrupt(
        &self,
        input: u64,
        context: &ContractContext,
        fuel: u64,
        mut interrupt: impl FnMut() -> bool,
    ) -> Result<Option<ContractExecution>, ExecutionError> {
        context.validate(&self.keys)?;
        let mut registers = vec![0; self.registers];
        let mut locals = vec![0; self.locals];
        let mut state = context.state.clone();
        let mut writes = vec![false; context.keys.len()];
        let mut events = Vec::new();
        let mut used = 0u64;
        let mut pc = 0;
        let mut dispatches = 0u16;
        loop {
            if dispatches == 0 && interrupt() {
                return Ok(None);
            }
            dispatches = (dispatches + 1) % 1024;
            let instruction = self
                .instructions
                .get(pc)
                .ok_or(ExecutionError::InvalidContext)?;
            if instruction.charged() {
                if used >= fuel {
                    return Err(ExecutionError::FuelExhausted);
                }
                used += 1;
            }
            match *instruction {
                Step::Constant { destination, value } => registers[destination] = value,
                Step::Input { destination } => registers[destination] = input,
                Step::Load { destination, local } => registers[destination] = locals[local],
                Step::Store { local, source, .. } => locals[local] = registers[source],
                Step::Move {
                    destination,
                    source,
                } => registers[destination] = registers[source],
                Step::Binary {
                    destination,
                    operator,
                    left,
                    right,
                } => {
                    registers[destination] = operator.apply(registers[left], registers[right])?;
                }
                Step::Not {
                    destination,
                    source,
                } => registers[destination] = u64::from(registers[source] == 0),
                Step::Branch { condition, yes, no } => {
                    pc = if registers[condition] != 0 { yes } else { no };
                    continue;
                }
                Step::Jump(next) => {
                    pc = next;
                    continue;
                }
                Step::Return(source) => {
                    if interrupt() {
                        return Ok(None);
                    }
                    return Ok(Some(ContractExecution {
                        value: registers[source],
                        fuel_used: used,
                        state,
                        writes,
                        events,
                    }));
                }
                Step::Height { destination } => registers[destination] = context.height,
                Step::Caller { destination, index } => {
                    registers[destination] = context.caller[index];
                }
                Step::KeyCount { destination } => {
                    registers[destination] =
                        u64::try_from(context.keys.len()).expect("validated state count fits u64");
                }
                Step::KeyWord {
                    destination,
                    key,
                    word,
                } => {
                    let key =
                        usize::try_from(registers[key]).map_err(|_| ExecutionError::Bounds)?;
                    let bytes = context.keys.get(key).ok_or(ExecutionError::Bounds)?;
                    if bytes.len() != 32 {
                        return Err(ExecutionError::Bounds);
                    }
                    registers[destination] = u64::from_le_bytes(
                        bytes[word * 8..word * 8 + 8]
                            .try_into()
                            .expect("checked address limb"),
                    );
                }
                Step::GetAt { destination, key } => {
                    let key = checked_slot(registers[key], context)?;
                    registers[destination] = state[key].unwrap_or(0);
                }
                Step::SetAt { key, source } => {
                    let key = checked_slot(registers[key], context)?;
                    state[key] = Some(registers[source]);
                    writes[key] = true;
                }
                Step::DeleteAt { key } => {
                    let key = checked_slot(registers[key], context)?;
                    state[key] = None;
                    writes[key] = true;
                }
                Step::Get { destination, key } => {
                    if !context.access[key] {
                        return Err(ExecutionError::AccessDenied);
                    }
                    registers[destination] = state[key].unwrap_or(0);
                }
                Step::Set { key, source } => {
                    if !context.access[key] {
                        return Err(ExecutionError::AccessDenied);
                    }
                    state[key] = Some(registers[source]);
                    writes[key] = true;
                }
                Step::Delete { key } => {
                    if !context.access[key] {
                        return Err(ExecutionError::AccessDenied);
                    }
                    state[key] = None;
                    writes[key] = true;
                }
                Step::Emit { topic, data } => {
                    if events.len() >= MAX_EVENTS {
                        return Err(ExecutionError::EventLimit);
                    }
                    events.push((registers[topic], registers[data]));
                }
            }
            pc += 1;
        }
    }
}

fn checked_slot(index: u64, context: &ContractContext) -> Result<usize, ExecutionError> {
    let index = usize::try_from(index).map_err(|_| ExecutionError::Bounds)?;
    if index >= context.keys.len() {
        return Err(ExecutionError::Bounds);
    }
    if !context.access[index] {
        return Err(ExecutionError::AccessDenied);
    }
    Ok(index)
}
