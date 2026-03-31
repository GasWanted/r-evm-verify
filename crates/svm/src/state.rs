use crate::taint::Taint;
use r_evm_verify_lifter::ir::{Expr, Prop};
use std::collections::{BTreeMap, HashMap};

/// Key for loop detection: (program counter, stack height).
type LoopKey = (usize, usize);

/// An event logged during symbolic execution for property checking.
#[derive(Debug, Clone)]
pub enum CallEvent {
    ExternalCall {
        offset: usize,
        addr: Expr,
        value: Expr,
        value_taint: Taint,
    },
    DelegateCall {
        offset: usize,
        addr: Expr,
    },
    StorageWrite {
        offset: usize,
        slot: Expr,
        value: Expr,
        value_taint: Taint,
    },
    SelfDestruct {
        offset: usize,
    },
    TxOriginCheck {
        offset: usize,
    },
}

/// Symbolic memory: sparse map from concrete offset to symbolic value.
#[derive(Debug, Clone, Default)]
pub struct SymbolicMemory {
    /// Concrete offset → symbolic value (32-byte word).
    words: HashMap<usize, Expr>,
}

impl SymbolicMemory {
    pub fn store(&mut self, offset: usize, value: Expr) {
        self.words.insert(offset, value);
    }

    pub fn load(&self, offset: usize) -> Expr {
        self.words
            .get(&offset)
            .cloned()
            .unwrap_or(Expr::Lit([0; 32]))
    }
}

/// Symbolic storage: maps symbolic slot expressions to symbolic values.
#[derive(Debug, Clone, Default)]
pub struct SymbolicStorage {
    /// Known concrete slot writes.
    concrete: HashMap<[u8; 32], Expr>,
    /// Symbolic slot writes (tracked in order for SLOAD resolution).
    writes: Vec<(Expr, Expr)>,
}

impl SymbolicStorage {
    pub fn sstore(&mut self, slot: Expr, value: Expr) {
        if let Expr::Lit(bytes) = &slot {
            self.concrete.insert(*bytes, value.clone());
        }
        self.writes.push((slot, value));
    }

    pub fn sload(&self, slot: &Expr) -> Expr {
        // Try concrete lookup first.
        if let Expr::Lit(bytes) = slot {
            if let Some(val) = self.concrete.get(bytes) {
                return val.clone();
            }
        }
        // Otherwise return symbolic SLOAD.
        Expr::SLoad(Box::new(slot.clone()))
    }
}

/// The full state of the symbolic virtual machine for one execution path.
#[derive(Debug, Clone)]
pub struct SvmState {
    /// Program counter (bytecode offset).
    pub pc: usize,
    /// Symbolic stack.
    pub stack: Vec<Expr>,
    /// Taint labels for stack expressions, parallel to `stack`.
    pub taints: Vec<Taint>,
    /// Symbolic memory.
    pub memory: SymbolicMemory,
    /// Symbolic storage.
    pub storage: SymbolicStorage,
    /// Path constraints accumulated at JUMPI forks.
    pub constraints: Vec<Prop>,
    /// Ordered log of calls and storage writes for property checking.
    pub call_log: Vec<CallEvent>,
    /// Number of instructions executed on this path.
    pub steps: u64,
    /// Maximum steps before termination.
    pub max_steps: u64,
    /// Loop detection: how many times each (pc, stack_height) has been visited.
    pub loop_visits: HashMap<LoopKey, u32>,
    /// Maximum visits to the same (pc, stack_height) before stopping loop unrolling.
    pub max_loop_bound: u32,
    /// Number of callback simulations on this path.
    pub callback_count: u32,
    /// Maximum callbacks per path.
    pub max_callbacks: u32,
    /// Deployed contract bytecodes: address (as [u8; 20]) → bytecode.
    pub contracts: BTreeMap<[u8; 20], Vec<u8>>,
    /// Call stack for cross-contract execution in prove mode.
    pub call_frames: Vec<crate::call_dispatch::CallFrame>,
}

impl SvmState {
    pub fn new(max_steps: u64) -> Self {
        Self::with_loop_bound(max_steps, 10)
    }

    pub fn with_loop_bound(max_steps: u64, max_loop_bound: u32) -> Self {
        Self {
            pc: 0,
            stack: Vec::with_capacity(1024),
            taints: Vec::with_capacity(1024),
            memory: SymbolicMemory::default(),
            storage: SymbolicStorage::default(),
            constraints: Vec::new(),
            call_log: Vec::new(),
            steps: 0,
            max_steps,
            loop_visits: HashMap::new(),
            max_loop_bound,
            callback_count: 0,
            max_callbacks: 1,
            contracts: BTreeMap::new(),
            call_frames: Vec::new(),
        }
    }

    /// Record a visit to the current (pc, stack_height).
    /// Returns true if the loop bound has been exceeded.
    pub fn check_loop_bound(&mut self) -> bool {
        let key = (self.pc, self.stack.len());
        let count = self.loop_visits.entry(key).or_insert(0);
        *count += 1;
        *count > self.max_loop_bound
    }

    pub fn push(&mut self, expr: Expr) {
        // Simplify expressions on push to keep expression trees small.
        self.stack
            .push(r_evm_verify_lifter::simplify::simplify_expr(&expr));
        self.taints.push(Taint::Unknown);
    }

    /// Push an expression with an explicit taint label.
    pub fn push_tainted(&mut self, expr: Expr, taint: Taint) {
        self.stack
            .push(r_evm_verify_lifter::simplify::simplify_expr(&expr));
        self.taints.push(taint);
    }

    pub fn pop(&mut self) -> Option<Expr> {
        if self.stack.is_empty() {
            return None;
        }
        self.taints.pop();
        self.stack.pop()
    }

    /// Pop an expression along with its taint label.
    pub fn pop_tainted(&mut self) -> Option<(Expr, Taint)> {
        let expr = self.stack.pop()?;
        let taint = self.taints.pop().unwrap_or(Taint::Unknown);
        Some((expr, taint))
    }

    /// Peek at the taint of the top-of-stack element at the given depth.
    pub fn peek_taint(&self, depth: usize) -> Taint {
        if depth < self.taints.len() {
            self.taints[self.taints.len() - 1 - depth]
        } else {
            Taint::Unknown
        }
    }

    pub fn peek(&self, depth: usize) -> Option<&Expr> {
        if depth < self.stack.len() {
            Some(&self.stack[self.stack.len() - 1 - depth])
        } else {
            None
        }
    }

    pub fn stack_len(&self) -> usize {
        self.stack.len()
    }

    /// Clone this state for forking at a JUMPI.
    pub fn fork(&self) -> Self {
        self.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn push_pop() {
        let mut state = SvmState::new(1000);
        let mut val = [0u8; 32];
        val[31] = 42;
        state.push(Expr::Lit(val));
        assert_eq!(state.stack_len(), 1);
        let popped = state.pop().unwrap();
        assert_eq!(popped, Expr::Lit(val));
        assert_eq!(state.stack_len(), 0);
    }

    #[test]
    fn memory_store_load() {
        let mut mem = SymbolicMemory::default();
        let val = Expr::Var("x".into());
        mem.store(0x40, val.clone());
        assert_eq!(mem.load(0x40), val);
        assert_eq!(mem.load(0x60), Expr::Lit([0; 32])); // uninitialized
    }

    #[test]
    fn storage_concrete_roundtrip() {
        let mut storage = SymbolicStorage::default();
        let slot = Expr::Lit([0; 32]);
        let val = Expr::Var("v".into());
        storage.sstore(slot.clone(), val.clone());
        assert_eq!(storage.sload(&slot), val);
    }

    #[test]
    fn storage_symbolic_sload() {
        let storage = SymbolicStorage::default();
        let slot = Expr::Var("slot".into());
        let loaded = storage.sload(&slot);
        assert!(matches!(loaded, Expr::SLoad(_)));
    }

    #[test]
    fn fork_is_independent() {
        let mut state = SvmState::new(1000);
        state.push(Expr::Var("x".into()));
        let mut forked = state.fork();
        forked.push(Expr::Var("y".into()));
        assert_eq!(state.stack_len(), 1);
        assert_eq!(forked.stack_len(), 2);
    }
}
