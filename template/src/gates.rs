//! The gates: each decision the kernel makes, as a trait whose contracts are
//! written in the spec's terms. The owner writes this file, like the spec; a
//! code search writes the implementation in exec.rs and cannot weaken a
//! contract. `bon types` emits this file's types for programs.

use vstd::prelude::*;
use crate::spec;

verus! {

/// What a process may spend: its limit, and what it has spent.
pub struct Budget {
    /// The most it may spend.
    pub limit: u64,
    /// What it has spent.
    pub spent: u64,
}

pub trait Gates {
    /// Whether spending amount keeps budget within its limit.
    fn within(budget: &Budget, amount: u64) -> (r: bool)
        ensures r == spec::within(budget.spent as nat, amount as nat, budget.limit as nat);
}

} // verus!
