//! What {{name}} must do. The spec starts from the nouns every kernel shares
//! (OSTEP and object capabilities): a process holds a capability; its
//! authority is the objects it may act on, and its limit what it may spend; a
//! grant attenuates. Write the project's own nouns, predicates, transitions and
//! invariants here; each `pub open spec fn` has one `///` sentence saying when
//! it holds.

use vstd::prelude::*;
use verus_state_machines_macros::tokenized_state_machine;

verus! {

/// An object a capability gives authority over, by its name.
pub struct Object(pub Seq<char>);

/// What a process holds: the objects it may act on, and the most it may spend.
pub struct Capability { pub authority: Set<Object>, pub limit: nat }

/// child is within parent: it names no object parent does not, and may spend no more.
pub open spec fn attenuates(child: Capability, parent: Capability) -> bool {
    child.authority.subset_of(parent.authority) && child.limit <= parent.limit
}

/// Spending amount after spent keeps within limit.
pub open spec fn within(spent: nat, amount: nat, limit: nat) -> bool { spent + amount <= limit }

tokenized_state_machine!{ kernel {
    fields {
        /// The most every process together may spend.
        #[sharding(variable)]
        pub limit: nat,

        /// What the processes have spent.
        #[sharding(variable)]
        pub spent: nat,
    }

    /// Nothing is spent yet.
    init!{ initialize(limit: nat) {
        init limit = limit;
        init spent = 0;
    } }

    /// A process spends amount, within the limit.
    transition!{ spend(amount: nat) {
        require within(pre.spent, amount, pre.limit);
        update spent = pre.spent + amount;
    } }

    /// Nothing spends past its limit.
    #[invariant]
    pub fn within_limit(&self) -> bool { self.spent <= self.limit }

    #[inductive(initialize)]
    fn initialize_inductive(post: Self, limit: nat) {}

    #[inductive(spend)]
    fn spend_inductive(pre: Self, post: Self, amount: nat) {}
}}

} // verus!
