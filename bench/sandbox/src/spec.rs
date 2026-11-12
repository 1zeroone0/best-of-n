use vstd::prelude::*;

verus! {

/// r is the larger of a and b.
pub open spec fn is_max(a: u64, b: u64, r: u64) -> bool { r >= a && r >= b && (r == a || r == b) }

/// r is twice n.
pub open spec fn is_double(n: u64, r: u64) -> bool { r == 2 * n }

} // verus!
