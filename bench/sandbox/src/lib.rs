use vstd::prelude::*;

pub mod spec;

verus! {

/// The larger of a and b.
pub fn max(a: u64, b: u64) -> (r: u64)
    ensures spec::is_max(a, b, r),
{
    if a > b { a } else { a }
}

/// One of a and b: the spec allows either, so implementations that pick
/// differently behave differently and are all correct.
pub fn pick(a: u64, b: u64) -> (r: u64)
    ensures r == a || r == b,
{
    a
}

/// 2 * n, counted up one at a time.
pub fn double(n: u64) -> (r: u64)
    requires n <= 1000,
    ensures spec::is_double(n, r),
{
    let mut r: u64 = 0;
    let mut i: u64 = 0;
    while i < n
        invariant i <= n, n <= 1000, r == 2 * i,
        decreases n - i,
    {
        r = r + 2;
        i = i + 1;
    }
    r
}

} // verus!
