//! The kernel's entry point for programs in WebAssembly: the program writes a
//! search's words (as the trace records them) into memory from `alloc`, and
//! calls a gate. Only the pointer-to-words step is here; decoding and deciding
//! are the kernel's.

use crate::exec::Kernel;
use crate::gates::{Encoding, Gates};

/// Memory for len words.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u64 {
    let mut b = Vec::<u64>::with_capacity(len);
    let p = b.as_mut_ptr();
    std::mem::forget(b);
    p
}

/// Return memory from `alloc`.
#[no_mangle]
pub unsafe extern "C" fn dealloc(p: *mut u64, len: usize) {
    drop(Vec::from_raw_parts(p, 0, len));
}

unsafe fn words(p: *const u64, len: usize) -> Vec<u64> {
    std::slice::from_raw_parts(p, len).to_vec()
}

/// The selected gate on one search: its index, -1 for none, -2 if the words
/// are not a search.
#[no_mangle]
pub unsafe extern "C" fn selected(p: *const u64, len: usize) -> i32 {
    match Kernel::decode(&words(p, len)) {
        Some(s) => Kernel::selected(&s).map_or(-1, |i| i as i32),
        None => -2,
    }
}

/// The cleared gate on x, a counterexample search, and t, the search it
/// tested: 1 cleared, 0 not, -2 if either is not a search.
#[no_mangle]
pub unsafe extern "C" fn cleared(x: *const u64, xlen: usize, t: *const u64, tlen: usize) -> i32 {
    match (Kernel::decode(&words(x, xlen)), Kernel::decode(&words(t, tlen))) {
        (Some(x), Some(t)) => Kernel::cleared(&x, &t) as i32,
        _ => -2,
    }
}
