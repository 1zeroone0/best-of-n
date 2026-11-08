//! The kernel's entry point for programs in WebAssembly: the program writes a
//! search's words (as the trace records them) into memory from `alloc`, and
//! calls a gate. Only the pointer-to-words step is here; decoding and deciding
//! are the kernel's.

use crate::exec::Kernel;
use crate::gates::{Encoding, Gates};

/// A gate's answer when it names no candidate.
pub const NONE: i32 = -1;
/// A gate's answer when the words are not a search (or name no such agent process).
pub const NOT_A_SEARCH: i32 = -2;

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

/// The selected gate on one search: its index, NONE, or NOT_A_SEARCH.
#[no_mangle]
pub unsafe extern "C" fn selected(p: *const u64, len: usize) -> i32 {
    match Kernel::decode(&words(p, len)) {
        Some(s) => Kernel::selected(&s).map_or(NONE, |i| i as i32),
        None => NOT_A_SEARCH,
    }
}

/// The not_found gate on x, a counterexample search, and t, the search it
/// tested: 1 not found, 0 found, or NOT_A_SEARCH if either is not one.
#[no_mangle]
pub unsafe extern "C" fn not_found(x: *const u64, xlen: usize, t: *const u64, tlen: usize) -> i32 {
    match (Kernel::decode(&words(x, xlen)), Kernel::decode(&words(t, tlen))) {
        (Some(x), Some(t)) => Kernel::not_found(&x, &t) as i32,
        _ => NOT_A_SEARCH,
    }
}

/// The found_on_trunk gate on a counterexample search of trunk: the index of
/// the test a code search carries, NONE, or NOT_A_SEARCH.
#[no_mangle]
pub unsafe extern "C" fn found_on_trunk(p: *const u64, len: usize) -> i32 {
    match Kernel::decode(&words(p, len)) {
        Some(s) => Kernel::found_on_trunk(&s).map_or(NONE, |i| i as i32),
        None => NOT_A_SEARCH,
    }
}

/// The verified gate on candidate i of one search: 1 verified, 0 not (or no
/// candidate), or NOT_A_SEARCH.
#[no_mangle]
pub unsafe extern "C" fn verified(p: *const u64, len: usize, i: usize) -> i32 {
    match Kernel::decode(&words(p, len)) {
        Some(s) => match s.results.get(i) {
            Some(Some(c)) => Kernel::verified(&s, c) as i32,
            Some(None) => 0,
            None => NOT_A_SEARCH,
        },
        None => NOT_A_SEARCH,
    }
}

static EMITTED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// One search as the kernel's JSON, in the spec's names (UTF-8): a pointer to
/// it, its length from `emitted`, freed with `dealloc_bytes`; null if the
/// words are not a search.
#[no_mangle]
pub unsafe extern "C" fn emit(p: *const u64, len: usize) -> *mut u8 {
    let Some(s) = Kernel::decode(&words(p, len)) else { return std::ptr::null_mut() };
    let mut b = Kernel::emit(&s).into_iter().collect::<String>().into_bytes();
    b.shrink_to_fit();
    EMITTED.store(b.len(), std::sync::atomic::Ordering::SeqCst);
    let q = b.as_mut_ptr();
    std::mem::forget(b);
    q
}

/// The length of the last `emit`.
#[no_mangle]
pub extern "C" fn emitted() -> usize { EMITTED.load(std::sync::atomic::Ordering::SeqCst) }

/// Return memory from `emit`.
#[no_mangle]
pub unsafe extern "C" fn dealloc_bytes(p: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(p, len, len));
}
