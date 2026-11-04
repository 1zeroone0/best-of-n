//! The verified gates, exported to WebAssembly for the view. The view writes a
//! search.json (see wire.rs) into memory from `alloc` and calls a gate on it.
//! Trusted: part of the TCB.

use crate::{exec, wire};

/// Memory for the view to write len bytes of JSON into.
#[no_mangle]
pub extern "C" fn alloc(len: usize) -> *mut u8 {
    let mut b = Vec::<u8>::with_capacity(len);
    let p = b.as_mut_ptr();
    std::mem::forget(b);
    p
}

/// Return memory from `alloc`.
#[no_mangle]
pub unsafe extern "C" fn dealloc(p: *mut u8, len: usize) {
    drop(Vec::from_raw_parts(p, 0, len));
}

unsafe fn json(p: *const u8, len: usize) -> Option<serde_json::Value> {
    serde_json::from_slice(std::slice::from_raw_parts(p, len)).ok()
}

/// The selected gate on one search: its index, -1 for none, -2 if the JSON
/// is not a search.
#[no_mangle]
pub unsafe extern "C" fn selected(p: *const u8, len: usize) -> i32 {
    match json(p, len).as_ref().and_then(wire::parse_search) {
        Some(s) => exec::selected(&s).map_or(-1, |i| i as i32),
        None => -2,
    }
}

/// The cleared gate on {"x": counterexample search, "t": the search it tested}:
/// 1 cleared, 0 not, -2 if the JSON is not two searches.
#[no_mangle]
pub unsafe extern "C" fn cleared(p: *const u8, len: usize) -> i32 {
    let v = match json(p, len) { Some(v) => v, None => return -2 };
    match (wire::parse_search(&v["x"]), wire::parse_search(&v["t"])) {
        (Some(x), Some(t)) => exec::cleared(&x, &t) as i32,
        _ => -2,
    }
}
