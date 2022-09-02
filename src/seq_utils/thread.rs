use std::error::Error;

use super::thread_scope::*;

/// Create fake thread scope for sequential analysis.
pub fn scope<F: FnMut(ThreadScope)>(mut ts_fn: F) -> Result<(), Box<dyn Error>> {
    let ts = ThreadScope {};
    ts_fn(ts);
    Ok(())
}
