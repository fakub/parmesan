pub struct ThreadScope {}

impl ThreadScope {

    /// Create fake thread spawn for sequential analysis.
    pub fn spawn<F: FnMut(())>(&self, mut spawn_fn: F) {
        spawn_fn(());
    }
}
