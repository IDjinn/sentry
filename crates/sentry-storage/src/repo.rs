//! Repositories: typed access to each table.
//!
//! Placeholder — concrete queries land in F1.3. For now we expose the pool
//! so the daemon can use it directly.

use crate::pool::PgPool;

/// Generic repo handle carrying the pool.
#[derive(Clone)]
pub struct Repo {
    pool: PgPool,
}

impl Repo {
    /// Create a repo backed by the given pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Access the underlying pool.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }
}
