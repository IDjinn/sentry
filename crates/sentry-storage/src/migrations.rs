//! Migrations runner.
//!
//! Migrations live in `crates/sentry-storage/migrations/*.sql` and are
//! embedded at compile time via `sqlx::migrate!`.

use crate::error::{Result, StorageError};
use crate::pool::PgPool;

/// Run all pending migrations.
pub async fn run(pool: &PgPool) -> Result<()> {
    sqlx::migrate!("./migrations")
        .run(pool.inner())
        .await
        .map_err(|e| StorageError::Migrate(e.to_string()))?;
    Ok(())
}
