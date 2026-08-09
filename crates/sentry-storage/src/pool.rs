//! Connection pool management.

use sqlx::postgres::{PgPool as SqlxPgPool, PgPoolOptions};

use sentry_core::config::PostgresConfig;

/// Wrapper around `sqlx::PgPool`.
#[derive(Clone)]
pub struct PgPool {
    pool: SqlxPgPool,
}

impl PgPool {
    /// Build a pool from config.
    pub async fn connect(cfg: &PostgresConfig) -> Result<Self> {
        if cfg.url.is_empty() {
            return Err(StorageError::Config("storage.postgres.url is empty".into()));
        }
        let pool = PgPoolOptions::new()
            .max_connections(cfg.max_connections)
            .connect(&cfg.url)
            .await
            .map_err(|e| StorageError::Connect(e.to_string()))?;
        Ok(Self { pool })
    }

    /// Access the underlying sqlx pool.
    pub fn inner(&self) -> &SqlxPgPool {
        &self.pool
    }
}

/// Storage-local error type.
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    #[error("storage config error: {0}")]
    Config(String),
    #[error("postgres connection error: {0}")]
    Connect(String),
    #[error("query error: {0}")]
    Query(String),
    #[error("migration error: {0}")]
    Migrate(String),
}

/// Convenience `Result` alias.
pub type Result<T> = std::result::Result<T, StorageError>;
