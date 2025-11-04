pub mod user_repository;

use redb::{Database as RedbDatabase, Error};
use std::sync::Arc;

#[derive(Clone)]
pub struct Database {
    pub db: Arc<RedbDatabase>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, Error> {
        let db = RedbDatabase::create(path)?;
        Ok(Database { db: Arc::new(db) })
    }

    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, Error> {
        // Create a temporary file for in-memory testing
        let temp_dir = std::env::temp_dir();
        let temp_path = temp_dir.join(format!("test-{}.redb", uuid::Uuid::new_v4()));
        let db = RedbDatabase::create(&temp_path)?;
        Ok(Database { db: Arc::new(db) })
    }
}
