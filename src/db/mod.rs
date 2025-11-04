pub mod user_repository;

use sled::Db;
use std::sync::Arc;

#[derive(Clone)]
pub struct Database {
    pub db: Arc<Db>,
}

impl Database {
    pub fn new(path: &str) -> Result<Self, sled::Error> {
        let db = sled::open(path)?;
        Ok(Database { db: Arc::new(db) })
    }

    #[allow(dead_code)]
    pub fn in_memory() -> Result<Self, sled::Error> {
        let db = sled::Config::new().temporary(true).open()?;
        Ok(Database { db: Arc::new(db) })
    }
}
