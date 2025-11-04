use crate::db::Database;
use crate::models::user::User;
use redb::{ReadableDatabase, ReadableTable, TableDefinition};
use tracing::info;

const USERS_TABLE: TableDefinition<&str, &str> = TableDefinition::new("users");
const EMAIL_INDEX_TABLE: TableDefinition<&str, &str> = TableDefinition::new("email_index");

pub struct UserRepository {
    db: Database,
}

impl UserRepository {
    pub fn new(db: Database) -> Self {
        UserRepository { db }
    }

    fn serialize_user(user: &User) -> String {
        serde_json::json!({
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "password_hash": user.password_hash,
            "created_at": user.created_at.timestamp()
        })
        .to_string()
    }

    fn deserialize_user(data: &str) -> Result<User, String> {
        let json: serde_json::Value =
            serde_json::from_str(data).map_err(|e| format!("Failed to parse JSON: {}", e))?;

        Ok(User {
            id: json["id"]
                .as_str()
                .ok_or("Missing id")?
                .to_string(),
            username: json["username"]
                .as_str()
                .ok_or("Missing username")?
                .to_string(),
            email: json["email"]
                .as_str()
                .ok_or("Missing email")?
                .to_string(),
            password_hash: json["password_hash"]
                .as_str()
                .ok_or("Missing password_hash")?
                .to_string(),
            created_at: chrono::DateTime::from_timestamp(
                json["created_at"].as_i64().ok_or("Missing created_at")?,
                0,
            )
            .unwrap_or_else(chrono::Utc::now),
        })
    }

    pub async fn create(&self, user: User) -> Result<User, String> {
        let write_txn = self
            .db
            .db
            .begin_write()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        {
            let mut users_table = write_txn
                .open_table(USERS_TABLE)
                .map_err(|e| format!("Failed to open users table: {}", e))?;

            let mut email_index = write_txn
                .open_table(EMAIL_INDEX_TABLE)
                .map_err(|e| format!("Failed to open email index: {}", e))?;

            // Check if email already exists
            if email_index.get(user.email.as_str()).is_ok_and(|v| v.is_some()) {
                return Err("Email already exists".to_string());
            }

            let serialized = Self::serialize_user(&user);

            users_table
                .insert(user.id.as_str(), serialized.as_str())
                .map_err(|e| format!("Failed to insert user: {}", e))?;

            email_index
                .insert(user.email.as_str(), user.id.as_str())
                .map_err(|e| format!("Failed to create email index: {}", e))?;
        }

        write_txn
            .commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        info!(user_id = %user.id, email = %user.email, "User created in database");

        Ok(user)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<User>, String> {
        let read_txn = self
            .db
            .db
            .begin_read()
            .map_err(|e| format!("Failed to begin read transaction: {}", e))?;

        let users_table = read_txn
            .open_table(USERS_TABLE)
            .map_err(|e| format!("Failed to open users table: {}", e))?;

        match users_table.get(id) {
            Ok(Some(data)) => {
                let user = Self::deserialize_user(data.value())?;
                Ok(Some(user))
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get user: {}", e)),
        }
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>, String> {
        let read_txn = self
            .db
            .db
            .begin_read()
            .map_err(|e| format!("Failed to begin read transaction: {}", e))?;

        let email_index = read_txn
            .open_table(EMAIL_INDEX_TABLE)
            .map_err(|e| format!("Failed to open email index: {}", e))?;

        match email_index.get(email) {
            Ok(Some(user_id)) => {
                let id = user_id.value();
                self.get_by_id(id).await
            }
            Ok(None) => Ok(None),
            Err(e) => Err(format!("Failed to get email index: {}", e)),
        }
    }

    #[allow(dead_code)]
    pub async fn update(&self, user: User) -> Result<User, String> {
        let write_txn = self
            .db
            .db
            .begin_write()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        {
            let mut users_table = write_txn
                .open_table(USERS_TABLE)
                .map_err(|e| format!("Failed to open users table: {}", e))?;

            // Check if user exists
            if users_table.get(user.id.as_str()).is_ok_and(|v| v.is_none()) {
                return Err("User not found".to_string());
            }

            let serialized = Self::serialize_user(&user);

            users_table
                .insert(user.id.as_str(), serialized.as_str())
                .map_err(|e| format!("Failed to update user: {}", e))?;
        }

        write_txn
            .commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        info!(user_id = %user.id, "User updated in database");

        Ok(user)
    }

    pub async fn update_password(&self, id: &str, new_password_hash: &str) -> Result<(), String> {
        // Get existing user
        let mut user = self
            .get_by_id(id)
            .await?
            .ok_or_else(|| "User not found".to_string())?;

        // Update password hash
        user.password_hash = new_password_hash.to_string();

        let write_txn = self
            .db
            .db
            .begin_write()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        {
            let mut users_table = write_txn
                .open_table(USERS_TABLE)
                .map_err(|e| format!("Failed to open users table: {}", e))?;

            let serialized = Self::serialize_user(&user);

            users_table
                .insert(id, serialized.as_str())
                .map_err(|e| format!("Failed to update password: {}", e))?;
        }

        write_txn
            .commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        info!(user_id = %id, "User password updated in database");

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn delete(&self, id: &str) -> Result<bool, String> {
        // Get user to find email before deleting
        let user = match self.get_by_id(id).await? {
            Some(u) => u,
            None => return Ok(false),
        };

        let write_txn = self
            .db
            .db
            .begin_write()
            .map_err(|e| format!("Failed to begin transaction: {}", e))?;

        {
            let mut users_table = write_txn
                .open_table(USERS_TABLE)
                .map_err(|e| format!("Failed to open users table: {}", e))?;

            let mut email_index = write_txn
                .open_table(EMAIL_INDEX_TABLE)
                .map_err(|e| format!("Failed to open email index: {}", e))?;

            // Delete from email index
            email_index
                .remove(user.email.as_str())
                .map_err(|e| format!("Failed to remove email index: {}", e))?;

            // Delete user
            users_table
                .remove(id)
                .map_err(|e| format!("Failed to delete user: {}", e))?;
        }

        write_txn
            .commit()
            .map_err(|e| format!("Failed to commit transaction: {}", e))?;

        info!(user_id = %id, "User deleted from database");
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    fn create_test_user() -> User {
        User {
            id: uuid::Uuid::new_v4().to_string(),
            username: "testuser".to_string(),
            email: "test@example.com".to_string(),
            password_hash: "hashed_password".to_string(),
            created_at: Utc::now(),
        }
    }

    #[tokio::test]
    async fn test_create_and_get_user() {
        let db = Database::in_memory().unwrap();
        let repo = UserRepository::new(db);
        let user = create_test_user();

        let created = repo.create(user.clone()).await.unwrap();
        assert_eq!(created.id, user.id);

        let retrieved = repo.get_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(retrieved.email, user.email);
    }

    #[tokio::test]
    async fn test_get_by_email() {
        let db = Database::in_memory().unwrap();
        let repo = UserRepository::new(db);
        let user = create_test_user();

        repo.create(user.clone()).await.unwrap();

        let retrieved = repo.get_by_email(&user.email).await.unwrap().unwrap();
        assert_eq!(retrieved.id, user.id);
    }

    #[tokio::test]
    async fn test_duplicate_email() {
        let db = Database::in_memory().unwrap();
        let repo = UserRepository::new(db);
        let user1 = create_test_user();

        repo.create(user1.clone()).await.unwrap();

        let mut user2 = create_test_user();
        user2.id = uuid::Uuid::new_v4().to_string();
        user2.email = user1.email.clone();

        let result = repo.create(user2).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("already exists"));
    }

    #[tokio::test]
    async fn test_update_user() {
        let db = Database::in_memory().unwrap();
        let repo = UserRepository::new(db);
        let mut user = create_test_user();

        repo.create(user.clone()).await.unwrap();

        user.username = "updated_username".to_string();
        repo.update(user.clone()).await.unwrap();

        let retrieved = repo.get_by_id(&user.id).await.unwrap().unwrap();
        assert_eq!(retrieved.username, "updated_username");
    }

    #[tokio::test]
    async fn test_delete_user() {
        let db = Database::in_memory().unwrap();
        let repo = UserRepository::new(db);
        let user = create_test_user();

        repo.create(user.clone()).await.unwrap();
        let deleted = repo.delete(&user.id).await.unwrap();
        assert!(deleted);

        let retrieved = repo.get_by_id(&user.id).await.unwrap();
        assert!(retrieved.is_none());
    }
}
