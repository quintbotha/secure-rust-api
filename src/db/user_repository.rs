use crate::db::Database;
use crate::models::user::User;
use bincode::{Decode, Encode};
use std::str;
use tracing::info;

const USERS_TREE: &str = "users";
const EMAIL_INDEX_TREE: &str = "email_index";

#[derive(Debug, Encode, Decode)]
pub struct StoredUser {
    pub id: String,
    pub username: String,
    pub email: String,
    pub password_hash: String,
    pub created_at: i64, // Store as timestamp
}

impl From<User> for StoredUser {
    fn from(user: User) -> Self {
        StoredUser {
            id: user.id,
            username: user.username,
            email: user.email,
            password_hash: user.password_hash,
            created_at: user.created_at.timestamp(),
        }
    }
}

impl From<StoredUser> for User {
    fn from(stored: StoredUser) -> Self {
        User {
            id: stored.id,
            username: stored.username,
            email: stored.email,
            password_hash: stored.password_hash,
            created_at: chrono::DateTime::from_timestamp(stored.created_at, 0)
                .unwrap_or_else(chrono::Utc::now),
        }
    }
}

pub struct UserRepository {
    db: Database,
}

impl UserRepository {
    pub fn new(db: Database) -> Self {
        UserRepository { db }
    }

    pub async fn create(&self, user: User) -> Result<User, String> {
        let users_tree = self
            .db
            .db
            .open_tree(USERS_TREE)
            .map_err(|e| format!("Failed to open users tree: {}", e))?;

        let email_index = self
            .db
            .db
            .open_tree(EMAIL_INDEX_TREE)
            .map_err(|e| format!("Failed to open email index: {}", e))?;

        // Check if email already exists
        if email_index
            .contains_key(user.email.as_bytes())
            .map_err(|e| e.to_string())?
        {
            return Err("Email already exists".to_string());
        }

        let stored_user = StoredUser::from(user.clone());
        let encoded = bincode::encode_to_vec(&stored_user, bincode::config::standard())
            .map_err(|e| format!("Failed to encode user: {}", e))?;

        users_tree
            .insert(user.id.as_bytes(), encoded.as_slice())
            .map_err(|e| format!("Failed to insert user: {}", e))?;

        // Create email index
        email_index
            .insert(user.email.as_bytes(), user.id.as_bytes())
            .map_err(|e| format!("Failed to create email index: {}", e))?;

        info!(user_id = %user.id, email = %user.email, "User created in database");

        Ok(user)
    }

    pub async fn get_by_id(&self, id: &str) -> Result<Option<User>, String> {
        let users_tree = self
            .db
            .db
            .open_tree(USERS_TREE)
            .map_err(|e| format!("Failed to open users tree: {}", e))?;

        match users_tree
            .get(id.as_bytes())
            .map_err(|e| format!("Failed to get user: {}", e))?
        {
            Some(data) => {
                let (stored_user, _): (StoredUser, usize) =
                    bincode::decode_from_slice(&data, bincode::config::standard())
                        .map_err(|e| format!("Failed to decode user: {}", e))?;
                Ok(Some(User::from(stored_user)))
            }
            None => Ok(None),
        }
    }

    pub async fn get_by_email(&self, email: &str) -> Result<Option<User>, String> {
        let email_index = self
            .db
            .db
            .open_tree(EMAIL_INDEX_TREE)
            .map_err(|e| format!("Failed to open email index: {}", e))?;

        match email_index
            .get(email.as_bytes())
            .map_err(|e| format!("Failed to get email index: {}", e))?
        {
            Some(user_id) => {
                let id = str::from_utf8(&user_id).map_err(|e| format!("Invalid user ID: {}", e))?;
                self.get_by_id(id).await
            }
            None => Ok(None),
        }
    }

    #[allow(dead_code)]
    pub async fn update(&self, user: User) -> Result<User, String> {
        let users_tree = self
            .db
            .db
            .open_tree(USERS_TREE)
            .map_err(|e| format!("Failed to open users tree: {}", e))?;

        // Check if user exists
        if !users_tree
            .contains_key(user.id.as_bytes())
            .map_err(|e| e.to_string())?
        {
            return Err("User not found".to_string());
        }

        let stored_user = StoredUser::from(user.clone());
        let encoded = bincode::encode_to_vec(&stored_user, bincode::config::standard())
            .map_err(|e| format!("Failed to encode user: {}", e))?;

        users_tree
            .insert(user.id.as_bytes(), encoded.as_slice())
            .map_err(|e| format!("Failed to update user: {}", e))?;

        info!(user_id = %user.id, "User updated in database");

        Ok(user)
    }

    pub async fn update_password(&self, id: &str, new_password_hash: &str) -> Result<(), String> {
        let users_tree = self
            .db
            .db
            .open_tree(USERS_TREE)
            .map_err(|e| format!("Failed to open users tree: {}", e))?;

        // Get existing user
        let mut user = self
            .get_by_id(id)
            .await?
            .ok_or_else(|| "User not found".to_string())?;

        // Update password hash
        user.password_hash = new_password_hash.to_string();

        let stored_user = StoredUser::from(user);
        let encoded = bincode::encode_to_vec(&stored_user, bincode::config::standard())
            .map_err(|e| format!("Failed to encode user: {}", e))?;

        users_tree
            .insert(id.as_bytes(), encoded.as_slice())
            .map_err(|e| format!("Failed to update password: {}", e))?;

        info!(user_id = %id, "User password updated in database");

        Ok(())
    }

    #[allow(dead_code)]
    pub async fn delete(&self, id: &str) -> Result<bool, String> {
        let users_tree = self
            .db
            .db
            .open_tree(USERS_TREE)
            .map_err(|e| format!("Failed to open users tree: {}", e))?;

        let email_index = self
            .db
            .db
            .open_tree(EMAIL_INDEX_TREE)
            .map_err(|e| format!("Failed to open email index: {}", e))?;

        // Get user to find email before deleting
        if let Some(user) = self.get_by_id(id).await? {
            // Delete from email index
            email_index
                .remove(user.email.as_bytes())
                .map_err(|e| format!("Failed to remove email index: {}", e))?;

            // Delete user
            users_tree
                .remove(id.as_bytes())
                .map_err(|e| format!("Failed to delete user: {}", e))?;

            info!(user_id = %id, "User deleted from database");
            Ok(true)
        } else {
            Ok(false)
        }
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
