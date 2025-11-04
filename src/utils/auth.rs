use crate::models::user::Claims;
use argon2::{
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use rand_core::OsRng;
use std::env;

/// Hash a password using Argon2
pub fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let password_hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(password_hash.to_string())
}

/// Verify a password against a hash
pub fn verify_password(password: &str, password_hash: &str) -> bool {
    let parsed_hash = match PasswordHash::new(password_hash) {
        Ok(h) => h,
        Err(_) => return false,
    };
    let argon2 = Argon2::default();

    argon2
        .verify_password(password.as_bytes(), &parsed_hash)
        .is_ok()
}

/// Create a JWT token
pub fn create_jwt(user_id: &str, email: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-secret-key-change-in-production".to_string());
    let expiration = chrono::Utc::now()
        .checked_add_signed(chrono::Duration::hours(24))
        .expect("valid timestamp")
        .timestamp() as usize;

    let claims = Claims {
        sub: user_id.to_owned(),
        email: email.to_owned(),
        exp: expiration,
        iat: chrono::Utc::now().timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_ref()),
    )
}

/// Decode and validate a JWT token
pub fn decode_jwt(token: &str) -> Result<Claims, jsonwebtoken::errors::Error> {
    let secret = env::var("JWT_SECRET")
        .unwrap_or_else(|_| "your-secret-key-change-in-production".to_string());

    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_ref()),
        &Validation::default(),
    )?;

    Ok(token_data.claims)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // Ensure tests that modify env vars run serially
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn test_hash_password_returns_hash() {
        let password = "test_password_123";
        let result = hash_password(password);

        assert!(result.is_ok());
        let hash = result.unwrap();
        assert!(!hash.is_empty());
        assert_ne!(hash, password);
    }

    #[test]
    fn test_hash_password_different_each_time() {
        let password = "test_password_123";
        let hash1 = hash_password(password).unwrap();
        let hash2 = hash_password(password).unwrap();

        // Even with same password, hashes should differ due to salt
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_verify_password_correct() {
        let password = "correct_password";
        let hash = hash_password(password).unwrap();

        let result = verify_password(password, &hash);
        assert!(result);
    }

    #[test]
    fn test_verify_password_incorrect() {
        let password = "correct_password";
        let wrong_password = "wrong_password";
        let hash = hash_password(password).unwrap();

        let result = verify_password(wrong_password, &hash);
        assert!(!result);
    }

    #[test]
    fn test_create_jwt_returns_token() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("JWT_SECRET", "test-secret-key");

        let user_id = "test-user-123";
        let email = "test@example.com";

        let result = create_jwt(user_id, email);
        assert!(result.is_ok());

        let token = result.unwrap();
        assert!(!token.is_empty());
        assert!(token.contains('.'));
    }

    #[test]
    fn test_decode_jwt_valid_token() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("JWT_SECRET", "test-secret-key");

        let user_id = "test-user-456";
        let email = "decode@example.com";

        let token = create_jwt(user_id, email).unwrap();
        let result = decode_jwt(&token);

        assert!(result.is_ok());
        let claims = result.unwrap();
        assert_eq!(claims.sub, user_id);
        assert_eq!(claims.email, email);
    }

    #[test]
    fn test_decode_jwt_invalid_token() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("JWT_SECRET", "test-secret-key");

        let invalid_token = "invalid.token.here";
        let result = decode_jwt(invalid_token);

        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_wrong_secret() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("JWT_SECRET", "secret1");
        let token = create_jwt("user", "test@example.com").unwrap();

        env::set_var("JWT_SECRET", "secret2");
        let result = decode_jwt(&token);

        assert!(result.is_err());
    }

    #[test]
    fn test_jwt_expiration_is_future() {
        let _lock = ENV_LOCK.lock().unwrap();
        env::set_var("JWT_SECRET", "test-secret-key");

        let token = create_jwt("user", "test@example.com").unwrap();
        let claims = decode_jwt(&token).unwrap();

        let now = chrono::Utc::now().timestamp() as usize;
        assert!(claims.exp > now);
        assert!(claims.iat <= now);
    }
}
