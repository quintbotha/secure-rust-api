use crate::db::user_repository::UserRepository;
use crate::models::user::User;
use crate::utils::auth::{create_jwt, hash_password, verify_password};
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use tracing::{error, info, warn};
use utoipa::ToSchema;

#[derive(Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub username: String,
    pub email: String,
    pub password: String,
}

#[derive(Deserialize, ToSchema)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}

#[derive(Serialize, ToSchema)]
pub struct AuthResponse {
    pub token: String,
    pub user: UserResponse,
}

#[derive(Serialize, ToSchema)]
pub struct UserResponse {
    pub id: String,
    pub username: String,
    pub email: String,
}

/// Register a new user
#[utoipa::path(
    post,
    path = "/api/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "User registered successfully", body = AuthResponse),
        (status = 400, description = "Invalid input")
    ),
    tag = "Authentication"
)]
pub async fn register(
    user_repo: web::Data<UserRepository>,
    payload: web::Json<RegisterRequest>,
) -> impl Responder {
    info!(username = %payload.username, email = %payload.email, "Registration attempt");

    // Validate input
    if payload.username.is_empty() || payload.email.is_empty() || payload.password.len() < 8 {
        warn!(username = %payload.username, email = %payload.email, "Registration failed: invalid input");
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Invalid input. Password must be at least 8 characters."
        }));
    }

    // Hash password
    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(e) => {
            error!(error = ?e, "Failed to hash password");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to hash password"
            }));
        }
    };

    // Create user
    let user = User {
        id: uuid::Uuid::new_v4().to_string(),
        username: payload.username.clone(),
        email: payload.email.clone(),
        password_hash,
        created_at: chrono::Utc::now(),
    };

    // Save to database
    let user = match user_repo.create(user).await {
        Ok(u) => u,
        Err(e) => {
            if e.contains("already exists") {
                warn!(email = %payload.email, "Registration failed: email already exists");
                return HttpResponse::Conflict().json(serde_json::json!({
                    "error": "Email already registered"
                }));
            }
            error!(error = %e, "Failed to create user in database");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to create user"
            }));
        }
    };

    // Generate JWT
    let token = match create_jwt(&user.id, &user.email) {
        Ok(t) => t,
        Err(e) => {
            error!(error = ?e, user_id = %user.id, "Failed to generate JWT");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate token"
            }));
        }
    };

    info!(user_id = %user.id, username = %user.username, "User registered successfully");

    HttpResponse::Created().json(AuthResponse {
        token,
        user: UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
        },
    })
}

/// Login an existing user
#[utoipa::path(
    post,
    path = "/api/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponse),
        (status = 401, description = "Invalid credentials")
    ),
    tag = "Authentication"
)]
pub async fn login(
    user_repo: web::Data<UserRepository>,
    payload: web::Json<LoginRequest>,
) -> impl Responder {
    info!(email = %payload.email, "Login attempt");

    // Fetch user from database
    let user = match user_repo.get_by_email(&payload.email).await {
        Ok(Some(u)) => u,
        Ok(None) => {
            warn!(email = %payload.email, "Login failed: user not found");
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "Invalid credentials"
            }));
        }
        Err(e) => {
            error!(error = %e, "Database error during login");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Server error"
            }));
        }
    };

    // Verify password
    if !verify_password(&payload.password, &user.password_hash) {
        warn!(email = %payload.email, "Login failed: invalid credentials");
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Invalid credentials"
        }));
    }

    // Generate JWT
    let token = match create_jwt(&user.id, &user.email) {
        Ok(t) => t,
        Err(e) => {
            error!(error = ?e, email = %payload.email, "Failed to generate JWT");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Failed to generate token"
            }));
        }
    };

    info!(email = %payload.email, user_id = %user.id, "User logged in successfully");

    HttpResponse::Ok().json(AuthResponse {
        token,
        user: UserResponse {
            id: user.id,
            username: user.username,
            email: user.email,
        },
    })
}
