use crate::models::user::Claims;
use actix_web::{web, HttpResponse, Responder};
use serde::{Deserialize, Serialize};
use std::env;
use tracing::{info, warn};
use utoipa::ToSchema;

#[derive(Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub timestamp: String,
    pub version: String,
    pub checks: HealthChecks,
}

#[derive(Serialize, ToSchema)]
pub struct HealthChecks {
    pub jwt_configured: bool,
    pub jwt_uses_default: bool,
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct SecureDataResponse {
    pub message: String,
    pub user_id: String,
    pub data: Vec<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateDataRequest {
    pub title: String,
    pub content: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateDataResponse {
    pub id: String,
    pub title: String,
    pub content: String,
    pub tags: Vec<String>,
    pub user_id: String,
    pub created_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateProfileRequest {
    pub username: Option<String>,
    pub email: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct UpdateProfileResponse {
    pub user_id: String,
    pub username: Option<String>,
    pub email: Option<String>,
    pub updated_at: String,
}

#[derive(Deserialize, ToSchema)]
pub struct ChangePasswordRequest {
    pub old_password: String,
    pub new_password: String,
}

#[derive(Serialize, ToSchema)]
pub struct ChangePasswordResponse {
    pub message: String,
    pub changed_at: String,
}

#[derive(Serialize, ToSchema)]
pub struct DeleteAccountResponse {
    pub message: String,
    pub user_id: String,
    pub deleted_at: String,
}

/// Public health check endpoint with dependency checks
#[utoipa::path(
    get,
    path = "/api/health",
    responses(
        (status = 200, description = "Service is healthy", body = HealthResponse),
        (status = 503, description = "Service is degraded")
    ),
    tag = "Health"
)]
pub async fn health() -> impl Responder {
    let jwt_secret = env::var("JWT_SECRET").ok();
    let default_secret = "your-secret-key-change-in-production";

    let jwt_configured = jwt_secret.is_some();
    let jwt_uses_default = jwt_secret.as_deref() == Some(default_secret);

    // Warn if using default JWT secret
    if jwt_uses_default {
        warn!("Health check: Using default JWT secret - NOT SECURE FOR PRODUCTION");
    }

    // Determine overall status
    let status = if jwt_uses_default {
        "degraded" // Using default secret is a security issue
    } else if jwt_configured {
        "healthy"
    } else {
        "degraded" // No JWT secret configured
    };

    let response = HealthResponse {
        status: status.to_string(),
        timestamp: chrono::Utc::now().to_rfc3339(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        checks: HealthChecks {
            jwt_configured,
            jwt_uses_default,
        },
    };

    if status == "healthy" {
        HttpResponse::Ok().json(response)
    } else {
        HttpResponse::ServiceUnavailable().json(response)
    }
}

/// Protected endpoint that requires authentication
#[utoipa::path(
    get,
    path = "/api/secure/data",
    responses(
        (status = 200, description = "Secure data retrieved", body = SecureDataResponse),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Secure"
)]
pub async fn get_secure_data(claims: web::ReqData<Claims>) -> impl Responder {
    HttpResponse::Ok().json(SecureDataResponse {
        message: "This is protected data".to_string(),
        user_id: claims.sub.clone(),
        data: vec![
            "Sensitive item 1".to_string(),
            "Sensitive item 2".to_string(),
            "Sensitive item 3".to_string(),
        ],
    })
}

/// Create new secure data (protected)
#[utoipa::path(
    post,
    path = "/api/secure/data",
    request_body = CreateDataRequest,
    responses(
        (status = 201, description = "Data created successfully", body = CreateDataResponse),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Secure"
)]
pub async fn create_secure_data(
    claims: web::ReqData<Claims>,
    payload: web::Json<CreateDataRequest>,
) -> impl Responder {
    // Validate input
    if payload.title.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Title is required"
        }));
    }

    if payload.content.is_empty() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "Content is required"
        }));
    }

    let data_id = uuid::Uuid::new_v4().to_string();
    let created_at = chrono::Utc::now();

    info!(
        user_id = %claims.sub,
        data_id = %data_id,
        title = %payload.title,
        "User created new data"
    );

    HttpResponse::Created().json(CreateDataResponse {
        id: data_id,
        title: payload.title.clone(),
        content: payload.content.clone(),
        tags: payload.tags.clone(),
        user_id: claims.sub.clone(),
        created_at: created_at.to_rfc3339(),
    })
}

/// Update user profile (protected)
#[utoipa::path(
    patch,
    path = "/api/secure/profile",
    request_body = UpdateProfileRequest,
    responses(
        (status = 200, description = "Profile updated successfully", body = UpdateProfileResponse),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Secure"
)]
pub async fn update_user_profile(
    claims: web::ReqData<Claims>,
    payload: web::Json<UpdateProfileRequest>,
) -> impl Responder {
    // Validate at least one field is being updated
    if payload.username.is_none() && payload.email.is_none() {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "At least one field (username or email) must be provided"
        }));
    }

    // Validate username if provided
    if let Some(ref username) = payload.username {
        if username.is_empty() || username.len() < 3 {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Username must be at least 3 characters"
            }));
        }
    }

    // Validate email if provided
    if let Some(ref email) = payload.email {
        if email.is_empty() || !email.contains('@') {
            return HttpResponse::BadRequest().json(serde_json::json!({
                "error": "Invalid email format"
            }));
        }
    }

    let updated_at = chrono::Utc::now();

    info!(
        user_id = %claims.sub,
        username = ?payload.username,
        email = ?payload.email,
        "User updated profile"
    );

    // In production, this would update the database
    HttpResponse::Ok().json(UpdateProfileResponse {
        user_id: claims.sub.clone(),
        username: payload.username.clone(),
        email: payload.email.clone(),
        updated_at: updated_at.to_rfc3339(),
    })
}

/// Get user profile from JWT claims
#[utoipa::path(
    get,
    path = "/api/secure/profile",
    responses(
        (status = 200, description = "User profile retrieved"),
        (status = 401, description = "Unauthorized")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Secure"
)]
pub async fn get_user_profile(claims: web::ReqData<Claims>) -> impl Responder {
    HttpResponse::Ok().json(serde_json::json!({
        "user_id": claims.sub,
        "email": claims.email,
        "exp": claims.exp,
    }))
}

/// Change user password (protected)
#[utoipa::path(
    post,
    path = "/api/secure/change-password",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed successfully", body = ChangePasswordResponse),
        (status = 400, description = "Invalid input"),
        (status = 401, description = "Unauthorized or incorrect old password")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Secure"
)]
pub async fn change_password(
    claims: web::ReqData<Claims>,
    payload: web::Json<ChangePasswordRequest>,
    user_repo: web::Data<crate::db::user_repository::UserRepository>,
) -> impl Responder {
    use crate::utils::auth::{hash_password, verify_password};

    // Validate new password strength
    if payload.new_password.len() < 8 {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "New password must be at least 8 characters long"
        }));
    }

    if payload.old_password == payload.new_password {
        return HttpResponse::BadRequest().json(serde_json::json!({
            "error": "New password must be different from old password"
        }));
    }

    // Get user from database
    let user = match user_repo.get_by_id(&claims.sub).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return HttpResponse::Unauthorized().json(serde_json::json!({
                "error": "User not found"
            }));
        }
        Err(e) => {
            warn!(error = %e, "Failed to fetch user from database");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }));
        }
    };

    // Verify old password
    if !verify_password(&payload.old_password, &user.password_hash) {
        return HttpResponse::Unauthorized().json(serde_json::json!({
            "error": "Incorrect old password"
        }));
    }

    // Hash new password
    let new_password_hash = match hash_password(&payload.new_password) {
        Ok(hash) => hash,
        Err(e) => {
            warn!(error = %e, "Failed to hash password");
            return HttpResponse::InternalServerError().json(serde_json::json!({
                "error": "Internal server error"
            }));
        }
    };

    // Update password in database
    if let Err(e) = user_repo
        .update_password(&claims.sub, &new_password_hash)
        .await
    {
        warn!(error = %e, "Failed to update password");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to update password"
        }));
    }

    let changed_at = chrono::Utc::now();

    info!(
        user_id = %claims.sub,
        "User changed password"
    );

    HttpResponse::Ok().json(ChangePasswordResponse {
        message: "Password changed successfully".to_string(),
        changed_at: changed_at.to_rfc3339(),
    })
}

/// Delete user account (protected)
#[utoipa::path(
    delete,
    path = "/api/secure/account",
    responses(
        (status = 200, description = "Account deleted successfully", body = DeleteAccountResponse),
        (status = 401, description = "Unauthorized"),
        (status = 500, description = "Internal server error")
    ),
    security(
        ("bearer_auth" = [])
    ),
    tag = "Secure"
)]
pub async fn delete_account(
    claims: web::ReqData<Claims>,
    user_repo: web::Data<crate::db::user_repository::UserRepository>,
) -> impl Responder {
    // Delete user from database
    if let Err(e) = user_repo.delete(&claims.sub).await {
        warn!(error = %e, user_id = %claims.sub, "Failed to delete user account");
        return HttpResponse::InternalServerError().json(serde_json::json!({
            "error": "Failed to delete account"
        }));
    }

    let deleted_at = chrono::Utc::now();

    info!(
        user_id = %claims.sub,
        email = %claims.email,
        "User account deleted"
    );

    HttpResponse::Ok().json(DeleteAccountResponse {
        message: "Account deleted successfully".to_string(),
        user_id: claims.sub.clone(),
        deleted_at: deleted_at.to_rfc3339(),
    })
}
