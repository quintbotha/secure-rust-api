mod db;
mod handlers;
mod middleware;
mod models;
mod utils;

use actix_cors::Cors;
use actix_web::{web, App, HttpServer};
use db::user_repository::UserRepository;
use db::Database;
use dotenv::dotenv;
use middleware::rate_limit::RateLimitMiddleware;
use std::env;
use tracing::info;
use tracing_actix_web::TracingLogger;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

#[derive(OpenApi)]
#[openapi(
    paths(
        handlers::api::health,
        handlers::api::get_secure_data,
        handlers::api::create_secure_data,
        handlers::api::get_user_profile,
        handlers::api::update_user_profile,
        handlers::api::change_password,
        handlers::api::delete_account,
        handlers::auth::register,
        handlers::auth::login,
    ),
    components(
        schemas(
            handlers::api::HealthResponse,
            handlers::api::HealthChecks,
            handlers::api::SecureDataResponse,
            handlers::api::CreateDataRequest,
            handlers::api::CreateDataResponse,
            handlers::api::UpdateProfileRequest,
            handlers::api::UpdateProfileResponse,
            handlers::api::ChangePasswordRequest,
            handlers::api::ChangePasswordResponse,
            handlers::api::DeleteAccountResponse,
            handlers::auth::RegisterRequest,
            handlers::auth::LoginRequest,
            handlers::auth::AuthResponse,
            handlers::auth::UserResponse,
            models::user::User,
            models::user::Claims,
        )
    ),
    tags(
        (name = "Health", description = "Health check endpoints"),
        (name = "Authentication", description = "User authentication endpoints"),
        (name = "Secure", description = "Protected endpoints requiring JWT authentication")
    ),
    modifiers(&SecurityAddon)
)]
struct ApiDoc;

struct SecurityAddon;

impl utoipa::Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            use utoipa::openapi::security::{HttpAuthScheme, HttpBuilder, SecurityScheme};

            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    HttpBuilder::new()
                        .scheme(HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .description(Some("Enter your JWT token"))
                        .build(),
                ),
            );
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();

    // Initialize tracing subscriber for structured logging
    let log_level = env::var("RUST_LOG").unwrap_or_else(|_| "info".to_string());

    tracing_subscriber::fmt()
        .with_env_filter(log_level)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .json()
        .init();

    // Initialize database
    let db_path = env::var("DB_PATH").unwrap_or_else(|_| "./data/sled.db".to_string());
    let database = Database::new(&db_path)
        .expect("Failed to initialize database");
    info!(db_path = %db_path, "Database initialized");

    let host = env::var("HOST").unwrap_or_else(|_| "127.0.0.1".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8080".to_string());
    let bind_address = format!("{}:{}", host, port);

    info!(bind_address = %bind_address, "Starting secure REST API server");
    info!("Available endpoints:");
    info!("   GET  /api/health          - Health check (public)");
    info!("   POST /api/auth/register   - Register new user (public)");
    info!("   POST /api/auth/login      - Login user (public)");
    info!("   GET  /api/secure/data            - Get secure data (protected)");
    info!("   POST /api/secure/data            - Create secure data (protected)");
    info!("   GET  /api/secure/profile         - Get user profile (protected)");
    info!("   PATCH /api/secure/profile        - Update user profile (protected)");
    info!("   POST /api/secure/change-password - Change password (protected)");
    info!("   DELETE /api/secure/account       - Delete account (protected)");
    info!(
        swagger_url = format!("http://{}/swagger-ui/", bind_address),
        "Swagger UI available"
    );

    HttpServer::new(move || {
        let user_repo = UserRepository::new(database.clone());
        
        // Configure CORS
        let cors = Cors::default()
            .allow_any_origin()
            .allowed_methods(vec!["GET", "POST", "PUT", "DELETE"])
            .allowed_headers(vec![
                actix_web::http::header::AUTHORIZATION,
                actix_web::http::header::ACCEPT,
                actix_web::http::header::CONTENT_TYPE,
            ])
            .max_age(3600);

        let openapi = ApiDoc::openapi();

        App::new()
            .app_data(web::Data::new(user_repo))
            .wrap(TracingLogger::default())
            .wrap(cors)
            // Swagger UI
            .service(SwaggerUi::new("/swagger-ui/{_:.*}").url("/api-docs/openapi.json", openapi))
            // Public routes
            .route("/api/health", web::get().to(handlers::api::health))
            // Auth routes with rate limiting (5 requests per minute per IP)
            .service(
                web::scope("/api/auth")
                    .wrap(RateLimitMiddleware::new(5))
                    .route("/register", web::post().to(handlers::auth::register))
                    .route("/login", web::post().to(handlers::auth::login)),
            )
            // Protected routes
            .service(
                web::scope("/api/secure")
                    .wrap(middleware::auth::AuthMiddleware)
                    .route("/data", web::get().to(handlers::api::get_secure_data))
                    .route("/data", web::post().to(handlers::api::create_secure_data))
                    .route("/profile", web::get().to(handlers::api::get_user_profile))
                    .route(
                        "/profile",
                        web::patch().to(handlers::api::update_user_profile),
                    )
                    .route(
                        "/change-password",
                        web::post().to(handlers::api::change_password),
                    )
                    .route("/account", web::delete().to(handlers::api::delete_account)),
            )
    })
    .bind(&bind_address)?
    .run()
    .await
}
