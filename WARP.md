# WARP.md

This file provides guidance to WARP (warp.dev) when working with code in this repository.

## Development Commands

### Building and Running
```bash
# Run in development mode
cargo run

# Build release binary
cargo build --release

# Run with debug logging
RUST_LOG=debug cargo run
```

### Testing
```bash
# Run all tests
cargo test

# Run tests with verbose output
cargo test --verbose

# Run a specific test
cargo test test_name

# Run tests with logging
RUST_LOG=debug cargo test
```

### Code Quality
```bash
# Format code (always run before commits)
cargo fmt

# Check formatting
cargo fmt --all -- --check

# Run linter
cargo clippy

# Run clippy with all targets and features (CI standard)
cargo clippy --all-targets --all-features -- -D warnings

# Security audit
cargo audit
```

### Docker
```bash
# Build and start with Docker Compose
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

### Environment Setup
- Copy `.env.example` to `.env` before first run
- Set `JWT_SECRET` to a strong random value (never use the default in production)
- Database is automatically initialized at path specified by `DB_PATH` (default: `./data/sled.db`)

## Architecture Overview

### Core Components

**Authentication Flow**
- JWT-based authentication with 24-hour token expiration
- Argon2 password hashing with automatic salt generation
- Rate limiting on auth endpoints (5 requests/minute per IP)
- Claims stored in request extensions via middleware for protected routes

**Database Layer**
- Redb embedded database for persistent storage
- Two-table design: `users` table + `email_index` for fast email lookups
- UserRepository pattern abstracts all DB operations
- Serialization via JSON for flexibility
- Database instance cloned and shared via Arc across handlers

**Middleware Stack**
1. `TracingLogger` - Structured logging for all requests
2. `Cors` - CORS configuration for cross-origin requests
3. `RateLimitMiddleware` - IP-based rate limiting (auth routes only)
4. `AuthMiddleware` - JWT validation and claims extraction (secure routes only)

**Request Flow for Protected Endpoints**
1. Request hits `/api/secure/*` route
2. `AuthMiddleware` extracts and validates JWT from Authorization header
3. Claims inserted into request extensions
4. Handler extracts claims and user_id from extensions
5. Handler uses `UserRepository` to fetch/modify data
6. Response returned with appropriate status code

### Module Structure

- `main.rs` - Server initialization, route configuration, OpenAPI setup
- `lib.rs` - Module exports for library usage
- `handlers/` - Request handlers for auth and API endpoints
  - `auth.rs` - Registration and login
  - `api.rs` - Protected endpoints (profile, data, password change, account deletion)
- `middleware/` - Custom middleware
  - `auth.rs` - JWT validation middleware
  - `rate_limit.rs` - Rate limiting middleware using governor
- `models/` - Data structures
  - `user.rs` - User model and JWT Claims
- `utils/` - Utility functions
  - `auth.rs` - Password hashing, JWT creation/validation
- `db/` - Database layer
  - `mod.rs` - Database wrapper with Arc<RedbDatabase>
  - `user_repository.rs` - CRUD operations for users

### Key Design Patterns

**Repository Pattern**: All database access goes through `UserRepository`, making it easy to swap storage backends.

**Middleware Transform**: Both auth and rate limiting use actix-web's Transform pattern for composable request processing.

**Claims in Extensions**: JWT claims are validated once in middleware and stored in request extensions, avoiding repeated validation in handlers.

**Structured Logging**: All significant operations logged with tracing, including user_id, email, and error context.

### Security Considerations

- All authentication endpoints are rate-limited
- Passwords never stored in plaintext; always hashed with Argon2
- JWT secret must be set via environment variable
- Token expiration enforced at validation time
- Email uniqueness enforced at database level
- Error messages intentionally vague for auth failures ("Invalid credentials" instead of "User not found")

### Testing Notes

- Unit tests exist in `utils/auth.rs` for password hashing and JWT operations
- Integration tests exist in `db/user_repository.rs` for database operations
- Tests use `ENV_LOCK` mutex when modifying environment variables to prevent race conditions
- In-memory database available via `Database::in_memory()` for testing

### OpenAPI/Swagger

- Full OpenAPI documentation available at `/swagger-ui/`
- All endpoints documented with utoipa macros
- Schemas auto-generated from Rust types
- Bearer token authentication configured in security schemes
