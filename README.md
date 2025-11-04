# Secure REST API in Rust

[![CI](https://github.com/quintbotha/secure-rust-api/actions/workflows/ci.yml/badge.svg)](https://github.com/quintbotha/secure-rust-api/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

A production-ready, secure REST API built with Rust, featuring JWT authentication, password hashing with Argon2, and CORS support.

## ⚠️ Disclaimer

**THIS SOFTWARE IS PROVIDED "AS IS" FOR EDUCATIONAL AND DEMONSTRATION PURPOSES ONLY.**

This project is a reference implementation and should not be used directly in production without:
- Proper security auditing
- Thorough testing in your specific environment
- Additional security hardening based on your requirements
- Regular security updates and maintenance

**The author assumes no liability for any damages, security breaches, or data loss that may occur from using this software. Use at your own risk.**

## 🔐 Security Features

- **JWT Authentication**: Stateless authentication using JSON Web Tokens
- **Argon2 Password Hashing**: Industry-standard password hashing algorithm
- **Rate Limiting**: In-memory IP-based rate limiting on authentication endpoints
- **CORS Configuration**: Cross-Origin Resource Sharing protection
- **Secure Headers**: HTTP security headers implementation
- **Token Expiration**: Automatic token expiration (24 hours)
- **Environment Variables**: Sensitive configuration via environment variables
- **Persistent Storage**: Sled embedded database for user data

## 🚀 Tech Stack

- **actix-web**: High-performance async web framework
- **tokio**: Async runtime
- **jsonwebtoken**: JWT implementation
- **argon2**: Password hashing
- **serde**: Serialization/deserialization
- **chrono**: Date and time handling
- **dotenvy**: Environment variable management
- **sled**: Embedded database
- **governor**: Rate limiting

## 📁 Project Structure

```
secure-rust-api/
├── src/
│   ├── handlers/       # Request handlers
│   │   ├── auth.rs     # Authentication endpoints
│   │   └── api.rs      # API endpoints
│   ├── middleware/     # Custom middleware
│   │   └── auth.rs     # JWT authentication middleware
│   ├── models/         # Data models
│   │   └── user.rs     # User and Claims models
│   ├── utils/          # Utility functions
│   │   └── auth.rs     # Auth utilities (hashing, JWT)
│   └── main.rs         # Application entry point
├── Cargo.toml          # Dependencies
├── .env.example        # Environment variables template
└── README.md           # This file
```

## 🛠️ Setup

### Prerequisites

- Rust 1.70+ (install from [rustup.rs](https://rustup.rs))
- Cargo (comes with Rust)

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/quintbotha/secure-rust-api.git
   cd secure-rust-api
   ```

2. **Create environment file**:
   ```bash
   cp .env.example .env
   ```

3. **Edit `.env` and set a strong JWT secret**:
   ```env
   JWT_SECRET=your-very-strong-random-secret-key-here
   ```

4. **Build the project**:
   ```bash
   cargo build --release
   ```

5. **Run the server**:
   ```bash
   cargo run
   ```

The server will start on `http://127.0.0.1:8080`

## 📡 API Endpoints

### Public Endpoints

#### Health Check
```bash
GET /api/health
```

**Response**:
```json
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

#### Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "username": "john_doe",
  "email": "john@example.com",
  "password": "securepassword123"
}
```

**Response**:
```json
{
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "user": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "username": "john_doe",
    "email": "john@example.com"
  }
}
```

#### Login User
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "john@example.com",
  "password": "password123"
}
```

**Response**: Same as register

### Protected Endpoints

These endpoints require a valid JWT token in the Authorization header.

#### Get Secure Data
```bash
GET /api/secure/data
Authorization: Bearer <your-jwt-token>
```

**Response**:
```json
{
  "message": "This is protected data",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "data": ["Sensitive item 1", "Sensitive item 2", "Sensitive item 3"]
}
```

#### Get User Profile
```bash
GET /api/secure/profile
Authorization: Bearer <your-jwt-token>
```

**Response**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "email": "john@example.com",
  "exp": 1704117600
}
```

#### Update User Profile
```bash
PATCH /api/secure/profile
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "username": "new_username",
  "email": "newemail@example.com"
}
```

**Response**:
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "username": "new_username",
  "email": "newemail@example.com",
  "updated_at": "2024-01-01T12:00:00Z"
}
```

#### Change Password
```bash
POST /api/secure/change-password
Authorization: Bearer <your-jwt-token>
Content-Type: application/json

{
  "old_password": "currentpassword123",
  "new_password": "newpassword456"
}
```

**Response**:
```json
{
  "message": "Password changed successfully",
  "changed_at": "2024-01-01T12:00:00Z"
}
```

#### Delete Account
```bash
DELETE /api/secure/account
Authorization: Bearer <your-jwt-token>
```

**Response**:
```json
{
  "message": "Account deleted successfully",
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "deleted_at": "2024-01-01T12:00:00Z"
}
```

## 🧪 Testing with cURL

### Register a new user
```bash
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "securepass123"
  }'
```

### Login (demo credentials)
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "test@example.com",
    "password": "password123"
  }'
```

### Access protected endpoint
```bash
# Replace <TOKEN> with the JWT from login/register
curl -X GET http://localhost:8080/api/secure/data \
  -H "Authorization: Bearer <TOKEN>"
```

### Update profile
```bash
curl -X PATCH http://localhost:8080/api/secure/profile \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "newusername",
    "email": "newemail@example.com"
  }'
```

### Change password
```bash
curl -X POST http://localhost:8080/api/secure/change-password \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{
    "old_password": "oldpassword123",
    "new_password": "newpassword456"
  }'
```

### Delete account
```bash
curl -X DELETE http://localhost:8080/api/secure/account \
  -H "Authorization: Bearer <TOKEN>"
```

## 🔧 Configuration

Edit `.env` to customize:

```env
# Server Configuration
HOST=127.0.0.1      # Bind address
PORT=8080           # Port number

# JWT Configuration
JWT_SECRET=your-secret-key  # Change this!

# Logging
RUST_LOG=info       # Log level (debug, info, warn, error)
```

## 🛡️ Security Best Practices

1. **Change the JWT Secret**: Always use a strong, random secret in production
2. **Use HTTPS**: Deploy behind a reverse proxy with TLS/SSL
3. **Rate Limiting**: Implement rate limiting for authentication endpoints
4. **Database**: Connect to a real database instead of in-memory storage
5. **Input Validation**: Add comprehensive input validation
6. **Error Handling**: Avoid exposing sensitive information in error messages
7. **Token Refresh**: Implement refresh tokens for long-lived sessions
8. **Password Requirements**: Enforce strong password policies

## 📝 Development

### Run in development mode
```bash
cargo run
```

### Run with debug logging
```bash
RUST_LOG=debug cargo run
```

### Format code
```bash
cargo fmt
```

### Run linter
```bash
cargo clippy
```

### Run tests
```bash
cargo test
```

## 🚀 Production Deployment

1. Build optimized release binary:
   ```bash
   cargo build --release
   ```

2. Binary location: `./target/release/secure-rust-api`

3. Set environment variables securely (never commit `.env`)

4. Use a process manager (systemd, PM2, etc.)

5. Deploy behind a reverse proxy (nginx, Caddy)

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

**Key Points:**
- ✅ Free to use, modify, and distribute
- ✅ Commercial use allowed
- ❌ No warranty provided
- ❌ Author not liable for damages

## 🤝 Contributing

Contributions welcome! Please feel free to submit a Pull Request.

By contributing, you agree that your contributions will be licensed under the MIT License.

## 📚 Resources

- [Actix Web Documentation](https://actix.rs/)
- [Rust Book](https://doc.rust-lang.org/book/)
- [JWT.io](https://jwt.io/)
- [OWASP Security Guidelines](https://owasp.org/)
