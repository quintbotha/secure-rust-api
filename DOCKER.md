# Docker Deployment Guide

## 🐳 Production-Ready Docker Setup

This project includes a secure, multi-stage Docker setup with the following features:

### Security Features
- ✅ **Distroless base image** - Minimal attack surface (no shell, no package manager)
- ✅ **Non-root user** - Runs as `nonroot` user (UID 65532)
- ✅ **Multi-stage build** - Small final image (~50MB)
- ✅ **Security options** - `no-new-privileges`, read-only where possible
- ✅ **Health checks** - Automatic container health monitoring
- ✅ **Network isolation** - Private Docker network

## 🚀 Quick Start

### 1. Set Environment Variables

Create a `.env` file in the project root:

```bash
JWT_SECRET=your-super-secure-random-jwt-secret-here
RUST_LOG=info
```

**Important:** Never use the default JWT secret in production!

### 2. Build and Run

```bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f api

# Check status
docker-compose ps
```

### 3. Test the API

```bash
# Health check
curl http://localhost:8080/api/health

# Register a user
curl -X POST http://localhost:8080/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "test@example.com",
    "password": "securepass123"
  }'
```

## 📦 Services

### API Service (`api`)
- **Image**: Custom built with Rust 1.89 + distroless
- **Port**: 8080
- **User**: nonroot (UID 65532)
- **Restart**: unless-stopped
- **Health Check**: `/api/health` endpoint

### Database Service (`db`)
- **Image**: busybox:1.36-musl (minimal)
- **Purpose**: Persistent volume management
- **User**: nonroot
- **Restart**: unless-stopped

## 📂 Data Persistence

Data is stored in named Docker volumes:

```bash
# List volumes
docker volume ls | grep secure-rust

# Inspect volume
docker volume inspect secure-rust-api-data

# Backup database
docker run --rm -v secure-rust-api-data:/data -v $(pwd):/backup \
  busybox tar czf /backup/backup.tar.gz -C /data .

# Restore database
docker run --rm -v secure-rust-api-data:/data -v $(pwd):/backup \
  busybox tar xzf /backup/backup.tar.gz -C /data
```

## 🔧 Management Commands

```bash
# Stop services
docker-compose down

# Stop and remove volumes (⚠️ deletes data)
docker-compose down -v

# Rebuild after code changes
docker-compose up -d --build

# View logs
docker-compose logs -f api

# Execute command in container (distroless has no shell)
docker-compose exec api /usr/local/bin/secure-rust-api --help

# Scale API (if load balancer configured)
docker-compose up -d --scale api=3
```

## 🔐 Security Best Practices

### 1. Environment Variables
Never commit `.env` files. Use secrets management:

```bash
# Use Docker secrets (Swarm mode)
docker secret create jwt_secret jwt_secret.txt
docker service create --secret jwt_secret ...

# Or use environment variables from CI/CD
JWT_SECRET=$(vault read -field=token secret/jwt) docker-compose up -d
```

### 2. Network Security

```bash
# Restrict external access
# In docker-compose.yml, remove port mapping and use reverse proxy
# ports:
#   - "127.0.0.1:8080:8080"  # Only localhost
```

### 3. Image Security

```bash
# Scan image for vulnerabilities
docker scan secure-rust-api:latest

# Use specific version tags
# FROM rust:1.89-slim-bookworm AS builder
```

### 4. Runtime Security

```bash
# Run with additional security options
docker run --rm \
  --security-opt=no-new-privileges:true \
  --cap-drop=ALL \
  --read-only \
  --tmpfs /tmp:noexec,nosuid,size=64M \
  secure-rust-api:latest
```

## 🚀 Production Deployment

### With Reverse Proxy (Recommended)

```yaml
# docker-compose.prod.yml
version: '3.9'

services:
  nginx:
    image: nginx:1.25-alpine
    ports:
      - "443:443"
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./ssl:/etc/ssl:ro
    depends_on:
      - api
    networks:
      - api_network

  api:
    # Remove direct port exposure
    # ports:
    #   - "8080:8080"
    expose:
      - "8080"
```

### Resource Limits

```yaml
services:
  api:
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
        reservations:
          cpus: '0.5'
          memory: 256M
```

## 📊 Monitoring

```bash
# Container stats
docker stats secure-rust-api

# Health status
docker inspect --format='{{.State.Health.Status}}' secure-rust-api

# Logs with timestamps
docker-compose logs -f --timestamps api
```

## 🐛 Troubleshooting

### Container won't start
```bash
# Check logs
docker-compose logs api

# Verify environment variables
docker-compose config
```

### Permission denied errors
```bash
# Fix volume permissions
docker-compose down
docker volume rm secure-rust-api-data
docker-compose up -d
```

### Cannot connect to API
```bash
# Check if port is bound
netstat -an | grep 8080

# Test from inside container network
docker run --network secure-rust-network curlimages/curl \
  curl http://secure-rust-api:8080/api/health
```

## 📝 Notes

- The distroless image has no shell - debugging requires multi-stage build with a debug stage
- Database files are stored in `/app/data/` inside the container
- Health checks ensure the container is marked unhealthy if the API fails
- All containers run as non-root for security
