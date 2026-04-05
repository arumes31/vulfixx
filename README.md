# CVE Tracker & Alerting System

[![Build and Publish Docker Image](https://github.com/your-username/cve-tracker/actions/workflows/docker.yml/badge.svg)](https://github.com/your-username/cve-tracker/actions)
[![Go Version](https://img.shields.io/badge/Go-1.24-00ADD8?style=flat&logo=go)](https://golang.org)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-316192?style=flat&logo=postgresql)](https://www.postgresql.org/)
[![Redis](https://img.shields.io/badge/Redis-7-DC382D?style=flat&logo=redis)](https://redis.io/)
[![Docker](https://img.shields.io/badge/Docker-Enabled-2496ED?style=flat&logo=docker)](https://www.docker.com/)

A secure, multi-user CVE (Common Vulnerabilities and Exposures) Tracking and Alerting Application. Designed for teams and individuals to monitor critical vulnerabilities, track their status, and receive proactive alerts. Built with a focus on self-containment, performance, and security.

---

## ✨ Features

- **Multi-User Capabilities:** Isolated workspaces and personal dashboard for each registered user.
- **Vulnerability Tracking:** Keep track of specific CVEs and organize their mitigation status.
- **Robust Authentication & Security:**
  - Mandatory Email Verification handled asynchronously via a Redis queue.
  - Optional TOTP (Time-based One-Time Password) Two-Factor Authentication.
  - IP-based Rate Limiting on all authentication endpoints to prevent brute-force attacks.
  - Strict CSRF protection and secure session management.
- **Proxy & Cloudflare Support:** Built-in IP resolution supporting `CF-Connecting-IP`, `X-Forwarded-For`, and `X-Real-IP`.
- **100% Self-Contained Frontend:** Zero reliance on external CDNs or remote resources. Fully built with vanilla HTML/CSS/JS and Go Templates.

## 🛠️ Technology Stack

- **Backend:** [Go](https://golang.org) (1.24)
- **Database:** PostgreSQL (with `pgx/v5` driver)
- **Caching & Queues:** Redis (with `go-redis/v9`)
- **Frontend:** Vanilla HTML5, CSS3, JavaScript + Go Templates (`html/template`)
- **Infrastructure:** Docker & Docker Compose
- **CI/CD:** GitHub Actions (Automated Docker builds on pushes to `main`)

## 🚀 Getting Started

### Prerequisites

Ensure you have the following installed on your local machine:
- [Docker](https://docs.docker.com/get-docker/) & Docker Compose
- [Go 1.24+](https://golang.org/dl/) (if running or building locally without Docker)

### Installation & Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-username/cve-tracker.git
   cd cve-tracker
   ```

2. **Environment Configuration:**
   The application requires specific environment variables for security. You must provide `SESSION_KEY` and `CSRF_KEY`, both of which **must be exactly 32 bytes**.

   Create a `.env` file in the root directory (or configure them in your environment/docker-compose):
   ```env
   # Security Keys (Must be EXACTLY 32 bytes)
   SESSION_KEY=your_32_byte_session_secret_key_
   CSRF_KEY=your_32_byte_csrf_secret_key_here

   # Proxy Settings
   ENABLE_CLOUDFLARE_PROXY=false # Set to true if behind Cloudflare

   # Database & Redis (Defaults in docker-compose)
   DATABASE_URL=postgres://postgres:postgres@db:5432/cvetracker?sslmode=disable
   REDIS_URL=redis://redis:6379/0
   ```

### Running Locally

**Using Docker Compose (Recommended):**
The easiest way to spin up the entire stack (App, PostgreSQL, Redis) is using Docker Compose.
```bash
docker compose up -d
```
The application will be available at `http://localhost:8080`.

**Building the Binary Manually:**
To build the Go binary directly:
```bash
go build ./cmd/cve-tracker
```
Make sure you have PostgreSQL and Redis instances running and properly configured in your environment variables before executing the binary.

## 🛡️ Security Architecture

Security is a first-class citizen in this project:
- **Authentication:** Sessions managed via `gorilla/sessions`, secured by the 32-byte `SESSION_KEY`.
- **CSRF Protection:** Integrated `gorilla/csrf` middleware requires a 32-byte `CSRF_KEY`.
- **Rate Limiting:** `golang.org/x/time/rate` manages strict IP-based rate limiting to thwart credential stuffing and brute force attempts.
- **2FA:** Implements TOTP algorithms utilizing the `github.com/pquerna/otp` library.
- **Privacy:** Frontend is entirely self-hosted to ensure no third-party tracking or remote asset injection.

## 📦 CI/CD Pipeline

The repository utilizes **GitHub Actions** for continuous integration and delivery.
On every push to the `main` branch, the workflow automatically builds the Docker image and publishes it to the configured container registry.

## 📄 License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
