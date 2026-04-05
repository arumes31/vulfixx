# CVE Tracker

A robust Go-based application for tracking and alerting on new Common Vulnerabilities and Exposures (CVEs) from the NIST NVD database.

## Features

- **Automated CVE Fetching**: Periodically synchronizes with the NIST NVD API.
- **Custom Subscriptions**: Users can subscribe to alerts based on keywords and CVSS severity scores.
- **Multi-Channel Alerts**: Supports both Email (SMTP) and Webhook notifications.
- **Secure Authentication**: Includes 2FA (TOTP) support and email verification.
- **Modern Infrastructure**: Containerized with Docker and orchestrated via Docker Compose.

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/arumes31/vulfixx.git
   cd vulfixx
   ```

2. Configure environment variables in `docker-compose.yml`:
   - `SMTP_HOST`: Your external SMTP server address.
   - `SMTP_PORT`: SMTP server port (e.g., 587).
   - `SMTP_USER`: SMTP username.
   - `SMTP_PASS`: SMTP password.
   - `SESSION_KEY`: A secure random string for session signing.

3. Start the application:
   ```bash
   docker-compose up --build
   ```

The application will be available at `http://localhost:8080`.

## Configuration

The application is configured via environment variables in the `docker-compose.yml` file:

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | `db` |
| `SMTP_HOST`| External SMTP server | `smtp.example.com` |
| `BASE_URL` | Application base URL | `http://localhost:8080` |

## Development

### Running Tests

To run the Go test suite:
```bash
go test ./...
```

### CI/CD Pipeline

This project uses GitHub Actions for continuous integration, covering:
- **Unit Testing**: Automated Go tests.
- **Linting**: Consistent code style with `golangci-lint`.
- **Security Scanning**: Vulnerability detection with `gosec`.
- **Container Publishing**: Automated builds pushed to GitHub Container Registry (GHCR).

## License

This project is licensed under the [MIT License](LICENSE).
