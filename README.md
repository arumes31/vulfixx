# CVE Tracker

A robust Go-based application for tracking and alerting on new Common Vulnerabilities and Exposures (CVEs) from the NIST NVD database.

## Features

- **Automated CVE Fetching**: Periodically synchronizes with the NIST NVD API.
- **Custom Subscriptions**: Users can subscribe to alerts based on keywords and CVSS severity scores.
- **Multi-Channel Alerts**: Supports both Email (SMTP) and Webhook notifications.
- **Export to CSV**: Easily export active CVEs to a CSV file from the dashboard.
- **Search & Filter**: Real-time client-side search on the dashboard.
- **Statistics Summary**: At-a-glance view of total, KEV, and high-severity CVEs.
- **User Activity Log**: Track important account actions for security auditing.
- **Dark Mode**: Toggle between light and dark themes for better accessibility.
- **Secure Authentication**: Includes 2FA (TOTP) support and email verification.
- **Modern Infrastructure**: Containerized with Docker and orchestrated via Docker Compose.

## Getting Started

### Prerequisites

- [Docker](https://www.docker.com/get-started)
- [Docker Compose](https://docs.docker.com/compose/install/)
- [Go 1.26](https://golang.org/dl/) (optional, for local development)
- [act](https://github.com/nektos/act) (optional, for running GitHub Actions locally)

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

This project uses a modern GitHub Actions pipeline (`.github/workflows/docker-build.yml`) for continuous integration:
- **Environment**: All CI jobs run in a **Go 1.26** containerized environment.
- **Unit Testing**: Automated Go tests to ensure logic correctness.
- **Linting**: Strict code quality checks with `golangci-lint` (v2.x).
- **Security Scanning**: Vulnerability detection with `gosec`.
- **Container Publishing**: Images are automatically built and pushed to **GitHub Container Registry (GHCR)**.

To run the entire CI pipeline locally using `act`:
```bash
act
```
Or run specific jobs:
```bash
act -j test
act -j lint
```

## License

This project is licensed under the [MIT License](LICENSE).
