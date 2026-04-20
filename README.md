# CVE Tracker

A robust Go-based application for tracking and alerting on new Common Vulnerabilities and Exposures (CVEs) from the NIST NVD database.

## Features

- **Automated CVE Fetching**: Periodically synchronizes with the NIST NVD API.
- **Custom Subscriptions**: Users can subscribe to alerts based on keywords and CVSS severity scores.
- **Multi-Channel Alerts**: Supports both Email (SMTP) and Webhook notifications.
- **Export Data**: Easily export active CVEs to CSV or account activity to JSON.
- **Search & Filter**: Real-time client-side search and pagination on the dashboard.
- **Bulk Actions**: Batch mark CVEs as resolved or ignored directly from the dashboard.
- **RSS Feed**: Personalized CVE feed accessible via a unique token.
- **Statistics Summary**: At-a-glance view of total, KEV, and high-severity CVEs.
- **User Activity Log**: Detailed audit trail of all important account actions.
- **Secure Account Management**: Support for email changes, password updates, 2FA (TOTP), and account deletion.
- **Dark Mode**: Native light/dark theme support.
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
   - `CSRF_KEY`: A secure random string for CSRF protection (exactly 32 bytes).

    3. Start the application:
    ```bash
    docker-compose up --build
    ```

    ### Running with GHCR (GitHub Container Registry)

    If you prefer not to build the image locally, you can use the pre-built image from GHCR:

    ```bash
    docker-compose -f docker-compose.ghcr.yml up
    ```

   The application will be available at `http://localhost:8080`.

   ## Configuration

   The application is configured via environment variables in the `docker-compose.yml` file:

   | Variable | Description | Default |
   |----------|-------------|---------|
   | `DB_HOST` | PostgreSQL host | `db` |
   | `DB_PORT` | PostgreSQL port | `5432` |
   | `DB_USER` | PostgreSQL user | `cveuser` |
   | `DB_PASSWORD`| PostgreSQL password | `cvepass` |
   | `DB_NAME` | PostgreSQL database name | `cvetracker` |
   | `REDIS_URL`| Redis connection URL | `redis:6379` |
   | `SMTP_HOST`| External SMTP server | `smtp.example.com` |
   | `SMTP_PORT`| SMTP server port | `587` |
   | `SMTP_USER`| SMTP username | `user@example.com` |
   | `SMTP_PASS`| SMTP password | `password` |
   | `SESSION_KEY`| Session signing key | `supersecretkey...` |
   | `CSRF_KEY` | CSRF protection key (32 bytes) | `0123456789...` |
   | `BASE_URL` | Application base URL | `http://localhost:8080` |

   *Note: The above is a partial list of key configurations. See `docker-compose.yml` for all available options.*
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
