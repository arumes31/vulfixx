# CVE Tracker

A robust Go-based application for tracking and alerting on new Common Vulnerabilities and Exposures (CVEs) from the NIST NVD database.

## 🚀 V2 Intelligence Features
- **Advanced Alert Routing**: Precision delivery of alerts to different channels based on severity or risk profile.
- **Complex Boolean Alert Filters**: Surgical alert filtering using multi-variable logic (e.g., `severity > 8 && epss > 0.1`).
- **Audit Logs for Remediation**: Comprehensive chronological tracking of all vulnerability status changes and manual acknowledgments.
- **Community OSINT Intelligence**: Automated discovery of technical discussions on Hacker News and Reddit for every threat.
- **Vendor Advisory Aggregator**: Intelligent classification and highlighting of official security bulletins from Microsoft, Cisco, Ubuntu, etc.
- **Social Buzz & Threat Trending**: GitHub-integrated "Buzz" meter that tracks community interest and public PoC presence.
- **EPSS Integration**: Exploit Prediction Scoring System (EPSS) integration for probability-based risk assessment.
- **Smart Alert Batching**: Redis-backed intelligence buffering that groups related threats into unified reports.
- **Actionable Notifications**: Direct "Acknowledge" and "Mute" functionality embedded in email alerts.
- **Infrastructure Context**: Automatic mapping of vulnerabilities to specific infrastructure assets.
- **CWE Classification**: Deep vulnerability categorization using Common Weakness Enumeration (CWE) intelligence.
- **Remediation Lifecycle**: Private journaling and status tracking for vulnerability management.
- **Automated Intelligence**: Weekly email summaries and CISA KEV automated synchronization.
- **Enhanced Telemetry**: Risk Profile distribution charts and direct Proof-of-Concept (PoC) discovery links.
- **Asset-Linked Monitoring**: Proactive infrastructure defense via asset-keyword mapping.
- **Secure Integration**: Filtered, token-authenticated RSS feeds for personalized technical intel.
- **Rich Email Alerts**: Premium HTML notifications with OSINT links, Vendor advisories, and Risk gauges.
- **Modern UI**: High-density dashboard with glassmorphism aesthetics and Material Symbol integration.

## 🏗️ Architecture
The application follows a modular architecture designed to prevent monolithic files and improve domain separation.

### Web Layer (`internal/web`)
- **`base.go`**: Core middlewares (Auth, Admin, Proxy, Security), template rendering, and global stats caching.
- **`auth_handlers.go`**: User identity, registration, and email verification.
- **`dashboard_handlers.go`**: CVE monitoring, status updates, and notes management.
- **`subscription_handlers.go`**: Keyword subscriptions, RSS feeds, and alert actions.
- **`asset_handlers.go`**: IT Asset inventory and keyword mapping.
- **`activity_handlers.go`**: Audit logging and JSON activity exports.
- **`alert_handlers.go`**: Chronological notification history.
- **`admin_handlers.go`**: Administrative user management.

### Worker Layer (`internal/worker`)
- **`alert_worker.go`**: CVE queue processing and multi-variable filtering.
- **`alert_buffer.go`**: Redis-backed digest creation and delivery delay logic.
- **`notifier.go`**: Multi-channel dispatcher (Email, Webhooks) with SSRF/DNS protection.
- **`email_worker.go`**: SMTP delivery and verification email queue.
- **`sync_nvd.go`**: NVD CVE data synchronization with incremental backoff.
- **`sync_github.go`**: GitHub Social Buzz and PoC discovery tracking.
- **`sync_cisa.go`**: Automated CISA KEV catalog synchronization.
- **`sync_epss.go`**: Probability-based risk scoring (FIRST EPSS).
- **`cron_worker.go`**: Scheduled tasks (Weekly summaries).

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
- **Styling**: Modernized CSS pipeline with **Tailwind CSS v4** for high-performance, zero-runtime styling.
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
