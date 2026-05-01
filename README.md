<p align="center">
  <img src="static/img/logo.png" alt="Vulfixx Logo" width="200">
</p>

<p align="center">
  <img src="https://img.shields.io/github/actions/workflow/status/arumes31/vulfixx/docker-build.yml?branch=v2_test&style=for-the-badge&logo=github" alt="Build Status">
  <img src="https://img.shields.io/github/actions/workflow/status/arumes31/vulfixx/go-licenses.yml?branch=v2_test&label=Licenses&style=for-the-badge&logo=github" alt="License Check Status">
  <img src="https://img.shields.io/badge/Go-1.26.2-00ADD8?style=for-the-badge&logo=go" alt="Go Version">
  <img src="https://img.shields.io/badge/Security-Gosec_Passed-brightgreen?style=for-the-badge&logo=shield" alt="Security Status">
  <img src="https://img.shields.io/github/license/arumes31/vulfixx?style=for-the-badge" alt="License">
</p>

# Vulfixx - Advanced CVE Tracker

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
- **Modern UI**: High-density dashboard with a premium glassmorphic Amber theme, built on a custom SPA navigation framework for high-performance, seamless transitions. Features **interactive column sorting**, dynamic multi-variable filtering, and synchronized risk distribution charts.
- **Dynamic Vendor Extraction**: Robust client-side parsing of CPE configurations to extract and display interactive vendor intelligence badges on threat detail pages.

## 🏗️ Architecture
The application follows a modular architecture designed to prevent monolithic files and improve domain separation.

### Web Layer (`internal/web`)
- **`base.go`**: Core middlewares (Auth, Admin, Proxy, Security), template rendering, and global stats caching.
- **`auth_handlers.go`**: User identity, registration, and email verification.
- **`dashboard_handlers.go`**: CVE monitoring, interactive sorting, status updates, and notes management.
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
- [Go 1.26.2](https://golang.org/dl/) (optional, for local development)
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
| `DB_SSLMODE` | PostgreSQL SSL mode (`disable`, `prefer`, `require`, `verify-full`) | `prefer` |
| `REDIS_URL`| Redis connection URL | `redis:6379` |
| `SMTP_HOST`| External SMTP server | `smtp.example.com` |
| `SMTP_PORT`| SMTP server port | `587` |
| `SMTP_USER`| SMTP username | `user@example.com` |
| `SMTP_PASS`| SMTP password | `password` |
| `SESSION_KEY`| Session signing key | `supersecretkey...` |
| `CSRF_KEY` | CSRF protection key (32 bytes) | `0123456789...` |
| `SECURE_COOKIE` | Enable secure cookie flag (for HTTPS) | `true` |
| `BASE_URL` | Application base URL | `http://localhost:8080` |
| `ADMIN_EMAIL`| Seed administrator email | `admin@example.com` |
| `ADMIN_PASSWORD`| Seed administrator password | `change-me` |
| `ADMIN_TOTP_SECRET`| Seed administrator TOTP secret (base32) | `YOUR_SECRET` |
| `NVD_API_KEY`| NIST NVD API Key (for higher rate limits) | `(empty)` |
| `NVD_API_URL`| Custom NVD API endpoint (optional) | `https://...` |

> **Security Warning:** The default seed values for `ADMIN_EMAIL`, `ADMIN_PASSWORD`, and `ADMIN_TOTP_SECRET` are insecure and must be changed before deploying to production. Please generate a strong password and a unique base32 TOTP secret. It is highly recommended to rotate the seeded admin credentials and remove defaults from any production configuration.

   *Note: The above is a partial list of key configurations. See `docker-compose.yml` for all available options.*
## Development

### Running Tests

To run the Go test suite:
```bash
go test ./...
```

Or use the automated test script with coverage:
```bash
./run_all_tests.sh
```

### CI/CD Pipeline

This project uses a modern GitHub Actions pipeline (`.github/workflows/docker-build.yml`) for continuous integration:
- **Environment**: All CI jobs run in a **Go 1.26.2** containerized environment.
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

### Local Development Scripts

For convenience, several shell scripts are provided to automate common tasks:
- **`run_all_tests.sh`**: Runs all tests with coverage and displays a summary.
- **`test_lint.sh`**: Executes `golangci-lint` with the project's configuration.
- **`fix_worker_panic.sh`**: Utility for patching specific worker edge cases.
- **`fix_errcheck.sh`**: Utility for automated error checking fixes.

- **Public SEO Dashboard**: High-performance public threat intelligence portal with built-in Schema.org JSON-LD structured data and Open Graph meta-tags for search engine authority.
- **Sitemap & Search Discovery**: Automated generation of `sitemap.xml` and `robots.txt` for efficient crawling of the top 1000 threats.
- **CSP Nonce Hardening**: Advanced Content Security Policy implementation using unique per-request nonces for all inline script execution.

## 🛡️ Security Hardening & Audit

The codebase has undergone a comprehensive security audit (April 2026) using automated static analysis (`gosec`), dependency scanning (`govulncheck`), and manual penetration testing of the public surface.

### Recent Remediation Actions
- **XSS Mitigation (CSP Nonces)**: Implemented unique per-request cryptographic nonces for all inline scripts.
- **Structured Data Protection**: Hardened JSON-LD generation with backend marshaling and `template.HTML` escaping.
- **Public Surface Abuse Prevention**: Integrated `RateLimitMiddleware` on all public SEO routes and implemented strict pagination depth validation.
- **SSRF Mitigation**: Implemented strict URL validation and scheme checks in all worker synchronization tasks.
- **SMTP Injection Protection**: Centralized email sanitization (`sanitizeEmail`) with CR/LF stripping and proper RFC parsing.
- **Session Security**: Enforced `SameSite=Lax` cookie policy and made `sslmode` configurable for secure production database connections.
- **SQL Injection Prevention**: 100% migration to parameterized queries via `pgx/v5` for all search and filter logic.

### Automated Checks
The CI pipeline automatically runs:
- `golangci-lint`: For code quality and best practices.
- `gosec`: For vulnerability scanning and static security analysis.
- `go test`: Comprehensive unit and integration test suite.

## License

This project is licensed under the [MIT License](LICENSE).
