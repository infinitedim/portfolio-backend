# Portfolio Backend - Rust + Axum with Comprehensive Logging

High-performance Rust backend with Axum web framework, featuring comprehensive file-based logging with Loki + Grafana for log aggregation, visualization, and monitoring.

## 🚀 Features

- **⚡ High Performance**: Built with Rust and Axum for blazing-fast request handling
- **📊 Comprehensive Logging**: Structured JSON logging with multiple log levels
- **📈 Log Aggregation**: Loki + Promtail for centralized log collection
- **📉 Beautiful Dashboards**: Pre-configured Grafana dashboards for monitoring
- **🔔 Smart Alerting**: Automated alerts for errors, performance issues, and security events
- **🔄 Log Rotation**: Automatic daily rotation with 30-day retention
- **📝 Multiple Log Sources**: Backend logs, frontend server logs, and client logs
- **🎯 Trace Context**: Request tracking across the stack

## Quick Start

### Prerequisites

- **Rust 1.75+** - [Install Rust](https://rustup.rs/)
- **Docker & Docker Compose** - [Install Docker](https://docs.docker.com/get-docker/)
- **Bun or Node.js** - For frontend (if running full stack)

### Starting the Backend

```bash
# Clone the repository (if not already)
git clone https://github.com/infinitedim/portfolio.git
cd portfolio/portfolio-backend

# Build the backend
cargo build --release

# Run the backend
cargo run

# Or run in release mode
./target/release/portfolio-backend
```

The backend will start on `http://localhost:8080` (or the configured PORT).

### Starting the Logging Stack

```bash
# Start Loki, Promtail, and Grafana
cd portfolio-backend
docker-compose -f docker-compose.logging.yml up -d

# Check if services are running
docker-compose -f docker-compose.logging.yml ps

# View logs
docker-compose -f docker-compose.logging.yml logs -f
```

### Starting the Backend

```bash
# Build and run the backend
cargo build --release
cargo run

# Or in development mode
cargo run
```

### Accessing Services

After starting the logging stack, you can access:

- **Grafana Dashboard**: <http://localhost:3001>
  - Username: `admin`
  - Password: `admin` (change this in production!)
  - Pre-configured dashboards available in the "Dashboards" section
- **Loki API**: <http://localhost:3100>
  - Health check: `curl http://localhost:3100/ready`
  - Query API: `http://localhost:3100/loki/api/v1/query`
- **Promtail**: <http://localhost:9080>
  - Metrics: `http://localhost:9080/metrics`
  - Ready check: `http://localhost:9080/ready`
- **Backend API**: <http://localhost:8080>
  - Health check: `curl http://localhost:8080/health`
  - API docs: Coming soon

## 📚 API Endpoints

### Health Check

```bash
GET http://localhost:8080/health

Response:
{
  "status": "healthy",
  "timestamp": "2024-01-01T12:00:00Z"
}
```

### Log Ingestion

```bash
POST http://localhost:8080/api/logs
Content-Type: application/json

{
  "logs": [
    {
      "timestamp": "2024-01-01T12:00:00Z",
      "level": "info",
      "message": "User action completed",
      "context": {
        "component": "auth",
        "user_id": "123"
      }
    }
  ]
}
```

### Portfolio Data (Future)

```bash
GET /api/portfolio      # Get portfolio data
GET /api/blog          # Get blog posts
GET /api/blog/:slug    # Get specific blog post
```

## 🛠️ Development

### Project Structure

```
portfolio-backend/
├── src/
│   ├── main.rs              # Application entry point
│   ├── lib.rs               # Library exports
│   ├── routes/              # API route handlers
│   │   ├── health.rs        # Health check endpoint
│   │   ├── logs.rs          # Log ingestion endpoint
│   │   ├── auth.rs          # Authentication (future)
│   │   ├── blog.rs          # Blog API (future)
│   │   └── portfolio.rs     # Portfolio data (future)
│   ├── logging/             # Logging configuration
│   │   ├── config.rs        # Log setup and config
│   │   └── middleware.rs    # HTTP request logging
│   └── db/                  # Database (future)
│       └── models.rs        # Data models
├── config/                  # Configuration files
│   ├── loki-config.yml      # Loki configuration
│   ├── promtail-config.yml  # Promtail configuration
│   └── grafana/             # Grafana config
│       ├── dashboards/      # Dashboard JSON files
│       ├── datasources/     # Datasource configs
│       └── alerts/          # Alert rules
├── logs/                    # Log file output
│   ├── app.log             # All application logs
│   └── error.log           # Error logs only
├── data/                    # Persistent data (Docker volumes)
│   ├── grafana/            # Grafana data
│   └── loki/               # Loki storage
└── Cargo.toml              # Rust dependencies

```

### Building & Running

```bash
# Development build (faster compilation)
cargo build
cargo run

# Release build (optimized)
cargo build --release
./target/release/portfolio-backend

# Run with custom environment
ENVIRONMENT=development LOG_LEVEL=debug cargo run

# Run tests
cargo test

# Run tests with output
cargo test -- --nocapture

# Check code without building
cargo check

# Format code
cargo fmt

# Run clippy (linter)
cargo clippy
```

### Environment Variables

The backend supports these environment variables:

```bash
# Application environment
ENVIRONMENT=production|staging|development  # Default: development

# Logging level
LOG_LEVEL=trace|debug|info|warn|error      # Default: info
RUST_LOG=info                               # Rust-specific logging

# Server configuration
HOST=0.0.0.0                                # Default: 0.0.0.0
PORT=8080                                   # Default: 8080
```

Copy `.env.example` to `.env` and fill secrets. Gate puzzle answers (`GATE_L1_ANSWER`, etc.) and `GATE_TOKEN_SECRET` are required for the terminal gate — see `.env.example` Gate section.

Gate API: `GET /api/gate/status`, `POST /api/gate/verify`, `POST /api/gate/unlock`, plus `/api/gate/challenge/*` for levels 2–3.

### Adding Logging to Your Code

```rust
use tracing::{info, warn, error, debug};

// Simple logging
info!("Server started");
warn!("Resource usage high");
error!("Database connection failed");

// Structured logging with fields
info!(
    user_id = %user.id,
    action = "login",
    "User logged in successfully"
);

// Function instrumentation (automatic span tracking)
#[tracing::instrument]
async fn process_request(id: String) -> Result<Response> {
    debug!("Processing request");
    // Your code here
    Ok(response)
}

// Manual span creation
use tracing::span;
let span = span!(tracing::Level::INFO, "database_query", table = "users");
let _enter = span.enter();
// Query code here
```

## 🏗️ Architecture

┌─────────────────┐
│ Frontend │
│ (Next.js) │
│ - Client logs │
│ - Server logs │
└────────┬────────┘
│
│ HTTP POST /api/logs
│
┌────────▼────────┐
│ Backend │
│ (Rust/Axum) │
│ - HTTP logs │
│ - App logs │
│ - Client logs │
└────────┬────────┘
│
│ Write to files
│
┌────────▼────────┐ ┌──────────────┐ ┌──────────────┐
│ Log Files │────►│ Promtail │────►│ Loki │
│ - app.log │ │ (Collector) │ │ (Storage) │
│ - error.log │ └──────────────┘ └──────┬───────┘
│ - access.log │ │
└─────────────────┘ │
│
┌────────▼────────┐
│ Grafana │
│ (Dashboards) │
└─────────────────┘

````

## Log Files

### Backend Logs

- **Location**: `logs/`
- **Files**:
  - `app.log` - All application logs
  - `error.log` - Error and fatal logs only
- **Format**: JSON (production) / Pretty (development)
- **Rotation**: Daily rotation, keeps last 30 days

### Frontend Logs

- **Location**: `../portfolio-frontend/logs/server/`
- **Files**:
  - `combined.log` - All server logs
  - `error.log` - Error logs
  - `access.log` - HTTP access logs
- **Format**: JSON
- **Rotation**: 50MB files, keeps 10 files

## 📊 Grafana Dashboards

Access Grafana at <http://localhost:3001> to view pre-configured dashboards:

### 1. Application Overview Dashboard

Monitor overall application health and performance:

- **Total Requests**: Requests per minute trend
- **Error Rate**: Percentage of failed requests (last 5 minutes)
- **Response Time**: P95 response time in milliseconds
- **Recent Errors**: Latest error messages with timestamps
- **Status Codes**: Distribution of HTTP status codes (2xx, 3xx, 4xx, 5xx)
- **Web Vitals**: LCP, FID, CLS metrics from client
- **Top Pages**: Most visited pages/endpoints

### 2. Errors Dashboard

Deep dive into application errors:

- **Error Count by Level**: Breakdown of ERROR, WARN, FATAL logs
- **Error Rate Trend**: Errors over time chart
- **Error Distribution**: Errors grouped by component/service
- **Critical Errors**: Recent FATAL level logs requiring immediate attention
- **Error Stack Traces**: Detailed error information table
- **Error Patterns**: Common error messages and patterns

### 3. Performance Dashboard

Analyze application performance:

- **Response Time Percentiles**: P50, P95, P99 latency
- **Slow Requests**: Requests taking > 1 second
- **Web Vitals Details**:
  - Largest Contentful Paint (LCP) - Should be < 2.5s
  - First Input Delay (FID) - Should be < 100ms
  - Cumulative Layout Shift (CLS) - Should be < 0.1
- **Request Duration Heatmap**: Visual representation of response times
- **Throughput**: Requests processed per second

### 4. Security Dashboard

Monitor security events and threats:

- **Suspicious Patterns**: Unusual request patterns or behaviors
- **Security Events**: Failed logins, unauthorized access attempts
- **Rate Limit Violations**: IPs hitting rate limits
- **Authentication Failures**: Failed login attempts by IP
- **CORS Violations**: Cross-origin request rejections
- **IP Analysis**: Top IPs with security events
- **User Agent Analysis**: Suspicious bot patterns

## 🔔 Alerting

Alerts are configured in `config/grafana/alerts/rules.yml` and will notify you of critical issues.

### Critical Alerts (Immediate Action Required)

- ⚠️ **High Error Rate**
  - Trigger: >5 errors/second for 5 minutes
  - Action: Check application logs, investigate root cause

- ⚠️ **Service Down**
  - Trigger: No logs received for 5 minutes
  - Action: Check if backend is running, verify Promtail connection

- ⚠️ **Out of Memory**
  - Trigger: Memory-related errors detected in logs
  - Action: Restart service, investigate memory leaks

### Warning Alerts (Monitor Closely)

- ⚡ **Slow Response Time**
  - Trigger: P95 response time >2s for 10 minutes
  - Action: Check database queries, optimize slow endpoints

- 📊 **Poor Web Vitals**
  - Trigger: LCP >4s for 10 minutes
  - Action: Optimize frontend performance, reduce bundle size

### Security Alerts

- 🔐 **Failed Login Attempts**
  - Trigger: >10 failed attempts in 5 minutes
  - Action: Potential bruteforce attack, consider IP blocking

- 🚨 **Rate Limit Abuse**
  - Trigger: >100 rate limit violations in 5 minutes
  - Action: Review rate limit policies, block abusive IPs

- **Failed Logins**: >10 failed attempts in 5 minutes
- **Rate Limit Abuse**: >100 violations in 5 minutes

## ⚙️ Configuration

### Log Levels

The backend supports multiple log levels for different environments:

- **TRACE**: Very detailed debugging information (development only)
  - Use for step-by-step execution tracking
  - Example: Function entry/exit, variable values

- **DEBUG**: Debugging information (development/staging)
  - Use for troubleshooting issues
  - Example: SQL queries, API responses

- **INFO**: General informational messages (all environments)
  - Use for normal application flow
  - Example: Server started, request completed

- **WARN**: Warning conditions (all environments)
  - Use for potential issues that don't stop execution
  - Example: Deprecated API usage, high memory usage

- **ERROR**: Error conditions (all environments)
  - Use for errors that occur but are handled
  - Example: Failed database query, invalid input

- **FATAL**: Critical errors (all environments)
  - Use for unrecoverable errors
  - Example: Cannot start server, database unavailable

### Log File Configuration

**Backend Logs** (`portfolio-backend/logs/`):

```yaml
# app.log - All application logs
- Rotation: Daily at midnight
- Retention: 30 days
- Format: JSON in production, pretty in development
- Max size: Unlimited (per day)

# error.log - Error and fatal logs only
- Rotation: Daily at midnight
- Retention: 30 days
- Format: JSON
- Levels: ERROR, FATAL only
````

**Frontend Logs** (`portfolio-frontend/logs/server/`):

```yaml
# combined.log - All Next.js server logs
- Rotation: 50MB per file
- Retention: 10 files (500MB total)
- Format: JSON

# error.log - Error logs only
- Rotation: 50MB per file
- Retention: 10 files
- Format: JSON

# access.log - HTTP access logs
- Rotation: 50MB per file
- Retention: 10 files
- Format: Combined log format
```

### Retention Policies

- **Loki**: 30 days (configurable in `config/loki-config.yml`)
- **Backend logs**: Daily rotation, keeps last 30 days
- **Frontend logs**: 50MB rotation, keeps 10 files (~500MB)
- **Grafana data**: Persistent in Docker volume

To change retention:

**Loki** (`config/loki-config.yml`):

```yaml
limits_config:
  retention_period: 720h # 30 days (change as needed)
```

**Backend** (in code at `src/logging/config.rs`):

```rust
.rotation(Rotation::DAILY)
.max_log_files(30)  // Change this value
```

## Development

### Adding Logging to Code

**Rust Backend**:

```rust
use tracing::{info, warn, error};

#[tracing::instrument]
async fn my_handler() -> Result<Response> {
    info!("Processing request");

    match process_data().await {
        Ok(data) => {
            info!(count = data.len(), "Data processed successfully");
            Ok(data)
        }
        Err(e) => {
            error!(error = ?e, "Failed to process data");
            Err(e)
        }
    }
}
```

**TypeScript Frontend**:

```typescript
import { clientLogger } from "@/lib/logger";

function handleClick() {
  clientLogger.logUserAction("button_click", {
    buttonId: "submit",
    page: "/contact",
  });
}

try {
  const data = await fetchData();
  clientLogger.info(
    "Data fetched successfully",
    {
      component: "DataFetcher",
    },
    { count: data.length },
  );
} catch (error) {
  clientLogger.logError(error, {
    component: "DataFetcher",
    action: "fetch-data",
  });
}
```

### Querying Logs

**LogQL Examples**:

```logql
# All errors in the last hour
{level="error"} | json

# Slow requests (>1s)
{job="portfolio-backend"} | json | duration_ms > 1000

# Errors from specific component
{level="error", component="auth"} | json

# Client logs from mobile devices
{service="frontend", log_type="client"} | json | device_type="mobile"

# Security events
{} |= "Security event" | json

# Web Vitals - Poor LCP
{service="frontend"} |= "LCP" | json | value > 4000
```

## Troubleshooting

### No Logs Appearing in Grafana

1. Check if services are running:

   ```bash
   docker-compose -f docker-compose.logging.yml ps
   ```

2. Check Promtail logs:

   ```bash
   docker-compose -f docker-compose.logging.yml logs promtail
   ```

3. Verify log files exist:

   ```bash
   ls -la logs/
   ls -la ../portfolio-frontend/logs/server/
   ```

4. Test Loki connection:

   ```bash
   curl http://localhost:3100/ready
   ```

### High Memory Usage

1. Check Loki retention settings in `config/loki-config.yml`
2. Reduce retention period if needed
3. Run compaction manually:

   ```bash
   docker-compose -f docker-compose.logging.yml restart loki
   ```

### Slow Queries in Grafana

1. Reduce time range
2. Add more specific filters to queries
3. Use label filters before JSON parsing
4. Check Loki performance in container logs

## 🛠️ Tech Stack

- **🦀 Rust** - Systems programming language (1.75+)
- **🚀 Axum** - Ergonomic and modular web framework
- **📝 Tracing** - Structured logging and distributed tracing
- **📊 Loki** - Scalable log aggregation system by Grafana Labs
- **📤 Promtail** - Log shipping agent that tails log files
- **📈 Grafana** - Observability and visualization platform
- **🐳 Docker** - Containerization for logging infrastructure
- **📦 Cargo** - Rust package manager and build system

## 🧪 Testing & Development

### Running Tests

```bash
# Run all tests
cargo test

# Run with standard output
cargo test -- --nocapture

# Run specific test
cargo test test_health_endpoint

# Run tests with logging enabled
RUST_LOG=debug cargo test

# Run integration tests only
cargo test --test '*'

# Check code without building
cargo check
```

### Code Quality

```bash
# Format code
cargo fmt

# Check formatting without modifying files
cargo fmt -- --check

# Run linter (clippy)
cargo clippy

# Run clippy with strict warnings
cargo clippy -- -D warnings

# Generate documentation
cargo doc --open
```

### Code Coverage (Optional)

```bash
# Install tarpaulin
cargo install cargo-tarpaulin

# Generate HTML coverage report
cargo tarpaulin --out Html

# Generate and upload to codecov
cargo tarpaulin --out Xml
```

## 🚀 Production Deployment

### Security Checklist

- [ ] Change Grafana admin password
- [ ] Configure authentication for Grafana
- [ ] Set up HTTPS for Grafana
- [ ] Configure firewall rules (only allow internal access to Loki/Promtail)
- [ ] Enable PII masking in all logs
- [ ] Set up log encryption at rest
- [ ] Configure backup for Grafana dashboards and Loki data

### Performance Optimization

- [ ] Tune Loki ingestion limits based on log volume
- [ ] Configure query timeout appropriately
- [ ] Set up Loki horizontal scaling if needed
- [ ] Use SSD storage for Loki data
- [ ] Configure log sampling for high-volume endpoints

### Monitoring

- [ ] Set up alerts for Loki service health
- [ ] Monitor Loki disk usage
- [ ] Monitor Promtail lag
- [ ] Set up dashboards for logging infrastructure itself

## 🤝 Contributing

Contributions are welcome! Here's how you can help:

1. **Fork** the repository
2. **Create** a feature branch (`git checkout -b feature/amazing-feature`)
3. **Commit** your changes (`git commit -m 'feat: add amazing feature'`)
4. **Push** to the branch (`git push origin feature/amazing-feature`)
5. **Open** a Pull Request

### Development Guidelines

- Follow Rust coding conventions and use `cargo fmt`
- Run `cargo clippy` and fix all warnings
- Add tests for new features
- Update documentation as needed
- Keep commits atomic and well-described

## 📚 Additional Resources

- [Rust Book](https://doc.rust-lang.org/book/)
- [Axum Documentation](https://docs.rs/axum/)
- [Tracing Documentation](https://docs.rs/tracing/)
- [Loki Documentation](https://grafana.com/docs/loki/)
- [LogQL Guide](https://grafana.com/docs/loki/latest/logql/)
- [Grafana Dashboards](https://grafana.com/docs/grafana/latest/dashboards/)

## 📄 License

MIT License - see the [LICENSE](../LICENSE) file for details

## 💬 Support

- 📖 Check the [Frontend README](../portfolio-frontend/README.md) for full-stack setup
- 🐛 Found a bug? [Open an issue](https://github.com/infinitedim/portfolio/issues)
- 💡 Have a suggestion? [Start a discussion](https://github.com/infinitedim/portfolio/discussions)

---

**Built with 🦀 Rust and ❤️ by [Dimas Saputra](https://github.com/infinitedim)**
