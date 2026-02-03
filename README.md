# Portfolio Backend - Logging System

Comprehensive file-based logging system with Loki + Grafana for log aggregation and monitoring.

## Quick Start

### Prerequisites

- Docker and Docker Compose
- Rust 1.75+ (for backend development)
- Node.js 18+ and Bun (for frontend)

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

### Accessing Dashboards

- **Grafana**: http://localhost:3001
  - Username: `admin`
  - Password: `admin`
- **Loki API**: http://localhost:3100
- **Promtail**: http://localhost:9080

## Architecture

```
┌─────────────────┐
│  Frontend       │
│  (Next.js)      │
│  - Client logs  │
│  - Server logs  │
└────────┬────────┘
         │
         │ HTTP POST /api/logs
         │
┌────────▼────────┐
│  Backend        │
│  (Rust/Axum)    │
│  - HTTP logs    │
│  - App logs     │
│  - Client logs  │
└────────┬────────┘
         │
         │ Write to files
         │
┌────────▼────────┐     ┌──────────────┐     ┌──────────────┐
│  Log Files      │────►│  Promtail    │────►│  Loki        │
│  - app.log      │     │  (Collector) │     │  (Storage)   │
│  - error.log    │     └──────────────┘     └──────┬───────┘
│  - access.log   │                                  │
└─────────────────┘                                  │
                                                     │
                                            ┌────────▼────────┐
                                            │  Grafana        │
                                            │  (Dashboards)   │
                                            └─────────────────┘
```

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

## Grafana Dashboards

### Application Overview

- Total requests per minute
- Error rate (last 5 minutes)
- P95 response time
- Recent error logs
- Requests by status code
- Web Vitals metrics

### Errors Dashboard

- Error count by level
- Error rate by component
- Error distribution by service
- Recent critical errors
- Error details table

### Performance Dashboard

- Response time percentiles (P50, P95, P99)
- Slow requests (>1s)
- Web Vitals (LCP, FID, CLS)
- Request duration heatmap

### Security Dashboard

- Suspicious request patterns
- Security events by type
- Rate limit violations
- Failed authentication attempts
- CORS violations
- Security events by IP

## Alerting

Alerts are configured in `config/grafana/alerts/rules.yml`:

### Critical Alerts

- **High Error Rate**: >5 errors/second for 5 minutes
- **Service Down**: No logs received for 5 minutes
- **Out of Memory**: Memory errors detected

### Warning Alerts

- **Slow Response Time**: P95 >2s for 10 minutes
- **Poor Web Vitals**: LCP >4s for 10 minutes

### Security Alerts

- **Failed Logins**: >10 failed attempts in 5 minutes
- **Rate Limit Abuse**: >100 violations in 5 minutes

## Configuration

### Environment Variables

**Backend (`portfolio-backend`)**:

```bash
ENVIRONMENT=production|staging|development
LOG_LEVEL=trace|debug|info|warn|error
```

**Frontend (`portfolio-frontend`)**:

```bash
NODE_ENV=production|development
NEXT_PUBLIC_LOG_LEVEL=trace|debug|info|warn|error
NEXT_PUBLIC_LOG_API_URL=/api/logs
```

### Log Levels

- **TRACE**: Very detailed debugging (dev only)
- **DEBUG**: Debugging information (dev/staging)
- **INFO**: General information (all environments)
- **WARN**: Warning conditions
- **ERROR**: Error conditions
- **FATAL**: Critical errors

### Retention Policies

- **Loki**: 30 days
- **Backend logs**: Daily rotation, 30 days
- **Frontend logs**: 50MB rotation, 10 files

## Testing

Unit tests are in each module under `#[cfg(test)] mod tests`. No database or Redis is required for tests (handlers use fallbacks when the pool is not initialized).

### Run tests

```bash
cargo test
```

**Note (Windows):** If you see linker errors like `link: extra operand`, ensure the MSVC link.exe is used (e.g. run from "Developer Command Prompt for VS" or fix PATH so MSVC tools come before GNU/MinGW).

### Coverage (target >88%)

Install [cargo-llvm-cov](https://github.com/taiki-e/cargo-llvm-cov) and run:

```bash
# Install (once)
cargo install cargo-llvm-cov

# Run tests with coverage
cargo llvm-cov test

# Report (text)
cargo llvm-cov report

# HTML report (open target/llvm-cov/html/index.html)
cargo llvm-cov report --html
```

To enforce a minimum coverage threshold (e.g. 88%):

```bash
cargo llvm-cov report --summary-only --fail-under 88
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

## Production Deployment

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

## License

MIT
