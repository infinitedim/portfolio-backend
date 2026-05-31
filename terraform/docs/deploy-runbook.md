# Deploy Runbook

## Prerequisites

- GCP project bootstrapped ([gcp-bootstrap.md](./gcp-bootstrap.md))
- `terraform apply` completed (all modules green)
- Docker image pushed to Artifact Registry (via CI or manual)

---

## 1. First Deploy — Populate Secrets

After `terraform apply` creates the Secret Manager entries, add values:

```bash
# Required secrets
echo -n 'postgres://portfolio:YOUR_PASSWORD@10.10.0.X:5432/portfolio' | \
  gcloud secrets versions add portfolio-database-url --data-file=-

echo -n 'your-jwt-secret-here' | \
  gcloud secrets versions add portfolio-jwt-secret --data-file=-

echo -n 'your-refresh-secret-here' | \
  gcloud secrets versions add portfolio-refresh-token-secret --data-file=-

echo -n '$argon2id$...' | \
  gcloud secrets versions add portfolio-admin-hash-password --data-file=-

echo -n 'gate-l2-password' | \
  gcloud secrets versions add portfolio-gate-l2-answer --data-file=-

echo -n 'gate-token-secret' | \
  gcloud secrets versions add portfolio-gate-token-secret --data-file=-

# VM secrets
echo -n 'postgres-db-password' | \
  gcloud secrets versions add portfolio-postgres-password --data-file=-

echo -n 'grafana-admin-password' | \
  gcloud secrets versions add portfolio-grafana-password --data-file=-

# Optional secrets (add when ready)
echo -n 'key' | gcloud secrets versions add portfolio-resend-api-key --data-file=-
echo -n 'ghp_...' | gcloud secrets versions add portfolio-gh-token --data-file=-
echo -n 'key' | gcloud secrets versions add portfolio-gemini-api-key --data-file=-
echo -n 'you@example.com' | gcloud secrets versions add portfolio-roadmap-email --data-file=-
echo -n 'your-roadmap-password' | gcloud secrets versions add portfolio-roadmap-password --data-file=-
echo -n 'metrics-bearer-token' | gcloud secrets versions add portfolio-metrics-token --data-file=-
```

Generate `ADMIN_HASH_PASSWORD` locally:

```bash
cd portfolio-backend
cargo run --bin hash-password
```

---

## 2. Push First Image Manually

If CI is not yet configured:

```bash
# Authenticate
gcloud auth configure-docker asia-southeast2-docker.pkg.dev

# Build and push
IMAGE="asia-southeast2-docker.pkg.dev/PROJECT_ID/portfolio/portfolio-backend"
docker build --platform linux/amd64 -t "${IMAGE}:latest" .
docker push "${IMAGE}:latest"

# Deploy to Cloud Run
gcloud run services update portfolio-backend \
  --region=asia-southeast2 \
  --image="${IMAGE}:latest"
```

---

## 3. Configure GitHub Actions

Set these as GitHub repository variables (Settings > Variables > Actions):

Also set Terraform var `admin_email` to a real address (backend fails startup when default admin@example.com is used in production).

| Variable | Value |
|----------|-------|
| `GCP_PROJECT_ID` | Your GCP project ID |
| `GCP_WIF_PROVIDER` | `terraform output -raw workload_identity_provider` |
| `GCP_DEPLOYER_SA` | `terraform output -raw github_deployer_sa_email` |

No secrets needed — Workload Identity Federation uses OIDC tokens.

---

## 4. Update Vercel Environment

After Cloud Run is deployed, get the URL:

```bash
gcloud run services describe portfolio-backend \
  --region=asia-southeast2 \
  --format='value(status.url)'
```

Set in Vercel dashboard (Settings > Environment Variables):

```
BACKEND_URL=https://<service-url>.run.app
NEXT_PUBLIC_API_URL=https://<service-url>.run.app
```

Update backend secrets to allow the Vercel origin:

```bash
# ALLOWED_ORIGINS and FRONTEND_ORIGIN are plain env vars in Cloud Run,
# not secrets. Update via gcloud or Terraform variable frontend_origin.
```

---

## 5. Update Prometheus Target

After Cloud Run deploys, update `config/prometheus.prod.yml`:

Replace `CLOUD_RUN_URL` with the actual Cloud Run hostname (without `https://`) and set `METRICS_BEARER_TOKEN` in the ops VM environment used by Prometheus:

```yaml
- job_name: portfolio-backend
  scheme: https
  static_configs:
    - targets: ["portfolio-backend-abc123-as.a.run.app"]
```

SSH into the ops VM and restart Prometheus:

```bash
gcloud compute ssh portfolio-prod-ops --zone=asia-southeast2-a --tunnel-through-iap
docker compose -f /opt/portfolio/docker-compose.gcp-ops.yml restart prometheus
```

---

## 6. Ops VM Access

### SSH

```bash
gcloud compute ssh portfolio-prod-ops \
  --zone=asia-southeast2-a \
  --tunnel-through-iap
```

### Grafana (port forward)

```bash
gcloud compute ssh portfolio-prod-ops \
  --zone=asia-southeast2-a \
  --tunnel-through-iap \
  -- -L 3000:localhost:3000
```

Then open `http://localhost:3000` in your browser.

### Postgres (port forward)

```bash
gcloud compute ssh portfolio-prod-ops \
  --zone=asia-southeast2-a \
  --tunnel-through-iap \
  -- -L 5432:localhost:5432
```

Then connect with `psql`:

```bash
psql -h localhost -U portfolio -d portfolio
```

### Redis (port forward)

```bash
gcloud compute ssh portfolio-prod-ops \
  --zone=asia-southeast2-a \
  --tunnel-through-iap \
  -- -L 6379:localhost:6379
```

Verify from your machine:

```bash
redis-cli -h localhost ping
# PONG
```

Cloud Run receives `REDIS_URL=redis://<ops_vm_internal_ip>:6379` from Terraform. After
`terraform apply`, confirm `/health/redis` returns `"status":"healthy"`.

If Redis was started manually on the ops VM, align with
`docker-compose.gcp-ops.yml` (port 6379, volume `/mnt/data/redis`).

---

## 7. Backup & Restore

### Automated Backups

Disk snapshots run daily at 03:00 UTC, retained for 14 days (managed by Terraform).

### Manual Snapshot

```bash
gcloud compute disks snapshot portfolio-prod-ops-data \
  --zone=asia-southeast2-a \
  --snapshot-names="manual-$(date +%Y%m%d-%H%M)"
```

### Restore from Snapshot

```bash
# Stop the VM
gcloud compute instances stop portfolio-prod-ops --zone=asia-southeast2-a

# Detach current data disk
gcloud compute instances detach-disk portfolio-prod-ops \
  --zone=asia-southeast2-a \
  --disk=portfolio-prod-ops-data

# Create new disk from snapshot
gcloud compute disks create portfolio-prod-ops-data-restored \
  --zone=asia-southeast2-a \
  --source-snapshot=SNAPSHOT_NAME

# Attach restored disk
gcloud compute instances attach-disk portfolio-prod-ops \
  --zone=asia-southeast2-a \
  --disk=portfolio-prod-ops-data-restored \
  --device-name=data-disk

# Start the VM
gcloud compute instances start portfolio-prod-ops --zone=asia-southeast2-a
```

---

## 8. Cloud Run outbound internet (roadmap.sh / GitHub)

Cloud Run uses the VPC connector **only for private ranges** (Postgres on the ops VM at `10.10.0.x`). Public HTTPS (`roadmap.sh`, `api.github.com`, etc.) must use Cloud Run’s default internet egress.

If `/api/roadmap/dashboard` returns **502** with `login request failed: error sending request for url (https://roadmap.sh/...)` while `/health` and `/api/portfolio` work, the service was likely deployed with `vpc-egress=all-traffic` and no Cloud NAT — outbound internet is black-holed.

**Quick fix (no Terraform):**

```bash
gcloud run services update portfolio-backend \
  --region=asia-southeast2 \
  --vpc-egress=private-ranges-only
```

**Verify after update:**

```bash
curl -m 15 https://portfolio-backend-843865911939.asia-southeast2.run.app/api/roadmap/dashboard
# expect 200 JSON or 502 with "ROADMAP_EMAIL/PASSWORD not configured" (secrets missing)
```

Populate roadmap credentials in **Secret Manager** (not Vercel — Vercel only serves the frontend):

```bash
echo -n 'you@example.com' | gcloud secrets versions add portfolio-roadmap-email --data-file=-
echo -n 'your-roadmap-password' | gcloud secrets versions add portfolio-roadmap-password --data-file=-
gcloud run services update portfolio-backend --region=asia-southeast2 --update-env-vars="FORCE_REDEPLOY=$(date +%s)"
```

---

## 9. Secret Rotation

```bash
# Generate new value, then:
echo -n 'new-jwt-secret' | \
  gcloud secrets versions add portfolio-jwt-secret --data-file=-

# Redeploy Cloud Run to pick up new secret version
gcloud run services update portfolio-backend \
  --region=asia-southeast2 \
  --update-env-vars="FORCE_REDEPLOY=$(date +%s)"
```

---

## 10. Teardown

To destroy all resources:

```bash
cd terraform/environments/prod
terraform destroy
```

Data disk snapshots are retained per the `on_source_disk_delete = "KEEP_AUTO_SNAPSHOTS"` policy.
