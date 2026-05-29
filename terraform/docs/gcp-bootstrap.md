# GCP Bootstrap — First-Time Setup

Complete these steps **once** before running `terraform apply`.

## 1. Create a GCP Project

```bash
gcloud projects create <PROJECT_ID> --name="Portfolio Backend"
gcloud config set project <PROJECT_ID>
```

Link a billing account:

```bash
gcloud billing accounts list
gcloud billing projects link <PROJECT_ID> --billing-account=<BILLING_ACCOUNT_ID>
```

## 2. Enable Required APIs

```bash
gcloud services enable \
  run.googleapis.com \
  compute.googleapis.com \
  artifactregistry.googleapis.com \
  secretmanager.googleapis.com \
  vpcaccess.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  cloudresourcemanager.googleapis.com
```

## 3. Create Terraform Service Account

```bash
gcloud iam service-accounts create terraform \
  --display-name="Terraform"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:terraform@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/editor"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:terraform@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/secretmanager.admin"

gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:terraform@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/iam.securityAdmin"
```

Download a key for local use (store securely, never commit):

```bash
gcloud iam service-accounts keys create ~/.config/gcloud/terraform-key.json \
  --iam-account=terraform@<PROJECT_ID>.iam.gserviceaccount.com

export GOOGLE_APPLICATION_CREDENTIALS=~/.config/gcloud/terraform-key.json
```

## 4. Create Remote State Bucket

```bash
gcloud storage buckets create gs://<PROJECT_ID>-tfstate \
  --location=asia-southeast2 \
  --uniform-bucket-level-access

gcloud storage buckets update gs://<PROJECT_ID>-tfstate --versioning
```

## 5. Configure terraform.tfvars

```bash
cd terraform/environments/prod
cp terraform.tfvars.example terraform.tfvars
# Edit terraform.tfvars with your project_id, region, etc.
```

## 6. Initialize and Apply

```bash
cd terraform/environments/prod
terraform init
terraform plan
terraform apply
```

## Region

Default region: `asia-southeast2` (Jakarta). Change in `terraform.tfvars` if needed.
