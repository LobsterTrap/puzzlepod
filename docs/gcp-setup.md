# GCP Setup for PuzzlePod CI/CD

This guide documents how to configure GCP Workload Identity Federation for GitHub Actions,
enabling the PuzzlePod CI/CD pipeline to call Vertex AI without stored API keys.

## Prerequisites

- A GCP project with billing enabled
- `gcloud` CLI installed and authenticated
- Owner or IAM Admin role on the GCP project

## Step 1: Enable Required APIs

```bash
gcloud services enable aiplatform.googleapis.com \
  iam.googleapis.com \
  cloudresourcemanager.googleapis.com \
  sts.googleapis.com \
  iamcredentials.googleapis.com
```

## Step 2: Create Workload Identity Pool

```bash
gcloud iam workload-identity-pools create github-actions-pool \
  --location="global" \
  --display-name="GitHub Actions Pool" \
  --description="Workload Identity Pool for GitHub Actions CI/CD"
```

## Step 3: Create Workload Identity Provider

Replace `<GITHUB_ORG>` with your GitHub organization or username.

```bash
gcloud iam workload-identity-pools providers create-oidc github-actions-provider \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --display-name="GitHub Actions Provider" \
  --issuer-uri="https://token.actions.githubusercontent.com" \
  --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.repository_owner=assertion.repository_owner" \
  --attribute-condition="assertion.repository_owner == '<GITHUB_ORG>'"
```

## Step 4: Create Service Account

```bash
gcloud iam service-accounts create puzzlepod-ci \
  --display-name="PuzzlePod CI Service Account" \
  --description="Service account for PuzzlePod GitHub Actions workflows"
```

## Step 5: Grant Vertex AI Access

```bash
gcloud projects add-iam-policy-binding <PROJECT_ID> \
  --member="serviceAccount:puzzlepod-ci@<PROJECT_ID>.iam.gserviceaccount.com" \
  --role="roles/aiplatform.user"
```

## Step 6: Bind Workload Identity to Service Account

Replace `<PROJECT_NUMBER>` (numeric) and `<GITHUB_ORG>/<REPO>` with your values.

```bash
gcloud iam service-accounts add-iam-policy-binding \
  puzzlepod-ci@<PROJECT_ID>.iam.gserviceaccount.com \
  --role="roles/iam.workloadIdentityUser" \
  --member="principalSet://iam.googleapis.com/projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-actions-pool/attribute.repository/<GITHUB_ORG>/<REPO>"
```

## Step 7: Get Provider Resource Name

```bash
gcloud iam workload-identity-pools providers describe github-actions-provider \
  --location="global" \
  --workload-identity-pool="github-actions-pool" \
  --format="value(name)"
```

This outputs a string like:
```
projects/<PROJECT_NUMBER>/locations/global/workloadIdentityPools/github-actions-pool/providers/github-actions-provider
```

## Step 8: Configure GitHub Repository

Add the following to your GitHub repository:

### Secrets (Settings > Secrets and variables > Actions > Secrets)
- `GCP_WORKLOAD_IDENTITY_PROVIDER`: The full provider resource name from Step 7
- `GCP_SERVICE_ACCOUNT`: `puzzlepod-ci@<PROJECT_ID>.iam.gserviceaccount.com`

### Variables (Settings > Secrets and variables > Actions > Variables)
- `GCP_PROJECT_ID`: Your GCP project ID
- `GCP_REGION`: Vertex AI region (default: `us-east5`)

## Verification

After configuration, the `agent-review.yml` workflow will automatically:
1. Exchange the GitHub OIDC token for short-lived GCP credentials
2. Call Vertex AI (Claude on Vertex) for PR reviews
3. Post review comments on the PR

To verify manually, trigger the workflow on a test PR and check the workflow logs.

## Security Notes

- **No long-lived credentials**: All authentication uses short-lived tokens via OIDC federation
- **Scoped access**: The attribute condition restricts access to your specific repository
- **Minimal permissions**: The service account only has `roles/aiplatform.user`
- **Audit trail**: All API calls are logged in GCP Cloud Audit Logs
