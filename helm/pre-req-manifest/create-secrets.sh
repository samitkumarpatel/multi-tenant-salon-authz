#!/usr/bin/env bash
# One-time manual setup — run this once per cluster/environment before deploying.
# All secrets are created idempotently (safe to re-run).
#
# Prerequisites: the salon namespace and shared secrets (postgres-secret, ghcr-secret)
# must already exist. Run helm/pre-req-manifest/create-secrets.sh in the
# multi-tenant-salon repo first if this is a fresh cluster.
#
# Usage:
#   export MAILJET_API_KEY="<your-mailjet-api-key>"
#   export MAILJET_API_SECRET="<your-mailjet-api-secret>"
#   ./helm/pre-req-manifest/create-secrets.sh

set -euo pipefail

NAMESPACE="salon"

# ── Validate inputs ───────────────────────────────────────────────────────────

: "${MAILJET_API_KEY:?MAILJET_API_KEY is required}"
: "${MAILJET_API_SECRET:?MAILJET_API_SECRET is required}"

# ── mailjet-secret ────────────────────────────────────────────────────────────
# Mounted into the auth pod via envFrom so MAILJET_API_KEY and MAILJET_API_SECRET
# are available at runtime without CI ever touching the values.

kubectl create secret generic mailjet-secret \
  --namespace "$NAMESPACE" \
  --from-literal=MAILJET_API_KEY="$MAILJET_API_KEY" \
  --from-literal=MAILJET_API_SECRET="$MAILJET_API_SECRET" \
  --dry-run=client -o yaml | kubectl apply -f -

echo "mailjet-secret created/updated"

echo ""
echo "All prerequisites are ready in namespace: $NAMESPACE"
