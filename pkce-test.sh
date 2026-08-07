#!/usr/bin/env bash
set -euo pipefail

AUTH_BASE="${1:-https://auth.my-saloon.online}"
CLIENT_ID="public-client"
REDIRECT_URI="http://127.0.0.1:3000"

CODE_VERIFIER=$(openssl rand -base64 32 | tr -d '=+/' | tr '+/' '-_' | head -c 43)
CODE_CHALLENGE=$(echo -n "$CODE_VERIFIER" | openssl dgst -sha256 -binary | openssl base64 | tr -d '=' | tr '+/' '-_')

echo ""
echo "=== Step 1 — Open in browser ==="
echo "${AUTH_BASE}/oauth2/authorize?response_type=code&client_id=${CLIENT_ID}&redirect_uri=${REDIRECT_URI}&scope=openid%20profile&code_challenge=${CODE_CHALLENGE}&code_challenge_method=S256"

echo ""
echo "=== Step 2 — Exchange code (replace AUTH_CODE with the code= value from the redirect) ==="
echo "http --form POST ${AUTH_BASE}/oauth2/token \\"
echo "  grant_type=authorization_code \\"
echo "  code=<AUTH_CODE> \\"
echo "  redirect_uri=${REDIRECT_URI} \\"
echo "  client_id=${CLIENT_ID} \\"
echo "  code_verifier=${CODE_VERIFIER}"
echo ""
