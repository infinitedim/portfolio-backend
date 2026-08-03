#!/usr/bin/env bash

# Batch translation script for Phase 1 (zh_CN & ja_JP)
# Usage:
#   ADMIN_TOKEN="your_jwt" ./scripts/batch-translate-phase1.sh
#   OR: ADMIN_EMAIL="admin@example.com" ADMIN_PASSWORD="pass" ./scripts/batch-translate-phase1.sh

set -euo pipefail

BACKEND_URL="${BACKEND_URL:-http://localhost:8080}"
TARGET_LOCALES=("zh_CN" "ja_JP")

echo "=== Portfolio Multi-Locale Batch Translation: Phase 1 (zh_CN, ja_JP) ==="

TOKEN="${ADMIN_TOKEN:-}"

if [ -z "$TOKEN" ]; then
    if [ -n "${ADMIN_EMAIL:-}" ] && [ -n "${ADMIN_PASSWORD:-}" ]; then
        echo "[*] Authenticating with ${ADMIN_EMAIL}..."
        LOGIN_RES=$(curl -s -X POST "${BACKEND_URL}/api/auth/login" \
            -H "Content-Type: application/json" \
            -d "{\"email\": \"${ADMIN_EMAIL}\", \"password\": \"${ADMIN_PASSWORD}\"}")
        
        TOKEN=$(echo "$LOGIN_RES" | grep -o '"accessToken":"[^"]*' | cut -d'"' -f4 || true)
        if [ -z "$TOKEN" ]; then
            echo "[!] Authentication failed. Response: ${LOGIN_RES}"
            exit 1
        fi
        echo "[+] Authentication successful."
    else
        echo "[!] Error: Neither ADMIN_TOKEN nor (ADMIN_EMAIL + ADMIN_PASSWORD) were provided."
        echo "Example: ADMIN_TOKEN=\"<jwt>\" $0"
        exit 1
    fi
fi

echo "[*] Fetching published English blog posts..."
POSTS_JSON=$(curl -s -X GET "${BACKEND_URL}/api/blog?locale=en&published=true&pageSize=100")

# Extract post IDs using grep/cut
POST_IDS=$(echo "$POSTS_JSON" | grep -o '"id":"[^"]*' | cut -d'"' -f4 || true)

if [ -z "$POST_IDS" ]; then
    echo "[!] No published English posts found or failed to parse response."
    exit 0
fi

TOTAL_POSTS=$(echo "$POST_IDS" | wc -l)
echo "[+] Found ${TOTAL_POSTS} published English posts."

SUCCESS_COUNT=0
FAIL_COUNT=0

for ID in $POST_IDS; do
    for LOCALE in "${TARGET_LOCALES[@]}"; do
        echo "[*] Requesting translation for post ${ID} -> ${LOCALE}..."
        
        HTTP_STATUS=$(curl -s -o /tmp/translate_resp.json -w "%{http_code}" \
            -X POST "${BACKEND_URL}/api/admin/blog/${ID}/translate?target=${LOCALE}" \
            -H "Authorization: Bearer ${TOKEN}" \
            -H "Content-Type: application/json")
        
        if [ "$HTTP_STATUS" -eq 200 ]; then
            echo "    [SUCCESS] Post ${ID} translated to ${LOCALE} (Status: pending_review)"
            SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
        else
            echo "    [FAILED] Post ${ID} -> ${LOCALE} (HTTP ${HTTP_STATUS})"
            cat /tmp/translate_resp.json
            echo ""
            FAIL_COUNT=$((FAIL_COUNT + 1))
        fi
        
        # 1-second rate limit throttling between API calls
        sleep 1
    done
done

echo ""
echo "=== Phase 1 Batch Translation Complete ==="
echo "Success: ${SUCCESS_COUNT} | Failed: ${FAIL_COUNT}"
echo "Pending translations are ready for review at: ${BACKEND_URL}/admin/blog/translations"
