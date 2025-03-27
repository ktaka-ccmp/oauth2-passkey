#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
  source .env
fi

# Check required environment variables
if [ -z "$GENERIC_DATA_STORE_TYPE" ] || [ -z "$GENERIC_DATA_STORE_URL" ] || [ -z "$GENERIC_CACHE_STORE_TYPE" ] || [ -z "$GENERIC_CACHE_STORE_URL" ]; then
  echo "ERROR: Required environment variables are not set in .env file."
  echo "Please ensure the following variables are set:"
  echo "  GENERIC_DATA_STORE_TYPE (e.g., postgres)"
  echo "  GENERIC_DATA_STORE_URL (e.g., postgresql://passkey:passkey@localhost:5432/passkey)"
  echo "  GENERIC_CACHE_STORE_TYPE (e.g., redis)"
  echo "  GENERIC_CACHE_STORE_URL (e.g., redis://localhost:6379)"
  exit 1
fi

# Use environment variables for database connection
case "$GENERIC_DATA_STORE_TYPE" in
  postgres)
    DB_STRING="psql $GENERIC_DATA_STORE_URL"
    ;;
  sqlite)
    DB_PATH="${GENERIC_DATA_STORE_URL#sqlite:}"
    DB_PATH="${DB_PATH#//}"
    DB_STRING="sqlite3 ${DB_PATH}"
    echo $DB_STRING
    ;;
  *)
    echo "ERROR: Unsupported data store type: $GENERIC_DATA_STORE_TYPE"
    exit 1
    ;;
esac

echo "Clearing database tables..."
echo "drop table o2p_passkey_credentials"| $DB_STRING
echo "drop table o2p_oauth2_accounts"| $DB_STRING
echo "drop table o2p_users"| $DB_STRING

# Clear cache based on cache store type
case "$GENERIC_CACHE_STORE_TYPE" in
  redis)
    echo "Clearing Redis cache..."
    redis-cli -u "$GENERIC_CACHE_STORE_URL" flushall
    ;;
  *)
    echo "WARNING: Clearing cache for $GENERIC_CACHE_STORE_TYPE is not implemented"
    ;;
esac

echo "Database and cache cleared successfully."
