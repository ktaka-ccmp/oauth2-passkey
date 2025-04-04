#!/bin/bash

# Load environment variables from .env file
if [ -f .env ]; then
  source .env
fi

# Check required environment variables
if [ -z "$GENERIC_DATA_STORE_TYPE" ] || [ -z "$GENERIC_DATA_STORE_URL" ]; then
  echo "ERROR: Required environment variables are not set in .env file."
  echo "Please ensure the following variables are set:"
  echo "  GENERIC_DATA_STORE_TYPE (e.g., postgres)"
  echo "  GENERIC_DATA_STORE_URL (e.g., postgresql://passkey:passkey@localhost:5432/passkey)"
  exit 1
fi

# Use environment variables for database connection
case "$GENERIC_DATA_STORE_TYPE" in
  postgres)
    # For PostgreSQL, use -q flag for quiet mode and set formatting options
    DB_STRING="psql -q $GENERIC_DATA_STORE_URL"
    # Use psql options to format output without confirmation messages
    FORMAT_COMMAND=""
    ;;
  sqlite)
    DB_PATH="${GENERIC_DATA_STORE_URL#sqlite:}"
    DB_PATH="${DB_PATH#//}"
    DB_STRING="sqlite3 ${DB_PATH}"
    echo $DB_STRING
    # SQLite formatting options
    SQLITE_HEADERS=".headers on"
    SQLITE_MODE=".mode column"
    FORMAT_COMMAND="$SQLITE_HEADERS\n$SQLITE_MODE\n"
    ;;
  *)
    echo "ERROR: Unsupported data store type: $GENERIC_DATA_STORE_TYPE"
    exit 1
    ;;
esac

# Define queries for each table
QUERY_USERS="select sequence_number,is_admin,id,account,label,created_at from o2p_users;"
QUERY_PASSKEY_CREDENTIALS="select user_id,user_name,credential_id,public_key,created_at from o2p_passkey_credentials;"
QUERY_OAUTH2_ACCOUNTS="select user_id,email,id,created_at from o2p_oauth2_accounts;"

#QUERY_PASSKEY_CREDENTIALS="select user_id,user_name,user_display_name,credential_id,public_key,created_at from passkey_credentials;"
#QUERY_PASSKEY_CREDENTIALS="select user_id,hex(credential_id),user_handle,user_name,user_display_name,created_at from passkey_credentials;"
#QUERY_OAUTH2_ACCOUNTS="select user_id,id,provider_user_id,email,created_at from oauth2_accounts;"
#QUERY_OAUTH2_ACCOUNTS="select user_id,email,name,created_at from oauth2_accounts;"

# Combine all queries (can be customized by commenting out lines)
ALL_QUERIES=""
ALL_QUERIES+="$QUERY_USERS"
ALL_QUERIES+="$QUERY_PASSKEY_CREDENTIALS"
ALL_QUERIES+="$QUERY_OAUTH2_ACCOUNTS"

# Run the watch command
watch -n 1 'echo "'"$FORMAT_COMMAND$ALL_QUERIES"'" | '"$DB_STRING"
