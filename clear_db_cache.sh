#!/bin/bash

#DB_STRING="psql postgres://passkey:passkey@localhost:5432/passkey"
DB_STRING="sqlite3 /tmp/sqlite.db"

echo "drop table o2p_users"| $DB_STRING
echo "drop table o2p_passkey_credentials"| $DB_STRING
echo "drop table o2p_oauth2_accounts"| $DB_STRING
redis-cli flushall
