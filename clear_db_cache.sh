#!/bin/bash

#DB_STRING="psql postgres://passkey:passkey@localhost:5432/passkey"
DB_STRING="sqlite3 /tmp/sqlite.db"

echo "drop table users"| $DB_STRING
echo "drop table passkey_credentials"| $DB_STRING
redis-cli flushall

