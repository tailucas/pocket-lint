#!/usr/bin/env sh
set -eu

# Refresh local SQLite if not exists
if [ ! -f "${TABLESPACE_PATH}" ]; then
  /opt/app/backup_db.sh
fi
