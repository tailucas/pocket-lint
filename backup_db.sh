#!/usr/bin/env bash
set -eu
set -o pipefail

me="$(basename "$0")"
cd "$(dirname "$0")"

. <(sed 's/^/export /' /opt/app/cron.env)

log () {
  echo "${me} $1"
}

BACKUP_FILENAME_SUFFIX=""
if [ -n "${1:-}" ]; then
  if [ "$1" == "date" ]; then
    BACKUP_FILENAME_SUFFIX="_$(date +%y%m%d)"
  elif [ "$1" == "time" ]; then
    BACKUP_FILENAME_SUFFIX="_$(date +%y%m%d%H%M%S)"
  else
    BACKUP_FILENAME_SUFFIX="_$1"
  fi
fi
BACKUP_FILENAME="${APP_NAME}${BACKUP_FILENAME_SUFFIX}.db"
S3_RESTORE_PATH="s3://${BACKUP_S3_BUCKET}/${APP_NAME}.db"
S3_BACKUP_PATH="s3://${BACKUP_S3_BUCKET}/${BACKUP_FILENAME}"
TABLESPACE="${TABLESPACE_PATH}/${APP_NAME}.db"
AKID="{\"s\": {\"opitem\": \"AWS.${APP_NAME}\", \"opfield\": \"${AWS_DEFAULT_REGION}.akid\"}}"
export AWS_ACCESS_KEY_ID="$(echo "${AKID}" | poetry run /opt/app/cred_tool)"
log "using AWS Access Key ID ending ...${AWS_ACCESS_KEY_ID:15:5}"
SAK="{\"s\": {\"opitem\": \"AWS.${APP_NAME}\", \"opfield\": \"${AWS_DEFAULT_REGION}.sak\"}}"
export AWS_SECRET_ACCESS_KEY="$(echo "${SAK}" | poetry run /opt/app/cred_tool)"
if [ -s "${TABLESPACE}" ]; then
  log "creating backup of tablespace ${TABLESPACE}..."
  sqlite3 "${TABLESPACE}" ".backup /tmp/${APP_NAME}.db"
  log "uploading backup to ${S3_BACKUP_PATH}..."
  poetry run aws s3 cp "/tmp/${APP_NAME}.db" "${S3_BACKUP_PATH}" --only-show-errors
else
  log "restoring ${S3_RESTORE_PATH} to ${TABLESPACE}..."
  poetry run aws s3 cp "${S3_RESTORE_PATH}" "${TABLESPACE}" --only-show-errors
fi
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY

DB_HEARTBEAT=$(sqlite3 "${TABLESPACE}" 'select dt from heartbeat') || true
if [ -n "${DB_HEARTBEAT:-}" ]; then
  log "database heartbeat is ${DB_HEARTBEAT} UTC."
fi
