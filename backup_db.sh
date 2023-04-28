#!/usr/bin/env sh
set -e
set -o pipefail
cd "$(dirname "$0")"

BACKUP_FILENAME_SUFFIX=""
if [ -n "${1:-}" ]; then
  BACKUP_FILENAME_SUFFIX="_${1}"
fi
BACKUP_FILENAME="${APP_NAME}${BACKUP_FILENAME_SUFFIX}.db"

AKID="{\"s\": {\"opitem\": \"AWS.${APP_NAME}\", \"opfield\": \".username\"}}"
export AWS_ACCESS_KEY_ID="$(echo "${AKID}" | poetry run /opt/app/pylib/cred_tool)"
SAK="{\"s\": {\"opitem\": \"AWS.${APP_NAME}\", \"opfield\": \".password\"}}"
export AWS_SECRET_ACCESS_KEY="$(echo "${SAK}" | poetry run /opt/app/pylib/cred_tool)"
if [ -f "${TABLESPACE_PATH}" ]; then
  # create backup process
  sqlite3 "${TABLESPACE_PATH}" ".backup /tmp/${APP_NAME}.db"
  poetry run aws s3 cp "/tmp/${APP_NAME}.db" "s3://tailucas-automation/${BACKUP_FILENAME}" --only-show-errors
else
  # only if the tablespace does not exist
  poetry run aws s3 cp "s3://tailucas-automation/${APP_NAME}.db" "${TABLESPACE_PATH}" --only-show-errors
fi
unset AWS_ACCESS_KEY_ID
unset AWS_SECRET_ACCESS_KEY