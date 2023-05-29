#!/usr/bin/env sh
set -eu

# ngrok
NGROK_AUTH_TOKEN="$(echo '{"s": {"opitem": "ngrok", "opfield": "pocket_lint.token"}}'| poetry run /opt/app/pylib/cred_tool)"
/opt/app/ngrok authtoken --config /opt/app/ngrok.yml "${NGROK_AUTH_TOKEN}"
# check and opportunistically upgrade configuration
/opt/app/ngrok config check --config /opt/app/ngrok.yml || ./opt/app/ngrok config upgrade --config /opt/app/ngrok.yml
/opt/app/ngrok config check --config /opt/app/ngrok_oauth_callback.yml || ./opt/app/ngrok config upgrade --config /opt/app/ngrok_oauth_callback.yml

if [ "${NGROK_ENABLED:-}" = "true" ]; then
  cat << EOF >> /opt/app/supervisord.conf
[program:ngrok]
command=/opt/app/ngrok start --config /opt/app/ngrok.yml --config /opt/app/ngrok_oauth_callback.yml oauth_callback
autorestart=false
startretries=0
stderr_logfile=/dev/stderr
EOF
fi

# Refresh local SQLite if not exists
if [ ! -f "${TABLESPACE_PATH}" ]; then
  /opt/app/backup_db.sh
fi
