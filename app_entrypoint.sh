#!/usr/bin/env sh
set -eu

# ngrok
NGROK_AUTH_TOKEN="$(echo '{"s": {"opitem": "ngrok", "opfield": "pocket_lint.token"}}'| poetry run /opt/app/pylib/cred_tool)"
/opt/app/ngrok authtoken --config /opt/app/ngrok.yml "${NGROK_AUTH_TOKEN}"
cat /opt/app/config/ngrok_oauth_callback.yml \
  | sed 's@APP_HTTP_PORT@'"$APP_HTTP_PORT"'@' \
  | sed 's@NGROK_CLIENT_API_PORT@'"$NGROK_CLIENT_API_PORT"'@' \
  | sed 's@NGROK_TUNNEL_NAME@'"$NGROK_TUNNEL_NAME"'@' \
  > /opt/app/ngrok_oauth_callback.yml
# check and opportunistically upgrade configuration
/opt/app/ngrok config check --config /opt/app/ngrok.yml || ./opt/app/ngrok config upgrade --config /opt/app/ngrok.yml
/opt/app/ngrok config check --config /opt/app/ngrok_oauth_callback.yml || ./opt/app/ngrok config upgrade --config /opt/app/ngrok_oauth_callback.yml
cat << EOF >> /opt/app/supervisord.conf
[program:ngrok]
command=/opt/app/ngrok start --config /opt/app/ngrok.yml --config /opt/app/ngrok_oauth_callback.yml oauth_callback
autorestart=false
startretries=0
stderr_logfile=/dev/stderr
EOF

# Refresh local SQLite
# TODO: uncomment
# /opt/app/backup_db.sh