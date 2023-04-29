#!/usr/bin/env sh
set -eux

NGROK_URL=$(curl -s 'https://ngrok.com/download' | hxnormalize -x 2>/dev/null | grep '#linux-dl-link' | grep -Eo 'https://.*linux-amd64.tgz' | tail -1)
TMP_DIR=$(mktemp -d -t ngrok-XXXXXX)
wget -nv -P "${TMP_DIR}" "${NGROK_URL}"
tar -xvzf ${TMP_DIR}/*.tgz --directory /opt/app/