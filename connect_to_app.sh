#!/usr/bin/env bash
set -eu

CONTAINER_ID=$(docker ps -qf name="$1")
if [ -n "${CONTAINER_ID:-}" ]; then
  docker exec -it "$CONTAINER_ID" /bin/bash
else
  echo "No existing container, starting new session."
  docker compose run app bash
fi