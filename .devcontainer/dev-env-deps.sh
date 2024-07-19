#!/usr/bin/env bash
set -eu
set -o pipefail

if ! task --version; then
  sh -c "$(curl -sSL https://taskfile.dev/install.sh)" -- -b ~/.local/bin
fi

if ! poetry --version; then
  curl -sSL https://install.python-poetry.org | POETRY_HOME=~/.local python3 -
fi

poetry install --no-interaction
poetry show --tree
