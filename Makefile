.PHONY: all check build run dev

DOCKER_URL := https://docs.docker.com/engine/install
DOCKER_COMPOSE_URL := https://docs.docker.com/compose/install
DEVCLI_URL := https://code.visualstudio.com/docs/devcontainers/devcontainer-cli
CHECK_USER := vscode

all: dev

check:
	@if [ "${USER}" = "$(CHECK_USER)" ]; then \
	  echo "Running as user ${USER}; try 'task' command instead."; \
	  exit 1; \
	fi
	@which docker > /dev/null || (echo "Needs Docker with compose, see $(DOCKER_URL) and $(DOCKER_COMPOSE_URL)"; exit 1)
	@which devcontainer > /dev/null || (echo "Needs Dev Container CLI; see $(DEVCLI_URL)"; exit 1)

build: check
	devcontainer build --workspace-folder .

run: build
	devcontainer up --workspace-folder .

dev: run
	devcontainer exec --workspace-folder . bash
