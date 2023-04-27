APP := pocket_lint
DOCKER_APP := pocket-lint
USER_ID := 999
GROUP_ID := $(shell getent group docker | cut -f3 -d ':')

all: help

help:
	@echo "Depends on 1Password Connect Server: https://developer.1password.com/docs/connect/get-started"

user:
	id $(USER_ID) || (sudo useradd -r -u $(USER_ID) -g $(GROUP_ID) app && sudo usermod -a -G $(GROUP_ID) -u $(USER_ID) app)
	mkdir -p ./data/
	sudo chown $(USER_ID):$(GROUP_ID) ./data/
	sudo chmod 755 ./data/
	sudo chmod g+rws ./data/

setup: docker-compose.template
	@echo "Generating docker-compose.yml"
	cat docker-compose.template | sed "s~__DOCKER_HOSTNAME__~$(DOCKER_APP)~g" > docker-compose.template2
	python3 ./pylib/cred_tool ENV.$(APP) $(APP) | python3 ./pylib/yaml_interpol services/app/environment docker-compose.template2 > docker-compose.yml
	rm -f docker-compose.template2

build:
	docker-compose build --progress plain

run:
	docker-compose up

rund:
	docker-compose up -d

connect:
	./connect_to_app.sh $(DOCKER_APP)

clean:
	rm docker-compose.yml

.PHONY: all help setup run connect clean pydeps