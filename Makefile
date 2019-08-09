
.PHONY: all build push test

NAME := local-registry.i.ling.id.au/qemu/vm
RELEASE := $(shell cat VERSION)

build:
	docker build -t $(NAME):$(RELEASE) docker

push:
	docker push $(NAME):$(RELEASE)

test:
	docker-compose up

all: push build
