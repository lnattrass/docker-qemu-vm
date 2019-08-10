
.PHONY: all push

NAME := local-registry.i.ling.id.au/qemu/vm
RELEASE := $(shell cat VERSION)

.id: $(shell find docker)
	docker build --iidfile .id -t $(NAME):$(RELEASE) docker

push: .id
	docker tag $(shell echo cat $<) $(NAME):$(RELEASE)
	docker push $(NAME):$(RELEASE)

test: .id
	docker tag $(shell cat $<) $(NAME):$(RELEASE)
	cd test && docker-compose up

all: push build
