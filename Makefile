
.PHONY: all push

NAME := test
RELEASE := $(shell cat VERSION)

.id: $(shell find docker)
	docker build --iidfile .id -t $(NAME):$(RELEASE) docker

push: .id
	docker tag $(shell echo cat $<) $(NAME):$(RELEASE)
	docker push $(NAME):$(RELEASE)

test1: .id
	docker tag $(shell cat $<) $(NAME):$(RELEASE)
	cd test && docker-compose up test1

test2: .id
	docker tag $(shell cat $<) $(NAME):$(RELEASE)
	cd test && docker-compose up test2

all: push build
