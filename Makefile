IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= srodi
IMAGE_TAG ?= $(shell git describe --tags --always)
IMAGE := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/ebpf-prometheus-metrics/xdp-prometheus:$(IMAGE_TAG)
export IMAGE

.PHONY: all build clean docker

all: build

build:
	clang -O2 -g -target bpf -c bpf/xdp_ebpf.c -o bpf/xdp_ebpf.o
	go build -o main main.go

run: clean build
	sudo ./main

clean:
	rm -f main bpf/xdp_ebpf.o

docker:
	docker build -t $(IMAGE) .
	docker push $(IMAGE)

deploy:
	envsubst < deploy/deploy.yaml.tmpl | kubectl apply -f -

delete:
	envsubst < deploy/deploy.yaml.tmpl | kubectl delete -f -
