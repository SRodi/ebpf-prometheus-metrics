IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= srodi
IMAGE_TAG ?= $(shell git describe --tags --always)
IMAGE := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/ebpf-prometheus-metrics/latency:$(IMAGE_TAG)
export IMAGE

# Force make to always run these targets
.PHONY: all build clean docker deploy delete

all: build

build:
	clang -O2 -g -target bpf -c bpf/latency.c -o bpf/latency.o
	go build -o main main.go

run: clean build
	sudo ./main

clean:
	rm -f main bpf/latency.o

docker: build
	docker build -t $(IMAGE) .
	docker push $(IMAGE)

docker-run:
	docker run --cap-add=SYS_ADMIN  -p 8080:8080 $(IMAGE)

deploy:
	envsubst < deploy/deploy.yaml.tmpl | kubectl apply -f -

delete:
	envsubst < deploy/deploy.yaml.tmpl | kubectl delete -f -
