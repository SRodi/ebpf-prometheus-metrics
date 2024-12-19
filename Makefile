IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= srodi
# add arch to the tag
ARCH=$(shell uname -m)
IMAGE_TAG ?= $(shell git describe --tags --always)-$(ARCH)
IMAGE := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/ebpf-prometheus-metrics/latency:$(IMAGE_TAG)
export IMAGE
PLATFORM ?= $(if $(filter x86_64,$(ARCH)),linux/amd64,$(if $(filter arm64,$(ARCH)),linux/arm64,unsupported))
TARGETARCH ?= $(if $(filter x86_64,$(ARCH)),x86,$(if $(filter arm64,$(ARCH)),arm64,unsupported))

# Force make to always run these targets
.PHONY: all build load dump clean docker docker-run deploy delete prometheus

all: build

build: clean
	docker buildx build --platform $(PLATFORM) --build-arg TARGETARCH=$(TARGETARCH) -t bpf-compile:$(TARGETARCH) -f docker/Dockerfile.builder . --output=type=local,dest=./
	go build -o main main.go

load:
	sudo bpftool prog load bpf/latency.o /sys/fs/bpf/latency autoattach

dump:
	sudo bpftool map dump name latency_map

run: clean build
	sudo ./main

clean:
	sudo rm -f /sys/fs/bpf/latency
	rm -rf main bpf/latency.o ./build

docker:
	docker buildx build --platform $(PLATFORM) --build-arg TARGETARCH=$(TARGETARCH) -t $(IMAGE) -f docker/Dockerfile --push .

docker-run:
	docker run --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=BPF --ulimit memlock=1073741824:1073741824 -p 2112:2112 $(IMAGE)

deploy:
	envsubst < deploy/deploy.yaml | kubectl apply -f -

delete:
	envsubst < deploy/deploy.yaml | kubectl delete -f -

prometheus:
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm upgrade kube-prometheus-stack prometheus-community/kube-prometheus-stack --values deploy/prom-values.yaml

x-compile:
	docker buildx build --platform=linux/amd64 --build-arg TARGETARCH=x86_64 -t bpf-compile:latest -f docker/Dockerfile.xcompile . --output=type=local,dest=./build/