IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= srodi
# add arch to the tag
ARCH=$(shell uname -m)
IMAGE_TAG ?= $(shell git describe --tags --always)-$(ARCH)
IMAGE := $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/ebpf-prometheus-metrics/latency:$(IMAGE_TAG)
export IMAGE

# Force make to always run these targets
.PHONY: all build load clean docker deploy delete

all: build

build: clean
	clang -O2 -g -target bpf -c bpf/latency.c -o bpf/latency.o
	go build -o main main.go

load:
	sudo bpftool prog load bpf/latency.o /sys/fs/bpf/latency autoattach

dump:
	sudo bpftool map dump name latency_map

run: clean build
	sudo ./main

clean:
	sudo rm -f /sys/fs/bpf/latency
	rm -f main bpf/latency.o

docker:
	docker buildx build --platform linux/arm64 --build-arg TARGETARCH=arm64 -t $(IMAGE) -f docker/Dockerfile .
	docker push $(IMAGE)

docker-run:
	docker run --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=BPF --ulimit memlock=1073741824:1073741824 -p 2112:2112 $(IMAGE)

deploy:
	envsubst < deploy/deploy.yaml | kubectl apply -f -

delete:
	envsubst < deploy/deploy.yaml | kubectl delete -f -

build-arm64:
	docker buildx build --platform linux/arm64 --build-arg TARGETARCH=arm64 -t my-bpf-program:arm64 -f docker/Dockerfile.builder . --output=type=local,dest=./

build-x86:
	docker buildx build --platform linux/amd64 --build-arg TARGETARCH=x86 -t my-bpf-program:amd64 -f docker/Dockerfile.builder . --output=type=local,dest=./

prometheus:
	helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
	helm upgrade kube-prometheus-stack prometheus-community/kube-prometheus-stack --values deploy/prom-values.yaml