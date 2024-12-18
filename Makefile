IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= srodi
IMAGE_TAG ?= $(shell git describe --tags --always)
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

docker: build
	docker build -t $(IMAGE) .
	docker push $(IMAGE)

docker-run:
	docker run --cap-add=SYS_ADMIN --cap-add=NET_ADMIN --cap-add=BPF --ulimit memlock=1073741824:1073741824 -p 2112:2112 $(IMAGE)

deploy:
	envsubst < deploy/deploy.yaml.tmpl | kubectl apply -f -

delete:
	envsubst < deploy/deploy.yaml.tmpl | kubectl delete -f -
