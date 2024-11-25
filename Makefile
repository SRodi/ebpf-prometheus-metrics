IMAGE_REGISTRY ?= ghcr.io
IMAGE_NAMESPACE ?= srodi
IMAGE_TAG ?= $(shell git describe --tags --always)

.PHONY: all build clean docker

all: build

build:
	clang -O2 -g -target bpf -c xdp_ebpf.c -o xdp_ebpf.o
	go build -o main main.go

run: clean build
	sudo ./main

clean:
	rm -f main xdp_ebpf.o

docker:
	docker build -t $(IMAGE_REGISTRY)/$(IMAGE_NAMESPACE)/ebpf-prometheus-metrics/xdp-prometheus:$(IMAGE_TAG) .