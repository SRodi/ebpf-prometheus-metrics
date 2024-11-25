.PHONY: all build clean docker

all: build

build:
	clang -O2 -g -target bpf -c xdp_ebpf.c -o xdp_ebpf.o
	go build -o main main.go

clean:
	rm -f main xdp_ebpf.o

docker:
	docker build -t ghcr.io/srodi/ebpf-prometheus-metrics/xdp-prometheus .