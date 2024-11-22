.PHONY: all build clean docker

all: build

build:
	clang -O2 -g -target bpf -c xdp_ebpf.c -o xdp_ebpf.o
	go build -o main main.go

clean:
	rm -f main xdp_prog.o

docker:
	docker build -t xdp-prometheus .