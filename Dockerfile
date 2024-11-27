FROM golang:1.22.7 as builder

WORKDIR /app

COPY . .

# install Linux kernel headers
RUN apt-get update && apt-get install -y libbpf-dev
RUN go mod download
# RUN go build -o main .

FROM ubuntu:22.04

WORKDIR /root/

COPY --from=builder /app/main .
COPY bpf/xdp_ebpf.c ./bpf/
COPY bpf/xdp_ebpf.o ./bpf/

RUN apt-get update && apt-get install -y clang llvm iproute2 libbpf-dev

# Ensure the container runs as root
USER root

# Export metrics port
EXPOSE 8080

CMD ["./main"]