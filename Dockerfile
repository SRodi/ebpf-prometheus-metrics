FROM golang:1.22.7 as builder

WORKDIR /app

COPY . .

# install Linux kernel headers
RUN apt-get update && apt-get install -y libbpf-dev
RUN go mod download
RUN go build -o main .

FROM ubuntu:20.04

WORKDIR /root/

COPY --from=builder /app/main .
COPY xdp_ebpf.c .

RUN apt-get update && apt-get install -y clang llvm iproute2 libbpf-dev

CMD ["./main"]