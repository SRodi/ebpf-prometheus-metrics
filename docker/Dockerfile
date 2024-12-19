FROM --platform=$BUILDPLATFORM golang:1.23.4-alpine AS builder

WORKDIR /app

COPY bpf/latency.o ./bpf/
COPY go.mod go.sum main.go ./

RUN go mod download
RUN go build -o main .

# Final stage
FROM alpine:latest

WORKDIR /app

# Copy the binary from the build stage
COPY --from=builder /app/main .
COPY --from=builder /app/bpf/latency.o ./bpf/

# Ensure the container runs as root
USER root

# Export metrics port
EXPOSE 2112

CMD ["./main"]
