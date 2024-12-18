# Use multi-stage build to support multiarch
FROM --platform=$BUILDPLATFORM debian:bullseye-slim AS builder

# Install dependencies
RUN apt-get update && apt-get install -y \
    clang-16 \
    llvm-16 \
    libbpf-dev \
    gcc \
    make \
    git \
    linux-headers-generic \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

# Create a symlink to clang-16, llvm-16 and llvm-strip-16
RUN ln -s /usr/bin/clang-16 /usr/bin/clang && \
    ln -s /usr/bin/llvm-16 /usr/bin/llvm && \
    ln -s /usr/bin/llvm-objcopy-16 /usr/bin/llvm-strip

# Download the BPF tools
RUN git clone --recurse-submodules https://github.com/libbpf/bpftool.git && \
    cd bpftool/src && \
    make && \
    make install

WORKDIR /src

RUN mkdir bpf
# Generate vmlinux.h
RUN bpftool btf dump file /sys/kernel/btf/vmlinux format c > /src/bpf/vmlinux.h

# Set the target architecture
ARG TARGETARCH

# Copy the source code
COPY bpf/latency.c /src/bpf/latency.c

# Compile the BPF program
RUN clang -O2 -g -target bpf -D__TARGET_ARCH_${TARGETARCH} -Wall -c /src/bpf/latency.c -o /src/bpf/latency.o

# Final stage
FROM scratch AS final

# Copy the compiled object file
COPY --from=builder /src/bpf/latency.o /bpf/latency.o