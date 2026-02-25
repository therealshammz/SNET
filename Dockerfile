# Stage 1: Build with CGO enabled (needed for gopacket/pcap)
FROM golang:1.24 AS builder

WORKDIR /build

# Install libpcap-dev (required for gopacket/pcap)
RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source and build
COPY . .
# CGO_ENABLED=1 so it links libpcap
RUN CGO_ENABLED=1 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w" \
    -o /snet \
    ./cmd/server

# Stage 2: Runtime image with libpcap runtime lib
FROM debian:bookworm-slim

# Install minimal runtime deps for libpcap
RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*

# Copy binary from builder
COPY --from=builder /snet /snet

# Default config (overridden by volume)
COPY configs/config.yaml /configs/config.yaml

# Entrypoint = binary
ENTRYPOINT ["/snet"]