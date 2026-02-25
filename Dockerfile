FROM golang:1.24 AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y libpcap-dev && rm -rf /var/lib/apt/lists/*

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 GOOS=linux go build \
    -trimpath \
    -ldflags "-s -w" \
    -o /snet \
    ./cmd/server

FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y libpcap0.8 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /snet /snet

COPY configs/config.yaml /configs/config.yaml

ENTRYPOINT ["/snet"]
