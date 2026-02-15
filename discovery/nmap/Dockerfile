# Multi-stage Dockerfile for nmap tool

# Stage 1: Build the Go wrapper
FROM golang:1.25-alpine AS builder

# Set working directory
WORKDIR /build

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build static binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -a -installsuffix cgo -ldflags '-extldflags "-static"' -o nmap-tool .

# Stage 2: Runtime image
FROM alpine:latest

# Install nmap, nmap-scripts, and ca-certificates
RUN apk add --no-cache \
    nmap \
    nmap-scripts \
    ca-certificates

# Copy the static binary from builder
COPY --from=builder /build/nmap-tool /usr/local/bin/nmap-tool

# Set the entrypoint to the Go wrapper (not /usr/bin/nmap)
ENTRYPOINT ["/usr/local/bin/nmap-tool"]
