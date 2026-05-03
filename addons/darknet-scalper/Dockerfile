# Stage 1: Build the Go binary
FROM golang:alpine AS builder
RUN apk add --no-cache git build-base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go mod tidy
RUN go build -o scalper .
RUN go install gitlab.com/yawning/obfs4.git/obfs4proxy@latest
RUN apk add --no-cache protobuf protobuf-dev
RUN go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
RUN go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# Stage 2: Final hardened image
FROM alpine:3.19

RUN apk add --no-cache \
    tor \
    chromium \
    nss \
    freetype \
    harfbuzz \
    ca-certificates \
    ttf-freefont \
    su-exec \
    dumb-init \
    tesseract-ocr \
    tesseract-ocr-data-eng \
    libtesseract-dev \
    leptonica-dev

# Create a non-root user
RUN adduser -D scalper

WORKDIR /app
COPY --from=builder /app/scalper .
COPY --from=builder /go/bin/obfs4proxy /usr/bin/obfs4proxy
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Improvement 4: Persistence moved to PostgreSQL (stateless container)
# RUN touch /app/darknet_intel.db && chown scalper:scalper /app/darknet_intel.db

# Tor Configuration (Internal only)
RUN echo "SocksPort 9050" > /etc/tor/torrc && \
    echo "ControlPort 9051" >> /etc/tor/torrc && \
    echo "CookieAuthentication 1" >> /etc/tor/torrc

# Expose only the Scalper API port
EXPOSE 9090

# Use dumb-init to handle signals and su-exec to drop privileges
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]
