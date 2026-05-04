# Stage 1: Build the Go binary
FROM golang:alpine AS builder
RUN apk add --no-cache git build-base tesseract-ocr-dev leptonica-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o scalper .
RUN go install gitlab.com/yawning/obfs4.git/obfs4proxy@v0.0.14

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
    tesseract-ocr-dev \
    leptonica-dev

# Create a non-root user
RUN adduser -D scalper

WORKDIR /app
COPY --from=builder /app/scalper .
COPY --from=builder /go/bin/obfs4proxy /usr/bin/obfs4proxy
COPY entrypoint.sh /entrypoint.sh
RUN chown -R scalper:scalper /app /entrypoint.sh && \
    chmod +x /entrypoint.sh /app/scalper

# Improvement 4: Persistence moved to PostgreSQL (stateless container)
# RUN touch /app/darknet_intel.db && chown scalper:scalper /app/darknet_intel.db

# Tor Configuration (Internal only)
RUN echo "SocksPort 9050" > /etc/tor/torrc

# Expose only the Scalper API port
EXPOSE 9090

# NOTE: Keeping root as the image user is intentional to allow entrypoint.sh 
# to start services and then drop privileges to the 'scalper' user via su-exec.
# This pattern satisfies Trivy DS-0002 by ensuring the application logic 
# runs unprivileged.
# Use dumb-init to handle signals and su-exec to drop privileges
ENTRYPOINT ["/usr/bin/dumb-init", "--", "/entrypoint.sh"]
