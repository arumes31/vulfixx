FROM golang:1.27.3-alpine3.24@sha256:fa3d596898d9f126af7c01d14ee7597bab3f39cccf392ef36b69fe77cd681f18 AS builder
RUN apk add --no-cache ca-certificates nodejs npm tzdata


WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .
RUN npm ci
RUN npx tailwindcss -i ./input.css -o ./static/css/main.css --minify
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/cve-tracker ./cmd/cve-tracker \
    && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/healthcheck ./cmd/healthcheck

FROM scratch
WORKDIR /app
COPY --from=builder --chown=10001:10001 /out/cve-tracker ./cve-tracker
COPY --from=builder --chown=10001:10001 /out/healthcheck ./healthcheck
COPY --from=builder --chown=10001:10001 /app/templates ./templates
COPY --from=builder --chown=10001:10001 /app/static ./static
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

USER 10001:10001

EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD ["./healthcheck"]
CMD ["./cve-tracker"]
