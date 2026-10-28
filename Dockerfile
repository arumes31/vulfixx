FROM golang:1.27.3-alpine@sha256:f2c872bcee949b7be9c490efd02b48a8a2fbf947cdf533f1c58525ec9d8170fd AS builder
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
