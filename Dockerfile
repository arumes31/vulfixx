FROM golang:1.25-alpine AS builder
RUN apk add --no-cache nodejs npm


WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN npm install -D tailwindcss@3 postcss autoprefixer @tailwindcss/forms @tailwindcss/container-queries
RUN npx tailwindcss -i ./input.css -o ./static/css/main.css --minify
RUN CGO_ENABLED=0 GOOS=linux go build -o cve-tracker ./cmd/cve-tracker

FROM ubuntu:24.04
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates tzdata && rm -rf /var/lib/apt/lists/*

# Create non-root user (fix for ubuntu:24.04 default user conflict)
RUN userdel -f ubuntu && \
    groupadd -g 1000 appuser && \
    useradd -u 1000 -g appuser -m appuser


WORKDIR /app
COPY --from=builder /app/cve-tracker .
COPY --from=builder /app/templates ./templates
COPY --from=builder /app/static ./static

RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8080
CMD ["./cve-tracker"]
