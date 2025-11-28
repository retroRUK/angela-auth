# ====== 1. Build Stage ======
FROM golang:1.25-alpine AS builder

WORKDIR /app

# Enable Go modules
ENV CGO_ENABLED=0
ENV GOOS=linux
ENV GOARCH=amd64

# Download dependencies first (cached)
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build the binary
RUN go build -o app src/main.go
# ====== 2. Runtime Stage ======
FROM alpine:latest

WORKDIR /app

# Copy the binary from builder stage
COPY --from=builder /app/app .

# Expose whichever port your app uses (example: 8080)
EXPOSE 5020

# Run the app
CMD ["./app"]