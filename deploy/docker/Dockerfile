# Multi-stage Dockerfile for Event Horizon License & Attestation Server (Spec v12)
FROM golang:1.22-alpine AS builder

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY shared/ ./shared/
COPY server/ ./server/
COPY builder/ ./builder/

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-w -s" -o /bin/event-horizon-server ./server/cmd/server

# Final minimal runtime container
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

RUN addgroup -S appgroup && adduser -S appuser -G appgroup
USER appuser

WORKDIR /app
COPY --from=builder /bin/event-horizon-server /app/server

EXPOSE 8443
VOLUME ["/var/lib/event-horizon"]

ENTRYPOINT ["/app/server"]
CMD ["--port=8443", "--db=/var/lib/event-horizon/event_horizon.db"]
