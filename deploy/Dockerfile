FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=2.0.0
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X eventhorizon/internal/version.Version=${VERSION}" \
        -o /out/eh-server ./cmd/eh-server \
 && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" \
        -o /out/ehctl ./cmd/ehctl
RUN mkdir -p /out/data /out/var/lib/eh && chown -R 65532:65532 /out/data /out/var/lib/eh

FROM rust:1.99.0-bookworm AS trustd
WORKDIR /src
COPY rust ./rust
RUN cargo build --locked --release --manifest-path rust/Cargo.toml -p eh-trustd

FROM gcr.io/distroless/cc-debian12:nonroot
COPY --from=build /out/eh-server /usr/local/bin/eh-server
COPY --from=build /out/ehctl /usr/local/bin/ehctl
COPY --from=trustd /src/rust/target/release/eh-trustd /usr/local/bin/eh-trustd
COPY --from=build --chown=65532:65532 /out/data /data
COPY --from=build --chown=65532:65532 /out/var/lib/eh /var/lib/eh
ENV EH_ATTESTATION_TRUSTD_PATH=/usr/local/bin/eh-trustd
VOLUME ["/data", "/var/lib/eh"]
EXPOSE 8443
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["/usr/local/bin/eh-server", "-health-check", "-config", "/etc/eh/server.yaml"]
ENTRYPOINT ["/usr/local/bin/eh-server"]
CMD ["-config", "/etc/eh/server.yaml"]
