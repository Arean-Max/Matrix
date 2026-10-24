# Deploying Event Horizon

Three supported shapes, all running the same binary:

| Shape | Use it when | Start here |
|-------|-------------|------------|
| systemd + SQLite on one box | default for a small vendor | `eh-server.service` + `config/server.example.yaml` |
| Docker / Compose | container platforms | `Dockerfile` + `docker-compose.yml` |
| Bare binary | you have your own supervisor | `eh-server -config server.yaml` |

## First run

1. Copy `config/server.example.yaml` and edit the paths.
2. Provide TLS material: `tls.cert_file` / `tls.key_file` are mandatory
   unless `security.dev_allow_http` is set for a development box. Any
   standard X.509 pair works (Let's Encrypt, company CA).
3. Start the server. On the very first start it writes
   `<data_dir>/bootstrap.token` and logs how to consume it.
4. Bootstrap the operator: `ehctl init --bootstrap-file <data_dir>/bootstrap.token`.
   The bootstrap credential is removed automatically once a real admin token
   exists (ADR-006).
5. Create the first license:
   `ehctl license create --customer "Acme" --channel manual`
   (for webhook delivery, set `notify.webhook_secret` first; otherwise
   webhook channels are rejected).

## Backups

`deploy/backup.sh` wraps `ehctl backup` (consistent SQLite copy via
`VACUUM INTO`) with retention. Schedule it nightly. Back up the master key
and TLS files **separately** — see `docs/OPERATIONS.md`.

## Verify the deployment

- `eh-server -health-check -config server.yaml` → exit 0 when the liveness
  endpoint answers (used by the container healthcheck).
- `ehctl status` → version, counters, uptime.
- End-to-end smoke: run `rust/target/release/eh-demo.exe --help`.

The Dockerfile and Compose file are provided for deployment but were **not
runtime-tested in this repository's build environment** (no Docker daemon
available); the systemd path and the binary itself were tested on Windows
and Linux shell level.
