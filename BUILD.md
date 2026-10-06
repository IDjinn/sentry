# Building Sentry

## Requirements

- **Rust 1.80+** (MSRV — required by `std::sync::LazyLock`)
- **Postgres** running locally for tests and storage:
  ```bash
  docker compose -f deploy/docker/docker-compose.yml up -d postgres
  ```
- **Windows**: MSVC Build Tools 2022 (rustup toolchain
  `stable-x86_64-pc-windows-msvc`)
- Python 3 + sklearn, only if retraining the ONNX model
  (`tools/train_model.py`)

## Build

```bash
cargo build                # dev build
cargo build --release      # production binary at target/release/sentry
```

### Optional features

```bash
cargo build --release --features sentry-cli/onnx      # local AI model (ONNX)
cargo build --release --features sentry-cli/edge-tls  # TLS termination (443)
```

Features are off by default to keep builds fast and deps lean.

## Run

```bash
cp config/sentry.example.toml sentry.toml   # then edit
./target/release/sentry config validate
./target/release/sentry run
```

Useful subcommands: `sentry --help`, `sentry run`, `sentry datasets`,
`sentry feeds`, `sentry protocol validate`, `sentry firewall status`,
`sentry serve` (HTTP API + dashboard), `sentry service install`.

Secrets go in env vars, never in committed config:

```bash
export SENTRY_STORAGE__POSTGRES__URL=postgres://sentry:secret@db/sentry
export SENTRY_CF_TOKEN=xxx        # Cloudflare API token (optional)
export SENTRY_LLM_KEY=zzz         # OpenRouter key (optional)
```

## Development workflow

Before committing, all three must pass:

```bash
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all    # 550+ tests (554 with --features sentry-cli/onnx)
```

Run a single crate's tests:

```bash
cargo test -p sentry-core
```

Other checks:

- No debug `println!` in committed code — use `tracing`.
- No secrets or `target/` artifacts in commits.
- New protocol schemas are validated by `sentry config validate` and
  `sentry protocol validate <schema>`.

## Docker

```bash
docker build -t sentry .
docker compose -f deploy/docker/docker-compose.yml up -d
```

Kubernetes manifests live in [`deploy/k8s/`](./deploy/k8s/)
(edge sidecar example: `edge-sidecar.yaml`).
