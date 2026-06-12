# NetScanner

A Rust network scanner with a web dashboard for discovering hosts on your local network and scanning external IPs.

## Features

- **Local network scan** — auto-detects private subnets and probes hosts via TCP connect
- **External target scan** — scan a single IP or CIDR (up to /16)
- **Web dashboard** — view discovered hosts, open ports, latency, and scan status
- **Re-run scans** — trigger local or external scans from the UI or API
- **Docker-first development** — build, test, and run entirely in containers

## Quick Start

```bash
# Run tests with 100% coverage enforcement
./scripts/test.sh

# Start the dashboard (host networking for local discovery)
docker compose up --build app
```

Open [http://localhost:8080](http://localhost:8080).

## API

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/health` | Health check |
| GET | `/api/hosts` | List discovered hosts |
| GET | `/api/status` | Current scan status |
| POST | `/api/scan/local` | Scan detected local subnet |
| POST | `/api/scan/target` | Scan `{ "target": "8.8.8.8" }` |

## Development (Docker only)

```bash
# Interactive dev container
docker compose run --rm dev

# Inside the container
cargo test --workspace
cargo run -p netscanner-server
```

## Architecture

- `netscanner-core` — scanning engine, CIDR expansion, host probing
- `netscanner-server` — Axum API + static dashboard
- `web/` — dashboard assets

## License

MIT
