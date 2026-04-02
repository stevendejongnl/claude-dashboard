# claude-dashboard

Real-time visibility into your Claude Code sessions. Intercepts HTTPS traffic via mitmproxy, stores it in SQLite, and streams it live to a web dashboard. Detects credential leaks in prompts and file reads using entropy-based pattern matching.

---

## What it shows

- **Live Wire** — every API call Claude Code makes, categorised (messages, metrics, statsig), with status, duration, size, and a leak badge
- **Telemetry Events** — `tengu_init`, `tengu_api_success`, `tengu_exit`, tool use events with cost/token metadata
- **Leaks** — secrets detected in outgoing prompts, redacted with context and entropy score
- **API Stats** — daily cost and token usage chart
- **Sessions** — per-session cost, input/output tokens, lines added/removed

Click any flow in the Live Wire panel to inspect the full request and response body.

---

## Architecture

```
Claude Code (Node.js)
  │  HTTPS_PROXY=http://localhost:8082
  │  NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem
  ▼
mitmproxy:8082  (proxy container)
  │  intercepts + decrypts TLS
  │  runs addon.py → scans for secrets → writes to SQLite
  ▼
dashboard.db  (SQLite, shared volume at ./data/)
  ▼
FastAPI:8888  (dashboard container)
  │  REST API + WebSocket broadcaster
  │  reads telemetry from TELEMETRY_DIR
  ▼
nginx:5000  (nginx container)
  │  reverse proxies to FastAPI
  ▼
Browser  (or via sandbox-setup at /dashboard/)
```

All three containers use `network_mode: host` — required when running inside a Proxmox LXC where Docker's iptables DNAT doesn't apply to loopback interfaces.

---

## Quick start (standalone)

### Prerequisites

- Docker + Docker Compose
- Claude Code CLI installed and authenticated

### 1. Clone and start

```bash
git clone https://github.com/stevendejongnl/claude-dashboard.git
cd claude-dashboard
docker compose up -d
```

On first start, mitmproxy generates its CA certificate at `~/.mitmproxy/mitmproxy-ca-cert.pem`.

### 2. Trust the CA certificate

**System-wide (Linux):**
```bash
sudo cp ~/.mitmproxy/mitmproxy-ca-cert.pem /usr/local/share/ca-certificates/mitmproxy.crt
sudo update-ca-certificates
```

**macOS:**
```bash
sudo security add-trusted-cert -d -r trustRoot \
  -k /Library/Keychains/System.keychain ~/.mitmproxy/mitmproxy-ca-cert.pem
```

You can also download it from the dashboard at `http://localhost:5000/api/cert` once it's running.

### 3. Route Claude Code through the proxy

Add a `claude` wrapper to your shell config (`.bashrc` or `.zshrc`):

```bash
claude() {
  HTTPS_PROXY=http://localhost:8082 \
  HTTP_PROXY=http://localhost:8082 \
  NO_PROXY=localhost,127.0.0.1,::1 \
  NODE_EXTRA_CA_CERTS=~/.mitmproxy/mitmproxy-ca-cert.pem \
  command claude "$@"
}
```

`NODE_EXTRA_CA_CERTS` is required — Node.js has its own CA bundle and ignores the system trust store.

### 4. Open the dashboard

```
http://localhost:5000
```

Run `claude` in another terminal and watch flows appear in real time.

---

## Telemetry events

Claude Code writes telemetry JSON files to `~/.claude/accounts/*/telemetry/`. The dashboard ingestor watches that directory and imports events on the fly. Mount it as a volume:

```yaml
volumes:
  - ~/.claude/accounts/work/telemetry:/telemetry:ro
```

Adjust the path to match your account directory. The `TELEMETRY_DIR` environment variable controls where the ingestor looks (default `/telemetry`).

---

## Running behind a path prefix

When serving the dashboard at a sub-path (e.g. `/dashboard/`) via a reverse proxy, the frontend uses a `<base href="/dashboard/">` tag and derives the WebSocket URL from it automatically. No additional configuration needed — just proxy `/dashboard/` to port `5000/`:

**nginx example:**
```nginx
location = /dashboard {
    return 302 /dashboard/;
}
location /dashboard/ {
    proxy_pass         http://localhost:5000/;
    proxy_http_version 1.1;
    proxy_set_header   Upgrade $http_upgrade;
    proxy_set_header   Connection "upgrade";
    proxy_set_header   Host $host;
    proxy_buffering    off;
}
```

---

## Credential leak detection

The proxy scans all text content sent to the Anthropic API (prompts, tool results, file reads) for secrets. Findings appear in the Leaks panel with severity, a redacted match, surrounding context, and Shannon entropy score.

### Detection rules

| Rule | Severity | What it matches |
|------|----------|----------------|
| `anthropic-api-key` | CRITICAL | `sk-ant-admin01-…` / `sk-ant-api03-…` |
| `rsa-private-key` | CRITICAL | PEM private key headers |
| `aws-access-key` | CRITICAL | `AKIA…`, `ASIA…`, etc. |
| `aws-secret-key` | CRITICAL | `aws_secret_access_key = …` (entropy ≥ 4.0) |
| `github-token` | HIGH | `ghp_…`, `ghs_…`, `github_pat_…` |
| `gitlab-token` | HIGH | `glpat-…` |
| `openai-key` | HIGH | `sk-…T3BlbkFJ…` |
| `stripe-key` | HIGH | `sk_live_…`, `rk_live_…` |
| `slack-webhook` | HIGH | `hooks.slack.com/services/…` |
| `jwt-token` | HIGH | `eyJ…eyJ…` |
| `db-connection-string` | HIGH | `postgres://user:pass@host/…` etc. |
| `generic-api-key` | MEDIUM | `api_key = …`, `access_token: …` (entropy ≥ 3.5) |
| `prose-password` | MEDIUM | `my password is …`, `wachtwoord is …` (entropy ≥ 3.1) |
| `env-secret` | MEDIUM | `PASSWORD=…`, `SECRET=…`, `TOKEN=…` (entropy ≥ 3.0) |
| `env-password-short` | MEDIUM | `PASS=…`, `PWD=…`, `KEY=…`, `CRED=…` (entropy ≥ 2.5) |

Entropy filtering reduces false positives on placeholder values like `PASSWORD=changeme`.

File content read via the Claude Code `Read` tool has its line-number prefixes (`1\t`, `2\t`) stripped before scanning so line-anchored patterns match correctly.

---

## Docker services

| Service | Image | Role |
|---------|-------|------|
| `proxy` | built from `./proxy/` | mitmproxy + addon.py |
| `dashboard` | built from `./dashboard/` | FastAPI + SQLite reader + WebSocket |
| `nginx` | `nginx:alpine` | Reverse proxy on port 5000 |

### Hot-reload without rebuilds

These files are volume-mounted and take effect after a container restart (no image rebuild needed):

```yaml
volumes:
  - ./proxy/scanner.py:/app/scanner.py:ro   # edit detection rules
  - ./proxy/addon.py:/app/addon.py:ro        # edit interception logic
  - ./dashboard/static:/app/static:ro        # edit frontend
```

```bash
# Apply a scanner.py change:
docker compose restart proxy

# Apply a frontend change:
docker compose restart dashboard
```

---

## REST API

| Endpoint | Description |
|----------|-------------|
| `GET /api/flows` | Recent API flows (`?limit=100&offset=0`) |
| `GET /api/events` | Telemetry events (`?event_name=tengu_exit&limit=200`) |
| `GET /api/leaks` | Detected secrets (`?severity=CRITICAL&limit=200`) |
| `GET /api/sessions` | Session summaries with cost and token totals |
| `GET /api/stats/cost` | Daily cost + token breakdown (for the chart) |
| `GET /api/cert` | Download the mitmproxy CA certificate |
| `WS  /ws` | WebSocket — streams `flow`, `event`, `leak` messages in real time |

---

## Data persistence

All data is stored in `./data/dashboard.db` (SQLite). The `data/` directory is a Docker volume mount — data persists across container restarts and rebuilds.

The mitmproxy CA certificate is stored in `~/.mitmproxy/` (also a volume mount). It is generated once on first start and reused on subsequent starts.

---

## Environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DB_PATH` | `/data/dashboard.db` | SQLite database path |
| `TELEMETRY_DIR` | `/telemetry` | Directory the ingestor watches for Claude Code telemetry JSON |
