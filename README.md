# PathLab (MVP)

**PathLab** is a tiny, cross‑platform, kernel‑free impairment proxy purpose‑built for **PQC/TLS handshake** testing.
It runs as a transparent TCP proxy, peeks at the **TLS ClientHello**, and can deterministically trigger the two
PQC‑specific early‑flight failures you care about:

- **`ABORT_AFTER_CH`** — forwards the ClientHello then immediately resets the connection (fast‑fail / middlebox intolerance).
- **`MTU1300_BLACKHOLE`** — forwards only the first N bytes (default **1300**) of the ClientHello and silently drops the rest
  to simulate a **PMTUD black‑hole** (slow‑fail / timeout).
 - **`LATENCY_50MS_JITTER_10`** — injects ~50ms base one‑way latency (+/‑ jitter) on client→upstream path after parsing ClientHello.
 - **`BANDWIDTH_1MBPS`** — throttles client→upstream throughput to ~1 Mbps after the ClientHello.

> No kernel modules. No admin rights. Single Go binary. HTTP control plane for automation.

---

## Build & Run

### Prereqs
- Go **1.22+** (`go version`)
- Optional: Docker (for containerized run)

### Build
```bash
cd cmd/pathlab
go build -o ../../bin/pathlab
../../bin/pathlab -h
```

### Run against a local upstream
Assume your TLS terminator (e.g., nginx or Envoy) listens on `127.0.0.1:8443`.

```bash
# Start PathLab: clients connect to :10443, PathLab forwards to 127.0.0.1:8443
./bin/pathlab -listen :10443 -upstream 127.0.0.1:8443 -admin :8080
```

Point your client to `https://localhost:10443` (or configure your app to talk to `:10443`).

### Docker
```bash
docker build -t pathlab:latest .
# Forward to an "upstream" service named nginx:443 in docker-compose
docker run --rm -p 10443:10443 -p 8080:8080 \
  -e PATHLAB_UPSTREAM=nginx:443 -e PATHLAB_LISTEN=:10443 -e PATHLAB_ADMIN=:8080 \
  pathlab:latest
```

See `docker-compose.example.yml` for an end‑to‑end sample.

---

## HTTP Control Plane

- `GET /impair/status` — current profile (JSON)
- `POST /impair/clear`  — return to pass‑through
- `POST /impair/apply`  — set profile via JSON body or query params

Examples:

```bash
# Fast‑fail: forward CH then RST both sides
curl -XPOST "http://localhost:8080/impair/apply?profile=ABORT_AFTER_CH"

# PMTUD black‑hole: forward first 1300 bytes, drop the rest (adjust with threshold_bytes)
curl -XPOST "http://localhost:8080/impair/apply?profile=MTU1300_BLACKHOLE&threshold_bytes=1300"

# Clear impairments
curl -XPOST "http://localhost:8080/impair/clear"

# Latency + jitter (defaults 50ms + 10ms jitter)
curl -XPOST "http://localhost:8080/impair/apply?profile=LATENCY_50MS_JITTER_10&latency_ms=80&jitter_ms=20"

# Bandwidth cap (approx 500 kbps)
curl -XPOST "http://localhost:8080/impair/apply?profile=BANDWIDTH_1MBPS&bandwidth_kbps=500"
```

Response (example):
```json
{
  "profile": "MTU1300_BLACKHOLE",
  "threshold_bytes": 1300,
  "updated_at": "2025-09-05T12:34:56Z"
}
```

### Rule DSL (dynamic per‑connection profiles)

PathLab can auto‑select an impairment profile per connection by inspecting the **ClientHello** before proxying it upstream.

Load rules (plain text) via `POST /rules`:

```
when ch_bytes > 1400 then MTU1300_BLACKHOLE
when pqc_hint == true then ABORT_AFTER_CH
when sni_contains example.com then LATENCY_50MS_JITTER_10
when alpn_contains h2 then LATENCY_50MS_JITTER_10
when cipher_count > 30 then MTU1300_BLACKHOLE
```

Supported condition fields:
- `ch_bytes` (numeric)
- `pqc_hint` (boolean)
- `cipher_count` (numeric)
- `sni_contains` (substring, case‑insensitive)
- `alpn_contains` (exact protocol token match, case‑insensitive)
- `ja3` (exact md5 hex fingerprint)

Comparators for numeric: `> >= < <= ==`
Boolean: `pqc_hint == true|false`
Substring forms omit an operator: `sni_contains example.com`
JA3: `ja3 == <32hex>`

Endpoints:
- `GET /rules` — list loaded rules
- `POST /rules` — replace rules with request body (text/plain)
- `DELETE /rules` — clear rules
- `GET /rules/test?...` — dry‑run matcher without a real connection. Query params: `ch_bytes`, `pqc_hint`, `cipher_count`, `sni`, `alpn`.

Example dry run:
```bash
curl "http://localhost:8080/rules/test?ch_bytes=1500"        # expect blackhole if rule loaded
curl "http://localhost:8080/rules/test?sni=example.com"     # triggers sni_contains rule
curl "http://localhost:8080/rules/test?alpn=h2"             # triggers alpn rule
```

Runtime logs show which rule matched:
```
[conn 12] rule matched -> profile=MTU1300_BLACKHOLE (ch_bytes=1522 pqc_hint=false)
```

If no rule matches, the current global impairment profile remains in effect.

### Signed Connection Receipts

Each connection produces a signed JSON **receipt** summarizing:
- Global profile at accept time
- Applied (possibly rule‑overridden) profile
- Rule match (if any)
- ClientHello metrics (bytes, cipher_count, pqc_hint, SNI, ALPN)
- JA3 fingerprint
- Outcome (closed/error) and error string

Endpoints:
- `GET /receipts?limit=50` — recent receipts (ring buffer, default capacity 256)
- `GET /receipts?id=12` — specific receipt
- `GET /receipts/pubkey` — Ed25519 public key (hex) used to sign receipts
- `GET /receipts/verify?id=12` — server-side verification of hash + signature
- `GET /receipts/stream` — live NDJSON stream of future receipts
- `POST /quic/parse_initial` — body: hex-encoded UDP datagram; returns parsed QUIC Initial metadata

Signature process:
1. Canonical JSON of the receipt with `hash` and `sig` fields empty is serialized.
2. SHA‑256 hex digest stored in `hash`.
3. Ed25519 signature over the canonical JSON stored in `sig` (hex).

Client‑side verification (pseudo Go):
```go
// fetch pubkey hex and receipt r
data := canonicalize(r) // same process: zero hash/sig, json.Marshal
ok := ed25519.Verify(pub, data, sig)
```

Key persistence: PathLab stores a 32‑byte Ed25519 seed in `pathlab-ed25519.key` (override with `-keyfile` or `PATHLAB_KEYFILE`). It is created on first run with secure randomness (0600 permissions).

---

## How it works (MVP)

- Accepts a client TCP connection and dials the upstream.
- Reads TLS records until a full **ClientHello** handshake is buffered (without terminating TLS).
- Depending on the active profile:
  - **ABORT_AFTER_CH**: writes the full ClientHello to upstream, then issues a best‑effort **RST** (linger = 0) on both sides.
  - **MTU1300_BLACKHOLE**: writes only the first **N** bytes of the ClientHello to upstream, then **silently discards** any further
    client bytes, leaving the connection to hang until the peer times out (default ~30s).

The parser is intentionally minimal but robust enough for most TLS 1.2/1.3 ClientHello variants.
A best‑effort `pqc_hint` flag is set if the buffer contains the hybrid group ID bytes (e.g., `0x11ec`).

> Note: PathLab (MVP) operates on TCP streams and **simulates** packet‑level issues. For true packet/ICMP behavior, use
> a host‑level script (see `scripts/windows/pathlab-windows-pmtud.ps1`) or Linux `tc`/`netem` in a privileged environment.

---

## Quick acceptance drills

1. **Middlebox intolerance (fast‑fail)**
   ```bash
   curl -XPOST http://localhost:8080/impair/apply?profile=ABORT_AFTER_CH
   # hit your service through :10443 and verify the breaker opens quickly and receipts show cause=middlebox_abort
   ```

2. **PMTUD black‑hole (slow‑fail)**
   ```bash
   curl -XPOST "http://localhost:8080/impair/apply?profile=MTU1300_BLACKHOLE&threshold_bytes=1300"
   # run handshake again, expect client timeout; breaker should trip open on timeout; receipts show cause=pmtud_blackhole
   ```

3. **Back to clean**
   ```bash
   curl -XPOST http://localhost:8080/impair/clear
   ```

---

## Example docker-compose

See `docker-compose.example.yml` for an nginx upstream and a PathLab sidecar.

### Integrating into an existing stack

Drop a `docker-compose.override.yml` alongside your existing `docker-compose.yml`:

```yaml
version: "3.8"
services:
  pathlab:
    build: .
    image: pathlab:latest
    environment:
      - PATHLAB_UPSTREAM=nginx:8443   # or envoy:8443
      - PATHLAB_LISTEN=:10443
      - PATHLAB_ADMIN=:8080
    ports:
      - "10443:10443"   # client entrypoint
      - "8080:8080"     # admin API
    depends_on:
      - nginx
    restart: unless-stopped
```

Then:
```bash
docker compose up -d --build pathlab
curl -k https://localhost:10443/
curl http://localhost:8080/impair/status
```

Point clients or your ingress front-end to `:10443` instead of the upstream’s original port. Use impairment APIs during tests; remove the override file (or `docker compose rm pathlab`) to revert.

---

## Roadmap (after MVP)

- QUIC/HTTP3 initial flight support (parse QUIC Initial / CRYPTO frames).
  - (partial) Initial packet metadata endpoint `/quic/parse_initial`.
- Signed impairment manifests & per‑connection receipts (Ed25519).
- Per‑direction & adaptive bandwidth/latency shaping refinements.
- Additional rule predicates: ALPN list contains, cipher suite IDs, JA3 hash, time‑window scheduling.

---

## Windows PMTUD script (optional true black‑hole)

`scripts/windows/pathlab-windows-pmtud.ps1` shows how to **lower interface MTU** and **block ICMP Fragmentation Needed**
to reproduce a real PMTUD black‑hole without drivers. Use with caution and revert after tests.

---

## Security & Caveats

- PathLab does **not** terminate TLS; it cannot access tls‑exporter keys. Use it alongside your TLS terminator to bind
  PPE/PCH receipts to sessions at the gateway.
- The RST behavior uses `SetLinger(0)`. Exact behavior may vary by OS. FIN close is acceptable for tests that only care
  about fast vs slow failure.


MIT License — see `LICENSE`.
