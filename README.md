# PathLab

[![CI](https://github.com/Maverick0351a/PathLab/actions/workflows/ci.yml/badge.svg)](https://github.com/Maverick0351a/PathLab/actions/workflows/ci.yml)

Network path impairment & TLS/QUIC introspection lab in one self‑contained Go binary.

## Features
- TLS ClientHello introspection: SNI, ALPN, cipher count, JA3, basic PQC hint
- Rule DSL for conditional impairments (`ch_bytes`, `pqc_hint`, `cipher_count`, `sni_contains`, `alpn_contains`, `ja3`)
- Impairment profiles: CLEAN, ABORT_AFTER_CH, MTU1300_BLACKHOLE, LATENCY_50MS_JITTER_10, BANDWIDTH_1MBPS
- Configurable latency/jitter, bandwidth (up & down groundwork), blackhole duration
- Signed receipts (Ed25519) + streaming and verification endpoints
- QUIC Initial packet metadata parser endpoint
- Minimal tests + GitHub Actions CI

## Versioning
Current released version: see `VERSION` file and `CHANGELOG.md`. Tags follow semantic versioning (e.g. v0.1.0).

## Build
```
go build ./cmd/pathlab
```

## Run
```
pathlab -listen :10443 -upstream example.com:443 -admin :8080
```

## Key Admin Endpoints
- `/impair` (apply/clear/status) manage impairment profile
- `/rules` load/clear/list rule DSL
- `/rules/test` dry‑run rule matching via query params
- `/receipts` list recent signed receipts
- `/receipts/stream` SSE stream of new receipts
- `/receipts/pubkey` Ed25519 public key
- `/receipts/verify` server-side signature verification for a receipt id
- `/quic` parse hex‑encoded QUIC Initial packet (metadata only)

## License
Apache 2.0

See `CHANGELOG.md` for release notes and roadmap items.
