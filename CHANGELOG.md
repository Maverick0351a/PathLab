# Changelog

## v0.1.0 - 2025-09-05
Initial public MVP release.
- Transparent TCP impairment proxy
- Profiles: CLEAN, ABORT_AFTER_CH, MTU1300_BLACKHOLE, LATENCY_50MS_JITTER_10, BANDWIDTH_1MBPS
- Rule DSL (ch_bytes, pqc_hint, cipher_count, sni_contains, alpn_contains, ja3)
- Signed connection receipts (Ed25519) + streaming endpoint
- JA3 fingerprint extraction
- QUIC Initial packet parser endpoint
- Configurable blackhole duration & directional bandwidth groundwork
- Basic tests & CI workflow
