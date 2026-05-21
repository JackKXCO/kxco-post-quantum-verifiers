# Changelog

All notable changes to the multi-language verifiers are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
each language uses its own SemVer line.

## [Unreleased]

### Added
- `SECURITY.md` — scope, threat model, disclosure window
- `.github/dependabot.yml` — weekly Mon 06:00 UTC for gomod, pip, cargo, github-actions
- Bench scripts per language (`bench_kxco_verify.py`, `go test -bench`, `cargo run --example bench`)
- Root `README.md` rewritten as the multi-language landing page with badge row
- Trusted Publishing for PyPI (`pypa/gh-action-pypi-publish`) and crates.io
  (`rust-lang/crates-io-auth-action`) — no long-lived token secrets after one-time
  web UI configuration on each registry

### Security
- No cryptographic code changed. Production behaviour is bit-for-bit identical to:
  - JavaScript: `kxco-post-quantum@1.0.3` on npm (separate repo)
  - Python: `kxco-verify@1.0.0` on PyPI
  - Rust: `kxco-verify@1.0.0` on crates.io
  - Go: `kxco-post-quantum-verifiers/go@go/v1.0.0` on proxy.golang.org

## [python/v1.0.0] — 2026-05-21
First Python release. `pip install kxco-verify`. See https://pypi.org/project/kxco-verify/

## [rust/v1.0.0] — 2026-05-21
First Rust release. `cargo add kxco-verify`. See https://crates.io/crates/kxco-verify

## [go/v1.0.0] — 2026-05-21
First Go release. `go get github.com/JackKXCO/kxco-post-quantum-verifiers/go@v1.0.0`.
See https://pkg.go.dev/github.com/JackKXCO/kxco-post-quantum-verifiers/go
