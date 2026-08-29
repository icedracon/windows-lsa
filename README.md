# windows-lsa

[![Crates.io](https://img.shields.io/crates/v/windows-lsa.svg)](https://crates.io/crates/windows-lsa)
[![Docs.rs](https://docs.rs/windows-lsa/badge.svg)](https://docs.rs/windows-lsa)
[![CI](https://github.com/icedracon/windows-lsa/actions/workflows/ci.yml/badge.svg)](https://github.com/icedracon/windows-lsa/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Safe Rust wrapper around the Windows **Local Security Authority (LSA)**
Kerberos authentication package. Enumerate the current logon session's ticket
cache, retrieve the TGT bytes, submit KRB-CRED, and purge entries — without
handwriting `LSA_STRING`, `KERB_*_REQUEST`, or `LsaFreeReturnBuffer` calls.
Intended for AD tooling, DFIR, and Kerberos audit code that needs to talk to
LSA directly rather than shelling out to `klist`.

## Status

**`0.2` tested companion crate.** LSA connection, Kerberos package lookup,
ticket-cache query, retrieval, submission, and purge paths are implemented on
top of `win32-min`; APIs may still evolve before 1.0. See the central
[`win32-min` ecosystem map](https://github.com/icedracon/win32-min/blob/master/ECOSYSTEM.md)
for compatibility and maturity information.

## What it does

Wraps the four `LsaCallAuthenticationPackage` messages that any real Kerberos
client tool ends up needing: `KerbRetrieveTicketMessage`,
`KerbQueryTicketCacheMessage`, `KerbSubmitTicketMessage`,
`KerbPurgeTicketCacheMessage`. The transport layer
(`LsaConnectUntrusted` / `LsaLookupAuthenticationPackage("Kerberos")` /
protocol-status propagation / response-buffer free) is done once, in RAII, so
callers only see typed `TicketCacheInfo` / `KrbCred` values. See
`[MS-KILE] 3.4.5` and `winnt.h` for the underlying primitives.

## Usage

```rust,no_run
use windows_lsa::{query_ticket_cache, retrieve_tgt};

fn main() -> windows_lsa::Result<()> {
    // Enumerate the current logon session's ticket cache.
    for t in query_ticket_cache(None)? {
        println!("{} @ {}", t.server_name, t.realm_name);
    }

    // Pull the current TGT (raw encoded ASN.1 Ticket bytes for the current LUID).
    let tgt = retrieve_tgt(None)?;
    println!("TGT: {} bytes", tgt.encoded.len());

    Ok(())
}
```

## Research workflow

Inventory the current logon session's Kerberos ticket metadata without
exporting or modifying ticket material:

```powershell
cargo run --example kerberos_cache
```

The example uses an untrusted LSA connection and can legitimately return an
empty cache for a local-account session. See the ecosystem's
[`RESEARCH-WORKFLOWS.md`](https://github.com/icedracon/win32-min/blob/master/RESEARCH-WORKFLOWS.md)
for the complete workflow set.

## What works / what does not (this version)

- Working:
  - `LsaConnectUntrusted` + `LsaDeregisterLogonProcess` via RAII `Lsa` handle.
  - `LsaLookupAuthenticationPackage("Kerberos")`.
  - `LsaCallAuthenticationPackage` transport, protocol-status propagation, and
    response-buffer free (`LsaFreeReturnBuffer`).
  - `KerbRetrieveTicketMessage` — encoded TGT bytes for current or supplied LUID.
  - `KerbQueryTicketCacheMessage` — strongly-typed `TicketCacheInfo` entries.
  - `KerbSubmitTicketMessage` — inline header + KRB-CRED trailer with correct
    `KerbCredOffset`.
  - `KerbPurgeTicketCacheMessage` — inline trailing UTF-16 SPN.
  - `zeroize` on `KrbCred` payload.
  - Non-Windows compile: stub returns `Error::Unsupported` at every entry point.
- Stubbed / next milestone:
  - Bytes returned by `retrieve_tgt` are the raw ASN.1 `Ticket`, **not** a full
    `KRB-CRED` — re-submitting via `submit_ticket` requires an external
    KRB-CRED wrapper.
  - `KerbRetrieveEncodedTicketMessage` (per-SPN with target name) not yet exposed.
  - `KerbQueryTicketCacheEx2Message` (session-key + client name) not yet exposed.
  - No live-DC integration tests — `#[cfg(windows)]` smoke tests tolerate empty caches.

## Related icedracon crates

- [`win32-min`](https://github.com/icedracon/win32-min) — verified,
  dependency-free Win32 ABI foundation used by this crate.
- [`windows-sspi-shim`](https://github.com/icedracon/windows-sspi-shim) —
  SSPI Negotiate ergonomics over Devolutions `sspi` for callers that want
  `seal`/`unseal` rather than raw ticket bytes.
- [`windows-token`](https://github.com/icedracon/windows-token) — RAII
  tokens + impersonation; pair with LSA calls made under an alternate LUID.
- [`windows-scm`](https://github.com/icedracon/windows-scm) — local Service
  Control Manager wrapper for the "run as SYSTEM" side of the same tooling.

Together these cover identity, authentication, telemetry, and local
administration workflows for Windows security research and defensive tooling.

## Dependencies

- `win32-min >= 0.1.2, < 0.2` with only `lsa-auth` enabled.
- `zeroize` for ticket payload cleanup and `thiserror` for the error taxonomy.
- No async runtime or generated Windows bindings.

## License

MIT © 2026 [zevs](https://github.com/icedracon)
