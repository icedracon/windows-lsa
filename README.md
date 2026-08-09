# windows-lsa

[![Crates.io](https://img.shields.io/crates/v/windows-lsa.svg)](https://crates.io/crates/windows-lsa)
[![Docs.rs](https://docs.rs/windows-lsa/badge.svg)](https://docs.rs/windows-lsa)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Safe Rust wrapper around the Windows **Local Security Authority (LSA)**
Kerberos authentication package. Enumerate the current logon session's ticket
cache, retrieve the TGT bytes, submit KRB-CRED, and purge entries — without
handwriting `LSA_STRING`, `KERB_*_REQUEST`, or `LsaFreeReturnBuffer` calls.
Intended for AD tooling, DFIR, and Kerberos audit code that needs to talk to
LSA directly rather than shelling out to `klist`.

## Status

**`0.1.0-dev`** — pre-alpha, expect breaking changes before `0.1.0`. Part of
the [icedracon](https://github.com/icedracon) Rust offensive-AD ecosystem.

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

- [`windows-sspi-shim`](https://github.com/icedracon/windows-sspi-shim) —
  SSPI Negotiate ergonomics over Devolutions `sspi` for callers that want
  `seal`/`unseal` rather than raw ticket bytes.
- [`windows-token`](https://github.com/icedracon/windows-token) — RAII
  tokens + impersonation; pair with LSA calls made under an alternate LUID.
- [`windows-scm`](https://github.com/icedracon/windows-scm) — local Service
  Control Manager wrapper for the "run as SYSTEM" side of the same tooling.

Together these enable "run adhammer as yourself" and impersonation-based
lateral-movement workflows without dragging in Impacket or Rubeus.

## License

MIT © 2026 [zevs](https://github.com/icedracon)
