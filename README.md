# windows-lsa

**STATUS: pre-alpha (0.1.0-dev). Windows-only functionality; compiles as a
stub on other targets. Not published, not stable.**

Thin safe wrapper around the Windows Local Security Authority (LSA)
Kerberos authentication package. Wraps:

- `LsaConnectUntrusted`
- `LsaLookupAuthenticationPackage("Kerberos")`
- `LsaCallAuthenticationPackage` with:
  - `KerbRetrieveTicketMessage`   (pull the current TGT)
  - `KerbQueryTicketCacheMessage` (enumerate cached tickets)
  - `KerbSubmitTicketMessage`     (inject a KRB-CRED)
  - `KerbPurgeTicketCacheMessage` (purge one SPN or all)

## Purpose

Building block for higher-level Windows Kerberos tooling (audit, DFIR,
ticket-round-trip, offline analysis). Kept intentionally small — no ASN.1
parsing, no KRB-CRED construction, no crypto. Those belong upstairs.

## Minimal usage

```rust
use windows_lsa::{retrieve_tgt, query_ticket_cache};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Enumerate the current logon session's ticket cache.
    for t in query_ticket_cache(None)? {
        println!("{} @ {}", t.server_name, t.realm_name);
    }

    // Pull the raw encoded ticket bytes of the TGT.
    let tgt = retrieve_tgt(None)?;
    println!("TGT bytes: {}", tgt.len());
    Ok(())
}
```

## What works (0.1.0-dev)

- `LsaConnectUntrusted` + `LsaDeregisterLogonProcess` (RAII).
- `LsaLookupAuthenticationPackage("Kerberos")`.
- `LsaCallAuthenticationPackage` transport, including protocol-status
  propagation and response-buffer free (`LsaFreeReturnBuffer`).
- `KerbRetrieveTicketMessage` — returns the `EncodedTicket` bytes of the
  TGT for the current or supplied LUID.
- `KerbQueryTicketCacheMessage` — enumerated as strongly-typed
  `TicketCacheInfo` entries.
- `KerbSubmitTicketMessage` — inline layout of header + KRB-CRED trailer,
  with correct `KerbCredOffset`.
- `KerbPurgeTicketCacheMessage` — inline layout of a trailing UTF-16 SPN.
- `zeroize` on the `KrbCred` payload.
- Non-Windows targets get a stub back-end that returns `Error::Unsupported`.

## Known gaps / next iterations

- The bytes returned by `retrieve_tgt` are the raw ASN.1 `Ticket`, not a
  full `KRB-CRED`. Re-submitting them via `submit_ticket` will not work
  until we add a KRB-CRED wrapper (out of scope for 0.1.0-dev).
- `KerbRetrieveEncodedTicketMessage` (per-SPN retrieval with target name)
  is not exposed yet — only the LUID-scoped TGT variant.
- `KerbQueryTicketCacheEx2Message` (session-key + client name) is not
  exposed yet.
- No live-DC integration tests. The `#[cfg(windows)]` smoke tests run
  against whatever cache the test host has and tolerate empty caches.

## License

MIT.
