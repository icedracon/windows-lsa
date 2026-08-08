//! # windows-lsa
//!
//! Thin, safe wrapper around the Windows Local Security Authority (LSA)
//! **Kerberos authentication package** primitives:
//!
//! - [`LsaConnectUntrusted`] — get a handle to LSA that non-privileged code can use.
//! - [`LsaLookupAuthenticationPackage`] — resolve the `"Kerberos"` package id.
//! - [`LsaCallAuthenticationPackage`] with:
//!   - `KerbRetrieveTicketMessage`  — pull the current TGT.
//!   - `KerbQueryTicketCacheMessage` — enumerate the LSA ticket cache.
//!   - `KerbSubmitTicketMessage`    — inject a KRB-CRED into the cache.
//!   - `KerbPurgeTicketCacheMessage` — purge specific / all entries.
//!
//! Status: **pre-alpha, 0.1.0-dev.** API surface is stable-ish, but structural
//! parsing of the returned Kerberos payloads is minimal (raw byte extraction
//! only — no ASN.1 decode, no KRB-CRED wrapping). Enough to prove the LSA
//! plumbing works round-trip; not enough to be a drop-in Mimikatz replacement.
//!
//! On non-Windows targets the crate compiles to a stub that returns
//! [`Error::Unsupported`] for every call, so downstream crates can `cfg`-gate
//! at their own convenience.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_debug_implementations)]

mod error;
mod types;

pub use error::{Error, Result};
pub use types::{AuthPackageId, KrbCred, Luid, TicketCacheInfo};

#[cfg(windows)]
mod sys;

#[cfg(windows)]
pub use sys::{Lsa, LsaHandle};

#[cfg(not(windows))]
mod stub;

#[cfg(not(windows))]
pub use stub::{Lsa, LsaHandle};

/// Convenience: connect, look up Kerberos, retrieve the TGT for the current
/// logon session (or the caller-supplied LUID if `luid` is `Some` and the
/// caller holds `SeTcbPrivilege`).
///
/// This is what most callers actually want. It performs `LsaConnectUntrusted`,
/// resolves the Kerberos package id, and issues `KerbRetrieveTicketMessage`.
pub fn retrieve_tgt(luid: Option<Luid>) -> Result<KrbCred> {
    let h = Lsa::connect_untrusted()?;
    let pkg = h.kerberos_package()?;
    h.retrieve_tgt(pkg, luid)
}

/// Convenience wrapper around `KerbQueryTicketCacheMessage`.
pub fn query_ticket_cache(luid: Option<Luid>) -> Result<Vec<TicketCacheInfo>> {
    let h = Lsa::connect_untrusted()?;
    let pkg = h.kerberos_package()?;
    h.query_ticket_cache(pkg, luid)
}

/// Convenience wrapper around `KerbSubmitTicketMessage`.
///
/// `cred.encoded` is passed through verbatim — it MUST already be a valid
/// ASN.1-DER `KRB-CRED` structure. This crate does not yet build KRB-CRED
/// wrappers for you.
pub fn submit_ticket(cred: &KrbCred, luid: Option<Luid>) -> Result<()> {
    let h = Lsa::connect_untrusted()?;
    let pkg = h.kerberos_package()?;
    h.submit_ticket(pkg, cred, luid)
}

/// Convenience wrapper around `KerbPurgeTicketCacheMessage`.
///
/// If `target_spn` is `None`, every ticket in the cache for `luid` is purged.
pub fn purge_ticket_cache(luid: Option<Luid>, target_spn: Option<&str>) -> Result<()> {
    let h = Lsa::connect_untrusted()?;
    let pkg = h.kerberos_package()?;
    h.purge_ticket_cache(pkg, luid, target_spn)
}
