//! Error type.

use thiserror::Error;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug, Error)]
pub enum Error {
    /// LSA API returned a non-success NTSTATUS at the transport layer
    /// (i.e. the `LsaCallAuthenticationPackage` return value itself).
    #[error("LSA API {api} failed: NTSTATUS 0x{status:08x}")]
    Lsa { api: &'static str, status: u32 },

    /// `LsaCallAuthenticationPackage` succeeded at the transport level but
    /// the auth package (Kerberos) reported a protocol-level failure via the
    /// out-parameter `ProtocolStatus`.
    #[error("Kerberos package returned protocol error: NTSTATUS 0x{0:08x}")]
    Protocol(u32),

    /// A response buffer from the auth package was too short or malformed.
    #[error("response buffer malformed: {0}")]
    Malformed(&'static str),

    /// String supplied by the caller cannot be encoded into UTF-16 within
    /// the length constraints of a `UNICODE_STRING` (max 65534 bytes).
    #[error("string too long for UNICODE_STRING")]
    StringTooLong,

    /// Numeric overflow when computing a buffer size.
    #[error("buffer arithmetic overflow")]
    Overflow,

    /// Called on a non-Windows target. The whole crate is a no-op there.
    #[error("windows-lsa is only functional on Windows")]
    Unsupported,
}
