//! Public data types shared between the Windows and stub back-ends.

use core::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Windows Locally Unique Identifier — same wire layout as `LUID` /
/// `LARGE_INTEGER`, kept target-neutral so it appears in the API on every OS.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, Hash)]
#[repr(C)]
pub struct Luid {
    pub low_part: u32,
    pub high_part: i32,
}

impl Luid {
    pub const ZERO: Luid = Luid {
        low_part: 0,
        high_part: 0,
    };

    #[inline]
    pub const fn new(low_part: u32, high_part: i32) -> Self {
        Self {
            low_part,
            high_part,
        }
    }

    #[inline]
    pub const fn as_u64(self) -> u64 {
        ((self.high_part as u32 as u64) << 32) | (self.low_part as u64)
    }
}

impl fmt::Display for Luid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "0x{:016x}", self.as_u64())
    }
}

/// Identifier returned by `LsaLookupAuthenticationPackage`. Newtype so it
/// cannot be confused with a raw u32.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub struct AuthPackageId(pub u32);

/// A Kerberos credential blob as accepted by `KerbSubmitTicketMessage` and
/// returned (in raw ticket form) by `KerbRetrieveTicketMessage`.
///
/// `encoded` is treated as opaque bytes by this crate — no ASN.1 parsing is
/// performed. For `submit_ticket` the caller MUST already have a valid
/// `KRB-CRED` structure. For values returned by [`crate::retrieve_tgt`] the
/// bytes are the raw `EncodedTicket` field of `KERB_EXTERNAL_TICKET` (i.e.
/// the ASN.1-DER `Ticket`, not a full `KRB-CRED`); wrapping that into a
/// KRB-CRED before it can be re-submitted is out of scope for this pre-alpha.
#[derive(Clone, Default, Zeroize, ZeroizeOnDrop)]
pub struct KrbCred {
    pub encoded: Vec<u8>,
}

impl KrbCred {
    #[inline]
    pub fn new(encoded: Vec<u8>) -> Self {
        Self { encoded }
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    #[inline]
    pub fn is_empty(&self) -> bool {
        self.encoded.is_empty()
    }

    #[inline]
    pub fn len(&self) -> usize {
        self.encoded.len()
    }
}

impl fmt::Debug for KrbCred {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KrbCred")
            .field("len", &self.encoded.len())
            .finish_non_exhaustive()
    }
}

/// One entry from `KerbQueryTicketCacheMessage`.
#[derive(Clone, Debug, Default)]
pub struct TicketCacheInfo {
    pub server_name: String,
    pub realm_name: String,
    pub start_time_ft: i64,
    pub end_time_ft: i64,
    pub renew_time_ft: i64,
    pub encryption_type: i32,
    pub ticket_flags: u32,
}
