//! Windows-only implementation. Everything in this file is gated on
//! `#[cfg(windows)]` at the crate root.
//!
//! The Kerberos submit/query/purge/retrieve request+response structures are
//! defined locally as `#[repr(C)]` POD to keep this crate independent of the
//! specific feature-gating of any single FFI provider — only the LSA transport
//! (`Lsa*` functions, `HANDLE`, `NTSTATUS`, `LSA_STRING`, `UNICODE_STRING`,
//! `LUID`) is imported from [`win32_min`].

use core::ffi::c_void;
use core::mem::size_of;
use core::ptr;

use win32_min::foundation::{HANDLE, LUID as WinLuid, NTSTATUS, UNICODE_STRING};
use win32_min::lsa_auth::{
    LsaCallAuthenticationPackage, LsaConnectUntrusted, LsaDeregisterLogonProcess,
    LsaFreeReturnBuffer, LsaLookupAuthenticationPackage, LSA_STRING,
};

use crate::error::{Error, Result};
use crate::types::{AuthPackageId, KrbCred, Luid, TicketCacheInfo};

// ---------------------------------------------------------------------------
// Kerberos protocol message ids (ntsecapi.h KERB_PROTOCOL_MESSAGE_TYPE).
// ---------------------------------------------------------------------------

const KERB_QUERY_TICKET_CACHE: u32 = 1;
const KERB_RETRIEVE_TICKET: u32 = 4;
const KERB_PURGE_TICKET_CACHE: u32 = 6;
const KERB_SUBMIT_TICKET: u32 = 19;

// Standard KerbRetrieveTicketMessage cache options — return whatever is in
// the cache, do not try to acquire a new TGT via KDC round-trip.
const KERB_RETRIEVE_TICKET_AS_KERB_CRED: u32 = 0x8;
// Default retrieve — 0 means "use cache", any encryption type.
const KERB_ETYPE_DEFAULT: i32 = 0;

// ---------------------------------------------------------------------------
// Kerberos LSA request/response structures. Layout must match the Windows
// SDK definitions in ntsecapi.h byte-for-byte.
// ---------------------------------------------------------------------------

#[repr(C)]
#[derive(Clone, Copy)]
struct SecHandle {
    lower: usize,
    upper: usize,
}

#[repr(C)]
struct KerbRetrieveTktRequest {
    message_type: u32,
    logon_id: WinLuid,
    target_name: UNICODE_STRING,
    ticket_flags: u32,
    cache_options: u32,
    encryption_type: i32,
    credentials_handle: SecHandle,
}

#[repr(C)]
struct KerbCryptoKey {
    key_type: i32,
    length: u32,
    value: *mut u8,
}

#[repr(C)]
struct KerbExternalTicket {
    service_name: *mut c_void, // PKERB_EXTERNAL_NAME
    target_name: *mut c_void,
    client_name: *mut c_void,
    domain_name: UNICODE_STRING,
    target_domain_name: UNICODE_STRING,
    alt_target_domain_name: UNICODE_STRING,
    session_key: KerbCryptoKey,
    ticket_flags: u32,
    flags: u32,
    key_expiration_time: i64,
    start_time: i64,
    end_time: i64,
    renew_until: i64,
    time_skew: i64,
    encoded_ticket_size: u32,
    encoded_ticket: *mut u8,
}

#[repr(C)]
struct KerbRetrieveTktResponse {
    ticket: KerbExternalTicket,
}

#[repr(C)]
struct KerbQueryTktCacheRequest {
    message_type: u32,
    logon_id: WinLuid,
}

#[repr(C)]
struct KerbTicketCacheInfoRaw {
    server_name: UNICODE_STRING,
    realm_name: UNICODE_STRING,
    start_time: i64,
    end_time: i64,
    renew_time: i64,
    encryption_type: i32,
    ticket_flags: u32,
}

#[repr(C)]
struct KerbQueryTktCacheResponse {
    message_type: u32,
    count_of_tickets: u32,
    // trailing: [KerbTicketCacheInfoRaw; count_of_tickets]
}

#[repr(C)]
struct KerbCryptoKey32 {
    key_type: i32,
    length: u32,
    offset: u32,
}

#[repr(C)]
struct KerbSubmitTktRequest {
    message_type: u32,
    logon_id: WinLuid,
    flags: u32,
    key: KerbCryptoKey32,
    kerb_cred_size: u32,
    kerb_cred_offset: u32,
    // trailing: kerb_cred_size bytes at kerb_cred_offset from start
}

#[repr(C)]
struct KerbPurgeTktCacheRequest {
    message_type: u32,
    logon_id: WinLuid,
    server_name: UNICODE_STRING,
    realm_name: UNICODE_STRING,
    // optional trailing UTF-16 payload the UNICODE_STRINGs may point into
}

/// Zero-initialized `UNICODE_STRING` (no default impl on the raw type).
#[inline]
fn empty_unicode_string() -> UNICODE_STRING {
    UNICODE_STRING {
        Length: 0,
        MaximumLength: 0,
        Buffer: core::ptr::null_mut(),
    }
}

// ---------------------------------------------------------------------------
// Public handle types.
// ---------------------------------------------------------------------------

/// Namespace type — the constructors live here to mirror the Win32 API shape.
#[derive(Debug)]
pub struct Lsa;

/// RAII wrapper around an LSA logon-process handle obtained via
/// `LsaConnectUntrusted`. Dropped via `LsaDeregisterLogonProcess`.
#[derive(Debug)]
pub struct LsaHandle {
    handle: HANDLE,
}

// The handle is owned; sending it across threads is safe (Win32 handles are
// process-global and LSA logon-process handles are not thread-affine).
unsafe impl Send for LsaHandle {}
unsafe impl Sync for LsaHandle {}

impl Lsa {
    /// `LsaConnectUntrusted` — obtain an LSA handle usable by non-privileged
    /// code. This is what every user-mode Kerberos client uses.
    pub fn connect_untrusted() -> Result<LsaHandle> {
        let mut h: HANDLE = ptr::null_mut();
        // SAFETY: out-pointer is valid, no aliasing, LsaConnectUntrusted has
        // no other pre-conditions.
        let status = unsafe { LsaConnectUntrusted(&mut h) };
        check(status, "LsaConnectUntrusted")?;
        Ok(LsaHandle { handle: h })
    }
}

impl Drop for LsaHandle {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // Best-effort. There is nothing sensible we can do with the return
            // value in Drop — mirrors what every other LSA client does.
            unsafe {
                let _ = LsaDeregisterLogonProcess(self.handle);
            }
        }
    }
}

impl LsaHandle {
    /// Look up the `"Kerberos"` authentication package id. Equivalent to
    /// `LsaLookupAuthenticationPackage(handle, "Kerberos", &pkg)`.
    pub fn kerberos_package(&self) -> Result<AuthPackageId> {
        // MICROSOFT_KERBEROS_NAME_A = "Kerberos".
        const NAME: &[u8] = b"Kerberos";
        let lsa_str = LSA_STRING {
            Length: NAME.len() as u16,
            MaximumLength: NAME.len() as u16,
            Buffer: NAME.as_ptr() as *mut u8,
        };
        let mut pkg: u32 = 0;
        let status = unsafe { LsaLookupAuthenticationPackage(self.handle, &lsa_str, &mut pkg) };
        check(status, "LsaLookupAuthenticationPackage")?;
        Ok(AuthPackageId(pkg))
    }

    /// `KerbRetrieveTicketMessage` — return the raw `EncodedTicket` bytes of
    /// the TGT for the current (or supplied) LUID.
    ///
    /// **Note:** the returned bytes are the ASN.1-DER `Ticket`, NOT a full
    /// KRB-CRED. Re-submitting this via `submit_ticket` will not work without
    /// first wrapping it — see the crate-level TODO.
    pub fn retrieve_tgt(&self, pkg: AuthPackageId, luid: Option<Luid>) -> Result<KrbCred> {
        let req = KerbRetrieveTktRequest {
            message_type: KERB_RETRIEVE_TICKET,
            logon_id: to_win_luid(luid),
            target_name: empty_unicode_string(),
            ticket_flags: 0,
            cache_options: KERB_RETRIEVE_TICKET_AS_KERB_CRED,
            encryption_type: KERB_ETYPE_DEFAULT,
            credentials_handle: SecHandle { lower: 0, upper: 0 },
        };

        let response = self.call(pkg, &req, size_of::<KerbRetrieveTktRequest>() as u32)?;
        // SAFETY: response is a valid LSA-allocated buffer of at least
        // response.len bytes and outlives this scope until we drop it.
        let bytes = unsafe {
            let resp_ptr = response.ptr as *const KerbRetrieveTktResponse;
            if response.len < size_of::<KerbRetrieveTktResponse>() {
                return Err(Error::Malformed("retrieve response short"));
            }
            let ticket = &(*resp_ptr).ticket;
            let size = ticket.encoded_ticket_size as usize;
            if size == 0 || ticket.encoded_ticket.is_null() {
                return Err(Error::Malformed("retrieve response has no ticket"));
            }
            core::slice::from_raw_parts(ticket.encoded_ticket, size).to_vec()
        };
        Ok(KrbCred::new(bytes))
    }

    /// `KerbQueryTicketCacheMessage` — enumerate cached tickets.
    pub fn query_ticket_cache(
        &self,
        pkg: AuthPackageId,
        luid: Option<Luid>,
    ) -> Result<Vec<TicketCacheInfo>> {
        let req = KerbQueryTktCacheRequest {
            message_type: KERB_QUERY_TICKET_CACHE,
            logon_id: to_win_luid(luid),
        };
        let response = self.call(pkg, &req, size_of::<KerbQueryTktCacheRequest>() as u32)?;

        // SAFETY: the buffer is at least response.len bytes long. We validate
        // both header size and per-entry stride before dereferencing.
        unsafe {
            if response.len < size_of::<KerbQueryTktCacheResponse>() {
                return Err(Error::Malformed("query response header short"));
            }
            let header = &*(response.ptr as *const KerbQueryTktCacheResponse);
            let n = header.count_of_tickets as usize;
            let stride = size_of::<KerbTicketCacheInfoRaw>();
            let needed = size_of::<KerbQueryTktCacheResponse>()
                .checked_add(n.checked_mul(stride).ok_or(Error::Overflow)?)
                .ok_or(Error::Overflow)?;
            if response.len < needed {
                return Err(Error::Malformed("query response trailing entries short"));
            }
            let entries_ptr = (response.ptr as *const u8)
                .add(size_of::<KerbQueryTktCacheResponse>())
                as *const KerbTicketCacheInfoRaw;

            let mut out = Vec::with_capacity(n);
            for i in 0..n {
                let raw = &*entries_ptr.add(i);
                out.push(TicketCacheInfo {
                    server_name: unicode_string_to_string(&raw.server_name),
                    realm_name: unicode_string_to_string(&raw.realm_name),
                    start_time_ft: raw.start_time,
                    end_time_ft: raw.end_time,
                    renew_time_ft: raw.renew_time,
                    encryption_type: raw.encryption_type,
                    ticket_flags: raw.ticket_flags,
                });
            }
            Ok(out)
        }
    }

    /// `KerbSubmitTicketMessage` — inject `cred.encoded` (a KRB-CRED) into
    /// the LSA cache for the given LUID.
    pub fn submit_ticket(
        &self,
        pkg: AuthPackageId,
        cred: &KrbCred,
        luid: Option<Luid>,
    ) -> Result<()> {
        let hdr_len = size_of::<KerbSubmitTktRequest>();
        let total = hdr_len
            .checked_add(cred.encoded.len())
            .ok_or(Error::Overflow)?;
        if total > u32::MAX as usize {
            return Err(Error::Overflow);
        }

        let mut buf: Vec<u8> = vec![0u8; total];
        {
            let hdr = KerbSubmitTktRequest {
                message_type: KERB_SUBMIT_TICKET,
                logon_id: to_win_luid(luid),
                flags: 0,
                key: KerbCryptoKey32 {
                    key_type: 0,
                    length: 0,
                    offset: 0,
                },
                kerb_cred_size: cred.encoded.len() as u32,
                kerb_cred_offset: hdr_len as u32,
            };
            // SAFETY: buf is at least hdr_len bytes; hdr is POD.
            unsafe {
                ptr::write(buf.as_mut_ptr() as *mut KerbSubmitTktRequest, hdr);
            }
        }
        if !cred.encoded.is_empty() {
            buf[hdr_len..].copy_from_slice(&cred.encoded);
        }

        // Discard the (usually empty) response buffer.
        let _ = self.call_raw(pkg, buf.as_ptr() as *const c_void, total as u32)?;
        Ok(())
    }

    /// `KerbPurgeTicketCacheMessage` — purge either everything, or one SPN.
    ///
    /// The realm-name field is left empty; passing an SPN alone matches the
    /// Windows behaviour of purging every entry with that ServerName across
    /// realms.
    pub fn purge_ticket_cache(
        &self,
        pkg: AuthPackageId,
        luid: Option<Luid>,
        target_spn: Option<&str>,
    ) -> Result<()> {
        // Precompute the trailing UTF-16 payload for ServerName, if any.
        let spn_utf16: Vec<u16> = match target_spn {
            None => Vec::new(),
            Some(s) => s.encode_utf16().collect(),
        };
        let spn_bytes = spn_utf16.len().checked_mul(2).ok_or(Error::Overflow)?;
        if spn_bytes > u16::MAX as usize - 2 {
            return Err(Error::StringTooLong);
        }

        let hdr_len = size_of::<KerbPurgeTktCacheRequest>();
        let total = hdr_len.checked_add(spn_bytes).ok_or(Error::Overflow)?;

        let mut buf: Vec<u8> = vec![0u8; total];
        // Copy the SPN into the trailer first so we can point Buffer at it.
        if spn_bytes > 0 {
            // SAFETY: spn_utf16 fits within the trailer; buf is large enough.
            unsafe {
                ptr::copy_nonoverlapping(
                    spn_utf16.as_ptr() as *const u8,
                    buf.as_mut_ptr().add(hdr_len),
                    spn_bytes,
                );
            }
        }
        let server_name = if spn_bytes == 0 {
            empty_unicode_string()
        } else {
            // SAFETY: the buffer trailer holds a valid UTF-16 sequence.
            UNICODE_STRING {
                Length: spn_bytes as u16,
                MaximumLength: spn_bytes as u16,
                Buffer: unsafe { buf.as_mut_ptr().add(hdr_len) as *mut u16 },
            }
        };
        let hdr = KerbPurgeTktCacheRequest {
            message_type: KERB_PURGE_TICKET_CACHE,
            logon_id: to_win_luid(luid),
            server_name,
            realm_name: empty_unicode_string(),
        };
        // SAFETY: buf is at least hdr_len bytes long; hdr is POD.
        unsafe {
            ptr::write(buf.as_mut_ptr() as *mut KerbPurgeTktCacheRequest, hdr);
        }

        let _ = self.call_raw(pkg, buf.as_ptr() as *const c_void, total as u32)?;
        Ok(())
    }

    // ---------- private helpers ----------

    fn call<T>(&self, pkg: AuthPackageId, req: &T, len: u32) -> Result<LsaResponse> {
        self.call_raw(pkg, req as *const T as *const c_void, len)
    }

    fn call_raw(&self, pkg: AuthPackageId, buf: *const c_void, len: u32) -> Result<LsaResponse> {
        let mut ret_buf: *mut c_void = ptr::null_mut();
        let mut ret_len: u32 = 0;
        let mut proto_status: NTSTATUS = 0;

        // SAFETY: all pointers are valid and non-aliasing; buf/len describe a
        // valid caller-owned request; the three out-parameters are exclusively
        // owned by this call.
        let status = unsafe {
            LsaCallAuthenticationPackage(
                self.handle,
                pkg.0,
                buf,
                len,
                &mut ret_buf,
                &mut ret_len,
                &mut proto_status,
            )
        };
        check(status, "LsaCallAuthenticationPackage")?;
        if proto_status != 0 {
            // Free the (possibly still-allocated) return buffer before bailing.
            if !ret_buf.is_null() {
                unsafe {
                    let _ = LsaFreeReturnBuffer(ret_buf);
                }
            }
            return Err(Error::Protocol(proto_status as u32));
        }
        Ok(LsaResponse {
            ptr: ret_buf,
            len: ret_len as usize,
        })
    }
}

// RAII wrapper for a return buffer that must be freed with LsaFreeReturnBuffer.
struct LsaResponse {
    ptr: *mut c_void,
    len: usize,
}

impl Drop for LsaResponse {
    fn drop(&mut self) {
        if !self.ptr.is_null() {
            // SAFETY: ptr was allocated by LsaCallAuthenticationPackage; free
            // exactly once, from the same DLL.
            unsafe {
                let _ = LsaFreeReturnBuffer(self.ptr);
            }
        }
    }
}

// ---------- misc ----------

fn to_win_luid(luid: Option<Luid>) -> WinLuid {
    match luid {
        None => WinLuid {
            LowPart: 0,
            HighPart: 0,
        },
        Some(l) => WinLuid {
            LowPart: l.low_part,
            HighPart: l.high_part,
        },
    }
}

fn check(status: NTSTATUS, api: &'static str) -> Result<()> {
    // NT_SUCCESS: high bit clear. LSA returns exactly STATUS_SUCCESS for the
    // transport-level calls we make, so a strict == 0 check is fine.
    if status == 0 {
        Ok(())
    } else {
        Err(Error::Lsa {
            api,
            status: status as u32,
        })
    }
}

fn unicode_string_to_string(us: &UNICODE_STRING) -> String {
    if us.Buffer.is_null() || us.Length == 0 {
        return String::new();
    }
    let len_words = (us.Length as usize) / 2;
    // SAFETY: LSA-supplied UNICODE_STRING; Buffer is valid for Length bytes.
    let slice = unsafe { core::slice::from_raw_parts(us.Buffer, len_words) };
    String::from_utf16_lossy(slice)
}

// Compile-time sanity checks: struct sizes must be reasonable on target ptr
// width (real byte-for-byte checks against the Windows SDK live in tests/).
#[cfg(target_pointer_width = "64")]
const _: () = {
    // KerbSubmitTktRequest: u32(4) + LUID(8) + flags u32(4) + KerbCryptoKey32(12) + u32(4) + u32(4) = 36
    assert!(size_of::<KerbSubmitTktRequest>() == 36);
    // KerbQueryTktCacheRequest: u32 + LUID = 12
    assert!(size_of::<KerbQueryTktCacheRequest>() == 12);
};
