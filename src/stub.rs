//! Non-Windows no-op back-end. Every entry point returns
//! [`Error::Unsupported`] so callers can `cfg`-gate at their own convenience
//! without breaking the shared type signature.

use crate::{AuthPackageId, Error, KrbCred, Luid, Result, TicketCacheInfo};

#[derive(Debug)]
pub struct Lsa;

#[derive(Debug)]
pub struct LsaHandle {
    _private: (),
}

impl Lsa {
    pub fn connect_untrusted() -> Result<LsaHandle> {
        Err(Error::Unsupported)
    }
}

impl LsaHandle {
    pub fn kerberos_package(&self) -> Result<AuthPackageId> {
        Err(Error::Unsupported)
    }

    pub fn retrieve_tgt(&self, _pkg: AuthPackageId, _luid: Option<Luid>) -> Result<KrbCred> {
        Err(Error::Unsupported)
    }

    pub fn query_ticket_cache(
        &self,
        _pkg: AuthPackageId,
        _luid: Option<Luid>,
    ) -> Result<Vec<TicketCacheInfo>> {
        Err(Error::Unsupported)
    }

    pub fn submit_ticket(
        &self,
        _pkg: AuthPackageId,
        _cred: &KrbCred,
        _luid: Option<Luid>,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }

    pub fn purge_ticket_cache(
        &self,
        _pkg: AuthPackageId,
        _luid: Option<Luid>,
        _target_spn: Option<&str>,
    ) -> Result<()> {
        Err(Error::Unsupported)
    }
}
