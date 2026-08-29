//! Read-only inventory of the current logon session's Kerberos ticket cache.
//!
//! Usage:
//!   cargo run --example kerberos_cache
//!
//! This uses LsaConnectUntrusted and does not retrieve, submit, or purge
//! ticket material. Local-account sessions may have an empty cache.

fn main() -> windows_lsa::Result<()> {
    let tickets = windows_lsa::query_ticket_cache(None)?;
    println!("cached_tickets={}", tickets.len());

    for ticket in tickets {
        println!(
            "server={} realm={} start_ft={} end_ft={} renew_ft={} etype={} flags=0x{:08x}",
            ticket.server_name,
            ticket.realm_name,
            ticket.start_time_ft,
            ticket.end_time_ft,
            ticket.renew_time_ft,
            ticket.encryption_type,
            ticket.ticket_flags,
        );
    }

    Ok(())
}
