use std::net::{Ipv4Addr, Ipv6Addr};
use libc::{in6_addr, in_addr, sockaddr_in, sockaddr_in6};

use crate::Result;
use crate::interface::Netmask;

/// Creates a `Ipv4Addr` from a (Unix) `in_addr` taking in account
/// the CPU endianess to avoid having twisted IP addresses.
///
/// refer: https://github.com/rust-lang/rust/issues/48819
pub fn ipv4_from_in_addr(internet_address: &in_addr) -> Result<Ipv4Addr> {
    let mut ip_addr = Ipv4Addr::from(internet_address.s_addr);

    if cfg!(target_endian = "little") {
        // due to a difference on how bytes are arranged on a
        // single word of memory by the CPU, swap bytes based
        // on CPU endianess to avoid having twisted IP addresses
        ip_addr = Ipv4Addr::from(internet_address.s_addr.swap_bytes());
    }

    Ok(ip_addr)
}

/// Creates a `Ipv6Addr` from a (Unix) `in6_addr`
pub fn ipv6_from_in6_addr(internet_address: &in6_addr) -> Result<Ipv6Addr> {
    let ip_addr = Ipv6Addr::from(internet_address.s6_addr);

    Ok(ip_addr)
}

/// Retrieves the Netmask from a `ifaddrs` instance for a network interface
/// from the AF_INET (IPv4) family.
pub fn make_ipv4_netmask(netifa: &libc::ifaddrs) -> Netmask<Ipv4Addr> {
    let sockaddr = netifa.ifa_netmask;

    if sockaddr.is_null() {
        return None;
    }

    let socket_addr = sockaddr as *mut sockaddr_in;
    let internet_address = unsafe { (*socket_addr).sin_addr };

    ipv4_from_in_addr(&internet_address).ok()
}

/// Retrieves the Netmask from a `ifaddrs` instance for a network interface
/// from the AF_INET6 (IPv6) family.
pub fn make_ipv6_netmask(netifa: &libc::ifaddrs) -> Netmask<Ipv6Addr> {
    let sockaddr = netifa.ifa_netmask;

    if sockaddr.is_null() {
        return None;
    }

    let socket_addr = sockaddr as *mut sockaddr_in6;
    let internet_address = unsafe { (*socket_addr).sin6_addr };

    //  Ignore local addresses
    if internet_address.s6_addr[0] == 0xfe && internet_address.s6_addr[1] == 0x80 {
        return None;
    }

    ipv6_from_in6_addr(&internet_address).ok()
}
