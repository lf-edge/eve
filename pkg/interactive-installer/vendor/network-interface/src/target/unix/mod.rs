pub mod ffi;

use std::collections::HashMap;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::slice::from_raw_parts;

use libc::{AF_INET, AF_INET6, sockaddr_in, sockaddr_in6, strlen, AF_LINK, if_nametoindex};

use crate::target::ffi::lladdr;
use crate::target::getifaddrs;
use crate::{Error, NetworkInterface, NetworkInterfaceConfig, Result};
use crate::utils::{ipv4_from_in_addr, ipv6_from_in6_addr, make_ipv4_netmask, make_ipv6_netmask};

impl NetworkInterfaceConfig for NetworkInterface {
    fn show() -> Result<Vec<NetworkInterface>> {
        let mut network_interfaces: HashMap<String, NetworkInterface> = HashMap::new();

        for netifa in getifaddrs()? {
            let netifa_addr = netifa.ifa_addr;
            let netifa_family = if netifa_addr.is_null() {
                continue;
            } else {
                unsafe { (*netifa_addr).sa_family as i32 }
            };

            let mut network_interface = match netifa_family {
                AF_LINK => {
                    let name = make_netifa_name(&netifa)?;
                    let mac = make_mac_addrs(&netifa);
                    let index = netifa_index(&netifa);
                    NetworkInterface {
                        name,
                        mac_addr: Some(mac),
                        addr: Vec::new(),
                        index,
                    }
                }
                AF_INET => {
                    let socket_addr = netifa_addr as *mut sockaddr_in;
                    let internet_address = unsafe { (*socket_addr).sin_addr };
                    let name = make_netifa_name(&netifa)?;
                    let index = netifa_index(&netifa);
                    let netmask = make_ipv4_netmask(&netifa);
                    let addr = ipv4_from_in_addr(&internet_address)?;
                    let broadcast = make_ipv4_broadcast_addr(&netifa)?;
                    NetworkInterface::new_afinet(name.as_str(), addr, netmask, broadcast, index)
                }
                AF_INET6 => {
                    let socket_addr = netifa_addr as *mut sockaddr_in6;
                    let internet_address = unsafe { (*socket_addr).sin6_addr };
                    let name = make_netifa_name(&netifa)?;
                    let index = netifa_index(&netifa);
                    let netmask = make_ipv6_netmask(&netifa);
                    let addr = ipv6_from_in6_addr(&internet_address)?;
                    let broadcast = make_ipv6_broadcast_addr(&netifa)?;
                    NetworkInterface::new_afinet6(name.as_str(), addr, netmask, broadcast, index)
                }
                _ => continue,
            };

            network_interfaces
                .entry(network_interface.name.clone())
                .and_modify(|old| old.addr.append(&mut network_interface.addr))
                .or_insert(network_interface);
        }

        Ok(network_interfaces.into_values().collect())
    }
}

/// Retrieves the network interface name
fn make_netifa_name(netifa: &libc::ifaddrs) -> Result<String> {
    let data = netifa.ifa_name as *mut u8;
    let len = unsafe { strlen(data as *const _) };
    let bytes_slice = unsafe { from_raw_parts(data, len) };
    let string = String::from_utf8(bytes_slice.to_vec()).map_err(Error::from)?;

    Ok(string)
}

/// Retrieves the broadcast address for the network interface provided of the
/// AF_INET family.
///
/// ## References
///
/// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
fn make_ipv4_broadcast_addr(netifa: &libc::ifaddrs) -> Result<Option<Ipv4Addr>> {
    let ifa_dstaddr = netifa.ifa_dstaddr;

    if ifa_dstaddr.is_null() {
        return Ok(None);
    }

    let socket_addr = ifa_dstaddr as *mut sockaddr_in;
    let internet_address = unsafe { (*socket_addr).sin_addr };
    let addr = ipv4_from_in_addr(&internet_address)?;

    Ok(Some(addr))
}

/// Retrieves the broadcast address for the network interface provided of the
/// AF_INET6 family.
///
/// ## References
///
/// https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man3/getifaddrs.3.html
fn make_ipv6_broadcast_addr(netifa: &libc::ifaddrs) -> Result<Option<Ipv6Addr>> {
    let ifa_dstaddr = netifa.ifa_dstaddr;

    if ifa_dstaddr.is_null() {
        return Ok(None);
    }

    let socket_addr = ifa_dstaddr as *mut sockaddr_in6;
    let internet_address = unsafe { (*socket_addr).sin6_addr };
    let addr = ipv6_from_in6_addr(&internet_address)?;

    Ok(Some(addr))
}

fn make_mac_addrs(netifa: &libc::ifaddrs) -> String {
    let mut mac = [0; 6];
    let mut ptr = unsafe { lladdr(netifa as *const libc::ifaddrs as *mut _) };

    for el in &mut mac {
        *el = unsafe { *ptr };
        ptr = ((ptr as usize) + 1) as *const u8;
    }

    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Retreives the name for the the network interface provided
///
/// ## References
///
/// https://man7.org/linux/man-pages/man3/if_nametoindex.3.html
fn netifa_index(netifa: &libc::ifaddrs) -> u32 {
    let name = netifa.ifa_name as *const libc::c_char;

    unsafe { if_nametoindex(name) }
}
