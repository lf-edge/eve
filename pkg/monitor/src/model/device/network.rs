// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ipc::monitorapi;
use ipnet::IpNet;
use macaddr::MacAddr;

#[allow(dead_code)] // intended API, not yet consumed by the UI
pub struct NetworkStatus {
    pub interfaces: Vec<NetworkInterfaceStatus>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct SimStatus {
    pub apn: String,
    pub slot: u32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CellularStatus {
    sims: Option<Vec<SimStatus>>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct WiFiStatus {
    pub ssid: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum NetworkType {
    Ethernet,
    WiFi(WiFiStatus),
    Cellular(CellularStatus),
}

impl NetworkType {
    #[allow(clippy::inherent_to_string)]
    pub fn to_string(&self) -> String {
        match self {
            NetworkType::Ethernet => "Ethernet".to_string(),
            NetworkType::WiFi(_) => "WiFi".to_string(),
            NetworkType::Cellular(_) => "Cellular".to_string(),
        }
    }
}

#[allow(dead_code)] // intended API, not yet consumed by the UI
pub enum IpConfig {
    Static {
        ip: Vec<IpAddr>,
        gw: IpAddr,
        ntp_servers: Option<Vec<IpAddr>>,
        routes: Option<Vec<IpAddr>>,
    },
    Dhcp,
}

#[allow(dead_code)] // intended API, not yet consumed by the UI
pub enum PhyConfig {
    Ethernet { mtu: u32 },
    WiFi { ssid: String, password: String },
    Cellular { apn: String, slot: u32 },
}

#[derive(Debug, Clone, PartialEq)]
pub struct ProxyHost {
    server: String,
    port: u32,
}

impl ProxyHost {
    pub fn to_url(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ProxyConfig {
    None,
    Pac {
        url: String,
    },
    Manual {
        http: Option<ProxyHost>,
        https: Option<ProxyHost>,
        ftp: Option<ProxyHost>,
        socks: Option<ProxyHost>,
    },
    Wad {
        url: String,
    },
}

impl Default for PhyConfig {
    fn default() -> Self {
        PhyConfig::Ethernet { mtu: 1500 }
    }
}

#[allow(dead_code)] // intended API, not yet consumed by the UI
pub struct InterfaceConfig {
    pub name: String,
    pub ip_config: IpConfig,
    pub phy_config: PhyConfig,
    pub proxy_config: ProxyConfig,
    pub proxy_certificate: Option<String>,
}

//TODO: convert to enum and create a separate struct for common fields
#[derive(Debug, Clone, PartialEq)]
pub struct NetworkInterfaceStatus {
    pub name: String,
    pub is_mgmt: bool,
    pub ipv4: Option<Vec<Ipv4Addr>>,
    pub ipv6: Option<Vec<Ipv6Addr>>,
    pub routes: Option<Vec<IpAddr>>,
    pub mac: Option<MacAddr>,
    pub ntp_servers: Option<Vec<String>>,
    pub up: bool,
    pub media: NetworkType,
    pub dns: Option<Vec<IpAddr>>,
    pub subnet: Option<IpNet>,
    pub is_dhcp: bool,
    pub proxy_config: ProxyConfig,
    pub domain: Option<String>,
    pub cost: u8,
    pub errors: Option<Vec<String>>,
}

pub trait ToInnerIpAddr {
    fn to_ipv4(&self) -> Option<Ipv4Addr>;
    fn to_ipv6(&self) -> Option<Ipv6Addr>;
}

impl ToInnerIpAddr for IpAddr {
    fn to_ipv4(&self) -> Option<Ipv4Addr> {
        match self {
            IpAddr::V4(ipv4) => Some(*ipv4),
            _ => None,
        }
    }

    fn to_ipv6(&self) -> Option<Ipv6Addr> {
        match self {
            IpAddr::V6(ipv6) => Some(*ipv6),
            _ => None,
        }
    }
}

impl NetworkInterfaceStatus {
    pub fn is_connected(&self) -> bool {
        self.errors.is_none() && self.up
    }
}

// ---------------------------------------------------------------------------
// Conversion from the monitorapi contract.
//
// The heavy parsing (address-family split, link-local filtering, proxy-mode
// detection, wireless decoding) now happens in the Go mapper, so these are
// largely straight field copies. The contract nests VLANs under their parent;
// the current UI consumes a flat list, so interfaces_from flattens them (VLANs
// become additional entries, as they appeared before). Surfacing the nesting
// and richer cellular detail is a later display change.
// ---------------------------------------------------------------------------

/// interfaces_from flattens the nested contract into the flat list the UI uses.
pub fn interfaces_from(status: &monitorapi::NetworkStatus) -> Vec<NetworkInterfaceStatus> {
    let mut out = Vec::new();
    for iface in &status.interfaces {
        out.push(iface_from_network(
            iface.name.clone(),
            iface.is_mgmt,
            iface.up,
            iface.cost,
            iface.mac.parse::<MacAddr>().ok(),
            media_from(&iface.media),
            &iface.network,
        ));
        for vlan in &iface.vlans {
            out.push(iface_from_network(
                vlan.name.clone(),
                vlan.is_mgmt,
                vlan.up,
                0,
                None,
                NetworkType::Ethernet,
                &vlan.network,
            ));
        }
    }
    out
}

fn iface_from_network(
    name: String,
    is_mgmt: bool,
    up: bool,
    cost: u8,
    mac: Option<MacAddr>,
    media: NetworkType,
    net: &monitorapi::PortNetwork,
) -> NetworkInterfaceStatus {
    NetworkInterfaceStatus {
        name,
        is_mgmt,
        ipv4: opt_vec(net.ipv4.iter().filter_map(|a| a.to_ipv4()).collect()),
        ipv6: opt_vec(net.ipv6.iter().filter_map(|a| a.to_ipv6()).collect()),
        routes: opt_vec(net.routes.clone()),
        mac,
        ntp_servers: opt_vec(net.ntp_servers.clone()),
        up,
        media,
        dns: opt_vec(net.dns_servers.clone()),
        subnet: net.subnet,
        is_dhcp: net.is_dhcp,
        proxy_config: proxy_from(&net.proxy),
        domain: opt_str(&net.domain),
        cost,
        errors: opt_vec(net.errors.clone()),
    }
}

fn media_from(m: &monitorapi::NetworkMedia) -> NetworkType {
    match m {
        monitorapi::NetworkMedia::Ethernet => NetworkType::Ethernet,
        monitorapi::NetworkMedia::Wifi { ssid } => NetworkType::WiFi(WiFiStatus {
            ssid: opt_str(ssid),
        }),
        monitorapi::NetworkMedia::Cellular { sims, .. } => NetworkType::Cellular(CellularStatus {
            sims: opt_vec(
                sims.iter()
                    .map(|s| SimStatus {
                        apn: s.apn.clone(),
                        slot: s.slot,
                    })
                    .collect(),
            ),
        }),
    }
}

fn proxy_from(p: &monitorapi::ProxySettings) -> ProxyConfig {
    match p {
        monitorapi::ProxySettings::None => ProxyConfig::None,
        monitorapi::ProxySettings::Pac { pac_file } => ProxyConfig::Pac {
            url: pac_file.clone(),
        },
        monitorapi::ProxySettings::Wpad { url } => ProxyConfig::Wad {
            url: url.clone().unwrap_or_default(),
        },
        monitorapi::ProxySettings::Manual { servers, .. } => {
            let (mut http, mut https, mut ftp, mut socks) = (None, None, None, None);
            for s in servers {
                let host = ProxyHost {
                    server: s.host.clone(),
                    port: u32::from(s.port),
                };
                match s.scheme {
                    monitorapi::ProxyScheme::Http => http = Some(host),
                    monitorapi::ProxyScheme::Https => https = Some(host),
                    monitorapi::ProxyScheme::Ftp => ftp = Some(host),
                    monitorapi::ProxyScheme::Socks => socks = Some(host),
                }
            }
            ProxyConfig::Manual {
                http,
                https,
                ftp,
                socks,
            }
        }
    }
}

fn opt_vec<T>(v: Vec<T>) -> Option<Vec<T>> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}

fn opt_str(s: &str) -> Option<String> {
    if s.is_empty() {
        None
    } else {
        Some(s.to_string())
    }
}
