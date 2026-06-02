// Copyright (c) 2024-2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::ipc::eve_types::{DhcpType, NetworkPortStatus, NetworkProxyType, WirelessType};
use ipnet::IpNet;
use macaddr::MacAddr;

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
    pub fn to_string(&self) -> String {
        match self {
            NetworkType::Ethernet => "Ethernet".to_string(),
            NetworkType::WiFi(_) => "WiFi".to_string(),
            NetworkType::Cellular(_) => "Cellular".to_string(),
        }
    }
}

pub enum IpConfig {
    Static {
        ip: Vec<IpAddr>,
        gw: IpAddr,
        ntp_servers: Option<Vec<IpAddr>>,
        routes: Option<Vec<IpAddr>>,
    },
    Dhcp,
}

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

impl ProxyConfig {
    fn is_manual(&self) -> bool {
        if let ProxyConfig::Manual {
            http,
            https,
            ftp,
            socks,
        } = self
        {
            http.is_some() || https.is_some() || ftp.is_some() || socks.is_some()
        } else {
            false
        }
    }
}

impl From<&crate::ipc::eve_types::ProxyConfig> for ProxyConfig {
    fn from(port_proxy_config: &crate::ipc::eve_types::ProxyConfig) -> Self {
        let iface_proxy_config = if port_proxy_config.network_proxy_enable {
            ProxyConfig::Wad {
                url: port_proxy_config.network_proxy_url.clone(),
            }
        } else if !port_proxy_config.pacfile.is_empty() {
            ProxyConfig::Pac {
                url: port_proxy_config.pacfile.clone(),
            }
        } else if let Some(proxies) = &port_proxy_config.proxies {
            let mut http_proxy = None;
            let mut https_proxy = None;
            let mut ftp_proxy = None;
            let mut socks_proxy = None;

            proxies.iter().for_each(|proxy| match proxy.proxy_type {
                NetworkProxyType::HTTP => {
                    http_proxy = Some(ProxyHost {
                        server: proxy.server.clone(),
                        port: proxy.port,
                    });
                }
                NetworkProxyType::SOCKS => {
                    socks_proxy = Some(ProxyHost {
                        server: proxy.server.clone(),
                        port: proxy.port,
                    });
                }
                NetworkProxyType::FTP => {
                    ftp_proxy = Some(ProxyHost {
                        server: proxy.server.clone(),
                        port: proxy.port,
                    });
                }
                NetworkProxyType::HTTPS => {
                    https_proxy = Some(ProxyHost {
                        server: proxy.server.clone(),
                        port: proxy.port,
                    });
                }
                NetworkProxyType::NOPROXY => {}
                NetworkProxyType::LAST => {}
            });

            let manual_proxies = ProxyConfig::Manual {
                http: http_proxy,
                https: https_proxy,
                ftp: ftp_proxy,
                socks: socks_proxy,
            };

            if manual_proxies.is_manual() {
                manual_proxies
            } else {
                ProxyConfig::None
            }
        } else {
            ProxyConfig::None
        };
        iface_proxy_config
    }
}

impl Default for PhyConfig {
    fn default() -> Self {
        PhyConfig::Ethernet { mtu: 1500 }
    }
}

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

pub trait IpV6LinikLocal {
    fn is_link_local(&self) -> bool;
}

impl IpV6LinikLocal for Ipv6Addr {
    fn is_link_local(&self) -> bool {
        self.segments()[0] == 0xfe80
    }
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

impl From<&NetworkPortStatus> for NetworkInterfaceStatus {
    fn from(port: &NetworkPortStatus) -> Self {
        // parse address list
        let ipv4 = port.addr_info_list.as_ref().map(|addr_info_list| {
            addr_info_list
                .iter()
                .filter(|addr_info| addr_info.addr.is_ipv4())
                .map(|addr_info| addr_info.addr.to_ipv4().unwrap())
                .collect()
        });

        let ipv6 = port.addr_info_list.as_ref().map(|addr_info_list| {
            addr_info_list
                .iter()
                .filter(|addr_info| addr_info.addr.is_ipv6())
                .map(|addr_info| addr_info.addr.to_ipv6().unwrap())
                // interfaces in EVE always have link local address which are not useful for the en user
                .filter(|addr| !addr.is_link_local())
                .collect()
        });

        // set media type
        let media = match port.wireless_cfg.w_type {
            WirelessType::None => NetworkType::Ethernet,
            WirelessType::Wifi => NetworkType::WiFi(WiFiStatus {
                //FIXME: why we have a Vec of WifiConfig?
                ssid: port
                    .wireless_cfg
                    .wifi
                    .as_ref()
                    .and_then(|w| Some(w[0].ssid.clone())),
            }),
            WirelessType::Cellular => NetworkType::Cellular(CellularStatus {
                // A modem can have 0 or multiple sims
                sims: port.wireless_cfg.cellular_v2.as_ref().and_then(|c| {
                    c.access_points.as_ref().and_then(|a| {
                        Some(
                            a.iter()
                                .map(|s| SimStatus {
                                    apn: s.apn.clone(),
                                    slot: u32::from(s.sim_slot),
                                })
                                .collect(),
                        )
                    })
                }),
            }),
        };

        let is_dhcp = port.dhcp == DhcpType::Client;

        // collect DNS servers
        let dns = port.dns_servers.as_ref().map(|dns_servers| {
            dns_servers
                .iter()
                .map(|dns_server| dns_server.clone())
                .collect()
        });

        // collect NTP servers. Some may come from DHCP as IpAddr, others are FQDN from
        // network configuration. Collect both types in the same list as strings

        let mut ntp_servers = vec![];
        // collect manually configured NTP servers
        if let Some(configured_ntp_servers) = &port.configured_ntp_servers {
            ntp_servers.extend(configured_ntp_servers.clone());
        }

        // append NTP servers provided by DHCP
        if is_dhcp {
            let dhcp_ntp_servers = port.dhcp_ntp_servers.as_ref().map(|ntp_servers| {
                ntp_servers
                    .iter()
                    .map(|ntp_server| ntp_server.clone().to_string())
                    .collect::<Vec<String>>()
            });
            if let Some(dhcp_ntp_servers) = dhcp_ntp_servers {
                ntp_servers.extend(dhcp_ntp_servers);
            }
        }

        let ntp_servers = if ntp_servers.is_empty() {
            None
        } else {
            Some(ntp_servers)
        };

        let last_error = &port.test_results.map_error();

        NetworkInterfaceStatus {
            name: port.if_name.clone(),
            ipv4,
            ipv6,
            is_mgmt: port.is_mgmt,
            routes: port.default_routers.clone(),
            mac: port.mac_addr,
            ntp_servers,
            up: port.up,
            media,
            dns,
            subnet: port.ipv4_subnet.clone(),
            is_dhcp,
            cost: port.cost,
            domain: if port.domain_name.is_empty() {
                None
            } else {
                Some(port.domain_name.clone())
            },
            proxy_config: (&port.proxy_config).into(),
            errors: last_error.clone(),
        }
    }
}

impl NetworkInterfaceStatus {
    pub fn is_connected(&self) -> bool {
        self.errors.is_none() && self.up
    }
}
