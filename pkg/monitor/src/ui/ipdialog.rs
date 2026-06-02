// Copyright (c) 2024-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, net::AddrParseError, net::Ipv4Addr, rc::Rc};
use url::Url;

use crossterm::event::{KeyCode, KeyEvent};
use log::debug;
use ratatui::{
    layout::{Constraint, Flex, Layout, Margin, Rect},
    style::{Color, Style},
    widgets::{Block, BorderType, Borders, Clear},
    Frame,
};
use std::net::Ipv6Addr;
use std::num::ParseIntError;
use std::str::FromStr;
use thiserror::Error;

use crate::{
    actions::MonActions,
    model::{
        device::network::{NetworkInterfaceStatus, ProxyConfig},
        model::Model,
    },
    traits::IWindow,
};

use super::{
    action::{Action, UiActions},
    tools::centered_rect,
    widgets::{
        button::ButtonElement, input_field::InputFieldElement, spin_box::SpinBoxElement,
        tab::TabElement,
    },
    window::Window,
};

#[derive(Error, Debug)]
pub enum CidrError {
    #[error("input string is empty")]
    EmptyInput,

    #[error("invalid IP address: {0}")]
    InvalidAddress(#[from] AddrParseError),

    #[error("invalid prefix length: {0}")]
    InvalidMask(#[from] ParseIntError),

    #[error("prefix length {given} is out of range (0–{max})")]
    MaskOutOfRange { given: u8, max: u8 },
}

#[derive(Clone, Debug, PartialEq)]
pub enum ProxyType {
    None,
    Manual,
    // Pac,
    // Wad,
}

#[derive(Clone, Debug, PartialEq)]
pub struct InterfaceState {
    pub iface_name: String,
    pub ip_dhcp: bool,
    pub proxy_type: ProxyType,
    pub ipv4: String,
    pub ipv6: String,
    pub mask: String,
    pub gw: String,
    pub proxy_url: String,
    pub proxy_certificate: String,
    pub pac_file: String,
    pub domain: String,
    pub dns: String,
    pub ntp: String,
    // manual proxies
    pub proxy_http: Option<Url>,
    pub proxy_https: Option<Url>,
    pub proxy_ftp: Option<Url>,
    pub proxy_socks: Option<Url>,
}

impl InterfaceState {
    pub fn is_dhcp(&self) -> bool {
        self.ip_dhcp
    }

    /// Create a ProxyConfig from the current InterfaceState
    pub fn create_proxy_config(&self) -> crate::ipc::eve_types::ProxyConfig {
        use crate::ipc::eve_types::{NetworkProxyType, ProxyConfig, ProxyEntry};
        use crate::ui::ipdialog::ProxyType;

        match self.proxy_type {
            ProxyType::None => ProxyConfig {
                proxies: None,
                pacfile: String::new(),
                network_proxy_enable: false,
                network_proxy_url: String::new(),
                wpad_url: String::new(),
                exceptions: String::new(),
                proxy_cert_pem: None,
            },
            ProxyType::Manual => {
                let mut proxies = Vec::new();

                // Helper function to extract host and port from validated URL
                let url_to_proxy_entry =
                    |url: &url::Url, proxy_type: NetworkProxyType| -> Option<ProxyEntry> {
                        if let Some(host) = url.host_str() {
                            let default_port = match proxy_type {
                                NetworkProxyType::HTTP => 8080,
                                NetworkProxyType::HTTPS => 8080,
                                NetworkProxyType::FTP => 21,
                                NetworkProxyType::SOCKS => 1080,
                                _ => 8080,
                            };
                            let port = url.port().unwrap_or(default_port) as u32;
                            Some(ProxyEntry {
                                proxy_type,
                                server: host.to_string(),
                                port,
                            })
                        } else {
                            None
                        }
                    };

                // Add HTTP proxy if specified
                if let Some(ref url) = self.proxy_http {
                    if let Some(entry) = url_to_proxy_entry(url, NetworkProxyType::HTTP) {
                        proxies.push(entry);
                    }
                }

                // Add HTTPS proxy if specified
                if let Some(ref url) = self.proxy_https {
                    if let Some(entry) = url_to_proxy_entry(url, NetworkProxyType::HTTPS) {
                        proxies.push(entry);
                    }
                }

                // Add FTP proxy if specified
                if let Some(ref url) = self.proxy_ftp {
                    if let Some(entry) = url_to_proxy_entry(url, NetworkProxyType::FTP) {
                        proxies.push(entry);
                    }
                }

                // Add SOCKS proxy if specified
                if let Some(ref url) = self.proxy_socks {
                    if let Some(entry) = url_to_proxy_entry(url, NetworkProxyType::SOCKS) {
                        proxies.push(entry);
                    }
                }

                // network_proxy_enable is only true when network_proxy_url is actually used
                let has_network_proxy_url = !self.proxy_url.is_empty();

                ProxyConfig {
                    proxies: if !proxies.is_empty() {
                        Some(proxies)
                    } else {
                        None
                    },
                    network_proxy_enable: has_network_proxy_url,
                    pacfile: self.pac_file.clone(),
                    network_proxy_url: self.proxy_url.clone(),
                    proxy_cert_pem: if !self.proxy_certificate.is_empty() {
                        Some(vec![self.proxy_certificate.clone().into_bytes()])
                    } else {
                        None
                    },
                    wpad_url: String::new(),
                    exceptions: String::new(),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::eve_types::NetworkProxyType;
    use url::Url;

    #[test]
    fn test_create_proxy_config_none() {
        let interface_state = InterfaceState {
            iface_name: "eth0".to_string(),
            ip_dhcp: true,
            proxy_type: ProxyType::None,
            ipv4: "192.168.1.100".to_string(),
            ipv6: "".to_string(),
            mask: "255.255.255.0".to_string(),
            gw: "192.168.1.1".to_string(),
            proxy_url: "".to_string(),
            proxy_certificate: "".to_string(),
            pac_file: "".to_string(),
            domain: "example.com".to_string(),
            dns: "8.8.8.8".to_string(),
            ntp: "pool.ntp.org".to_string(),
            proxy_http: None,
            proxy_https: None,
            proxy_ftp: None,
            proxy_socks: None,
        };

        let proxy_config = interface_state.create_proxy_config();

        assert_eq!(proxy_config.proxies, None);
        assert!(!proxy_config.network_proxy_enable);
        assert_eq!(proxy_config.pacfile, "");
        assert_eq!(proxy_config.network_proxy_url, "");
        assert_eq!(proxy_config.proxy_cert_pem, None);
    }

    #[test]
    fn test_create_proxy_config_manual() {
        let interface_state = InterfaceState {
            iface_name: "eth0".to_string(),
            ip_dhcp: true,
            proxy_type: ProxyType::Manual,
            ipv4: "192.168.1.100".to_string(),
            ipv6: "".to_string(),
            mask: "255.255.255.0".to_string(),
            gw: "192.168.1.1".to_string(),
            proxy_url: "http://proxy.example.com:8080".to_string(),
            proxy_certificate: "test-cert".to_string(),
            pac_file: "http://proxy.example.com/proxy.pac".to_string(),
            domain: "example.com".to_string(),
            dns: "8.8.8.8".to_string(),
            ntp: "pool.ntp.org".to_string(),
            proxy_http: Some(Url::parse("http://proxy.example.com:8080").unwrap()),
            proxy_https: Some(Url::parse("https://proxy.example.com:8443").unwrap()),
            proxy_ftp: Some(Url::parse("ftp://proxy.example.com:21").unwrap()),
            proxy_socks: Some(Url::parse("socks://proxy.example.com:1080").unwrap()),
        };

        let proxy_config = interface_state.create_proxy_config();

        assert!(proxy_config.network_proxy_enable);
        assert_eq!(proxy_config.pacfile, "http://proxy.example.com/proxy.pac");
        assert_eq!(
            proxy_config.network_proxy_url,
            "http://proxy.example.com:8080"
        );
        assert!(proxy_config.proxy_cert_pem.is_some());
        assert_eq!(
            proxy_config.proxy_cert_pem.unwrap()[0],
            "test-cert".as_bytes()
        );

        let proxies = proxy_config.proxies.unwrap();
        assert_eq!(proxies.len(), 4);

        // Check HTTP proxy
        let http_proxy = proxies
            .iter()
            .find(|p| p.proxy_type == NetworkProxyType::HTTP)
            .unwrap();
        assert_eq!(http_proxy.server, "proxy.example.com");
        assert_eq!(http_proxy.port, 8080);

        // Check HTTPS proxy
        let https_proxy = proxies
            .iter()
            .find(|p| p.proxy_type == NetworkProxyType::HTTPS)
            .unwrap();
        assert_eq!(https_proxy.server, "proxy.example.com");
        assert_eq!(https_proxy.port, 8443);

        // Check FTP proxy
        let ftp_proxy = proxies
            .iter()
            .find(|p| p.proxy_type == NetworkProxyType::FTP)
            .unwrap();
        assert_eq!(ftp_proxy.server, "proxy.example.com");
        assert_eq!(ftp_proxy.port, 21);

        // Check SOCKS proxy
        let socks_proxy = proxies
            .iter()
            .find(|p| p.proxy_type == NetworkProxyType::SOCKS)
            .unwrap();
        assert_eq!(socks_proxy.server, "proxy.example.com");
        assert_eq!(socks_proxy.port, 1080);
    }

    #[test]
    fn test_create_proxy_config_manual_with_default_ports() {
        let interface_state = InterfaceState {
            iface_name: "eth0".to_string(),
            ip_dhcp: true,
            proxy_type: ProxyType::Manual,
            ipv4: "192.168.1.100".to_string(),
            ipv6: "".to_string(),
            mask: "255.255.255.0".to_string(),
            gw: "192.168.1.1".to_string(),
            proxy_url: "".to_string(),
            proxy_certificate: "".to_string(),
            pac_file: "".to_string(),
            domain: "example.com".to_string(),
            dns: "8.8.8.8".to_string(),
            ntp: "pool.ntp.org".to_string(),
            proxy_http: Some(Url::parse("http://proxy.example.com").unwrap()),
            proxy_https: None,
            proxy_ftp: None,
            proxy_socks: None,
        };

        let proxy_config = interface_state.create_proxy_config();

        assert!(!proxy_config.network_proxy_enable);
        let proxies = proxy_config.proxies.unwrap();
        assert_eq!(proxies.len(), 1);

        // Check HTTP proxy with default port
        let http_proxy = &proxies[0];
        assert_eq!(http_proxy.proxy_type, NetworkProxyType::HTTP);
        assert_eq!(http_proxy.server, "proxy.example.com");
        assert_eq!(http_proxy.port, 8080); // Default HTTP proxy port
    }

    #[test]
    fn test_create_proxy_config_manual_empty() {
        let interface_state = InterfaceState {
            iface_name: "eth0".to_string(),
            ip_dhcp: true,
            proxy_type: ProxyType::Manual,
            ipv4: "192.168.1.100".to_string(),
            ipv6: "".to_string(),
            mask: "255.255.255.0".to_string(),
            gw: "192.168.1.1".to_string(),
            proxy_url: "".to_string(),
            proxy_certificate: "".to_string(),
            pac_file: "".to_string(),
            domain: "example.com".to_string(),
            dns: "8.8.8.8".to_string(),
            ntp: "pool.ntp.org".to_string(),
            proxy_http: None,
            proxy_https: None,
            proxy_ftp: None,
            proxy_socks: None,
        };

        let proxy_config = interface_state.create_proxy_config();

        assert_eq!(proxy_config.proxies, None);
        assert!(!proxy_config.network_proxy_enable);
    }

    #[test]
    fn test_integration_create_and_set_proxy_config() {
        let interface_state = InterfaceState {
            iface_name: "eth0".to_string(),
            ip_dhcp: true,
            proxy_type: ProxyType::Manual,
            ipv4: "192.168.1.100".to_string(),
            ipv6: "".to_string(),
            mask: "255.255.255.0".to_string(),
            gw: "192.168.1.1".to_string(),
            proxy_url: "http://proxy.example.com:8080".to_string(),
            proxy_certificate: "test-cert".to_string(),
            pac_file: "".to_string(),
            domain: "example.com".to_string(),
            dns: "8.8.8.8".to_string(),
            ntp: "pool.ntp.org".to_string(),
            proxy_http: Some(Url::parse("http://proxy.example.com:3128").unwrap()),
            proxy_https: None,
            proxy_ftp: None,
            proxy_socks: None,
        };

        // Test that create_proxy_config works and returns the expected config
        let proxy_config = interface_state.create_proxy_config();

        // Verify the created proxy config has the expected values
        assert!(proxy_config.network_proxy_enable);
        assert_eq!(
            proxy_config.network_proxy_url,
            "http://proxy.example.com:8080"
        );
        assert!(proxy_config.proxy_cert_pem.is_some());
        assert_eq!(
            proxy_config.proxy_cert_pem.unwrap()[0],
            "test-cert".as_bytes()
        );

        let proxies = proxy_config.proxies.unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].proxy_type, NetworkProxyType::HTTP);
        assert_eq!(proxies[0].server, "proxy.example.com");
        assert_eq!(proxies[0].port, 3128);

        // Test that we can create a second proxy config and it's independent
        let proxy_config2 = interface_state.create_proxy_config();
        assert_eq!(
            proxy_config2.network_proxy_url,
            proxy_config.network_proxy_url
        );
    }

    #[test]
    fn test_create_proxy_config_with_network_proxy_url() {
        let interface_state = InterfaceState {
            iface_name: "eth0".to_string(),
            ip_dhcp: true,
            proxy_type: ProxyType::Manual,
            ipv4: "192.168.1.100".to_string(),
            ipv6: "".to_string(),
            mask: "255.255.255.0".to_string(),
            gw: "192.168.1.1".to_string(),
            proxy_url: "http://network-proxy.example.com:8080".to_string(),
            proxy_certificate: "".to_string(),
            pac_file: "".to_string(),
            domain: "example.com".to_string(),
            dns: "8.8.8.8".to_string(),
            ntp: "pool.ntp.org".to_string(),
            proxy_http: Some(Url::parse("http://proxy.example.com:3128").unwrap()),
            proxy_https: None,
            proxy_ftp: None,
            proxy_socks: None,
        };

        let proxy_config = interface_state.create_proxy_config();

        // network_proxy_enable should be true because proxy_url is not empty
        assert!(proxy_config.network_proxy_enable);
        assert_eq!(
            proxy_config.network_proxy_url,
            "http://network-proxy.example.com:8080"
        );

        // Should also have proxy entries
        let proxies = proxy_config.proxies.unwrap();
        assert_eq!(proxies.len(), 1);
        assert_eq!(proxies[0].proxy_type, NetworkProxyType::HTTP);
        assert_eq!(proxies[0].server, "proxy.example.com");
        assert_eq!(proxies[0].port, 3128);
    }
}

/// Parse and validate proxy URL, adding default schema if missing
fn parse_proxy_url(input: &str, default_scheme: &str) -> Option<Url> {
    if input.trim().is_empty() {
        return None;
    }

    let input = input.trim();

    // Try parsing as-is first
    if let Ok(url) = Url::parse(input) {
        return Some(url);
    }

    // If parsing failed, try adding the default scheme
    let with_scheme = format!("{}://{}", default_scheme, input);
    Url::parse(&with_scheme).ok()
}

// here we deal with Strings because we update them from InputFiled
#[derive(Clone, Debug, PartialEq)]
pub struct IpDialogState {
    selected_tab: String,
    focus_tarcker_state: HashMap<String, usize>,
    pub new_iface_state: InterfaceState,
    pub old_iface_state: InterfaceState,
}

impl IpDialogState {
    pub fn get_focused_view(&self) -> Option<usize> {
        self.focus_tarcker_state.get(&self.selected_tab).copied()
    }
    pub fn get_current_tab_order(&self) -> Vec<&str> {
        let mut order = match self.selected_tab.as_str() {
            "IP" => {
                if self.new_iface_state.ip_dhcp {
                    vec!["ip_spinner"]
                } else {
                    vec![
                        "ip_spinner",
                        "ipv4",
                        "mask",
                        "gw",
                        "ipv6",
                        "domain",
                        "dns",
                        "ntp",
                    ]
                }
            }
            "Proxy" => match self.new_iface_state.proxy_type {
                ProxyType::None => vec!["proxy_spinner"],
                ProxyType::Manual => {
                    vec![
                        "proxy_spinner",
                        "http",
                        "https",
                        "ftp",
                        "socks",
                        // this is not supported yet but let's keep it here for future use
                        // "certificate",
                        // "upload",
                    ]
                } // this is not supported yet but let's keep it here for future use
                  // ProxyType::Wad => vec!["proxy_spinner"],
                  // ProxyType::Pac => vec!["proxy_spinner", "pac_file", "upload"],
            },
            _ => vec![],
        };
        order.push("ok");
        order.push("cancel");
        order
    }
}

fn on_init(w: &mut Window<IpDialogState>) {
    create_widgets(w);
    init_focus_tracker(w);
}

fn init_focus_tracker(w: &mut Window<IpDialogState>) {
    w.state.focus_tarcker_state.insert("IP".to_string(), 0);
    w.state.focus_tarcker_state.insert("Proxy".to_string(), 0);
    let current_tab_order = w
        .state
        .get_current_tab_order()
        .iter()
        .map(|s| s.to_string())
        .collect();
    w.set_focus_tracker_tab_order(current_tab_order);
    if let Some(focused_view) = w.state.get_focused_view() {
        w.set_focused_view(focused_view);
    }
}

/// Parse an IPv4 CIDR string, returning `(Ipv4Addr, prefix)`
/// defaulting to /32 when no mask is given.
pub fn validate_ipv4_cidr(input: &str) -> Result<(Ipv4Addr, u8), CidrError> {
    const MAX: u8 = 32;
    if input.is_empty() {
        return Err(CidrError::EmptyInput);
    }
    let (addr_part, mask_part) = input
        .split_once('/')
        .map_or((input, None), |(a, m)| (a, Some(m)));

    let addr = Ipv4Addr::from_str(addr_part)?;
    let prefix = if let Some(m_str) = mask_part {
        let m: u8 = m_str.parse()?;
        if m > MAX {
            return Err(CidrError::MaskOutOfRange { given: m, max: MAX });
        }
        m
    } else {
        MAX
    };

    Ok((addr, prefix))
}

/// Parse and validate an IPv6 CIDR string in `input`.
/// Returns the parsed `Ipv6Addr` and the prefix length.
///
/// # Examples
///
/// ```
/// use your_crate::validate_ipv6_cidr;
/// use std::net::Ipv6Addr;
///
/// assert_eq!(
///     validate_ipv6_cidr("2001:db8::dead:beef/64").unwrap(),
///     (Ipv6Addr::from_str("2001:db8::dead:beef").unwrap(), 64)
/// );
/// assert_eq!(
///     validate_ipv6_cidr("::1").unwrap(),
///     (Ipv6Addr::LOCALHOST, 128)
/// );
/// ```
pub fn validate_ipv6_cidr(input: &str) -> Result<(Ipv6Addr, u8), CidrError> {
    const MAX: u8 = 128;
    if input.is_empty() {
        return Err(CidrError::EmptyInput);
    }
    let (addr_part, mask_part) = input
        .split_once('/')
        .map_or((input, None), |(a, m)| (a, Some(m)));

    let addr = Ipv6Addr::from_str(addr_part)?;
    let prefix = if let Some(m_str) = mask_part {
        let m: u8 = m_str.parse()?;
        if m > MAX {
            return Err(CidrError::MaskOutOfRange { given: m, max: MAX });
        }
        m
    } else {
        MAX
    };

    Ok((addr, prefix))
}

fn create_widgets(w: &mut Window<IpDialogState>) {
    // create all widgets only once. We draw only widgets that present in the layout
    w.add_widget(
        "tabs",
        TabElement::new(
            vec!["IP", "Proxy"],
            "IP",
            Some(" Use ctrl + ◄ ► to change tab"),
        ),
    );

    // buttons
    w.add_widget("ok", ButtonElement::new("ok"));
    w.add_widget("cancel", ButtonElement::new("cancel"));

    let index = if w.state.new_iface_state.ip_dhcp {
        0
    } else {
        1
    };
    w.add_widget(
        "ip_spinner",
        SpinBoxElement::new(vec!["DHCP", "Static"]).selected(index),
    );

    w.add_widget(
        "ipv4",
        InputFieldElement::new("IPv4", Some(w.state.new_iface_state.ipv4.as_str()))
            .with_text_hint("e.g. 192.168.0.1")
            .validate(|ip| match validate_ipv4_cidr(ip) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }),
    );

    w.add_widget(
        "ipv6",
        InputFieldElement::new("IPv6", Some(w.state.new_iface_state.ipv6.as_str()))
            .with_text_hint("e.g. c820::1")
            .validate(|ip| match validate_ipv6_cidr(ip) {
                Ok(_) => Ok(()),
                Err(e) => Err(e.to_string()),
            }),
    );

    w.add_widget(
        "mask",
        InputFieldElement::new("Mask", Some(w.state.new_iface_state.mask.as_str()))
            .with_text_hint("e.g. 255.255.255.0")
            .validate(|mask| {
                if mask.is_empty() {
                    return Err("Mask cannot be empty".to_string());
                }
                // try to parse as IPv4 CIDR
                match validate_ipv4_cidr(mask) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.to_string()),
                }
            }),
    );
    w.add_widget(
        "gw",
        InputFieldElement::new("Gateway", Some(w.state.new_iface_state.gw.as_str()))
            .with_text_hint("e.g. 192.168.1.1, fe80::2"),
    );
    w.add_widget(
        "dns",
        InputFieldElement::new("DNS", Some(w.state.new_iface_state.dns.as_str()))
            .with_text_hint("e.g. 1.1.1.1, 4.4.4.4"),
    );
    w.add_widget(
        "domain",
        InputFieldElement::new("Domain", Some(w.state.new_iface_state.domain.as_str()))
            .with_text_hint("e.g. example.com"),
    );
    w.add_widget(
        "ntp",
        InputFieldElement::new("NTP", Some(w.state.new_iface_state.ntp.as_str()))
            .with_text_hint("e.g. 94.130.23.46, pool.ntp.org"),
    );

    // proxy widgets
    w.add_widget(
        "proxy_spinner",
        SpinBoxElement::new(vec!["None", "Manual" /*, "Pac"*/]),
    );
    w.add_widget(
        "http",
        InputFieldElement::new(
            "HTTP",
            Some(
                w.state
                    .new_iface_state
                    .proxy_http
                    .as_ref()
                    .map(|u| u.as_str())
                    .unwrap_or(""),
            ),
        )
        .with_text_hint("e.g. http://10.10.10.1:8080"),
    );
    w.add_widget(
        "https",
        InputFieldElement::new(
            "HTTPs",
            Some(
                w.state
                    .new_iface_state
                    .proxy_https
                    .as_ref()
                    .map(|u| u.as_str())
                    .unwrap_or(""),
            ),
        )
        .with_text_hint("e.g. https://10.10.10.1:8080"),
    );
    w.add_widget(
        "ftp",
        InputFieldElement::new(
            "FTP",
            Some(
                w.state
                    .new_iface_state
                    .proxy_ftp
                    .as_ref()
                    .map(|u| u.as_str())
                    .unwrap_or(""),
            ),
        ),
    );
    w.add_widget(
        "socks",
        InputFieldElement::new(
            "SOCKS",
            Some(
                w.state
                    .new_iface_state
                    .proxy_socks
                    .as_ref()
                    .map(|u| u.as_str())
                    .unwrap_or(""),
            ),
        ),
    );
    // w.add_widget(
    //     "pac_file",
    //     InputFieldElement::new("PAC file", Some(&w.state.new_iface_state.pac_file.as_str()))
    //         .enabled(false),
    // );
    // This is not supported yet but let's keep it here for future use
    // w.add_widget(
    //     "certificate",
    //     InputFieldElement::new(
    //         "Proxy Certificcate",
    //         Some(&w.state.new_iface_state.proxy_certificate.as_str()),
    //     )
    //     .enabled(false),
    // );
    // w.add_widget("upload", ButtonElement::new("Upload"));
}

fn update_ip_layout(w: &mut Window<IpDialogState>, rect: &Rect) {
    debug!("update_ip_layout");
    // split dialog content area. Top - Spinner widget
    let [spinner_rect, input_rect] =
        Layout::vertical(vec![Constraint::Length(1), Constraint::Fill(1)]).areas(*rect);

    w.update_layout("ip_spinner", spinner_rect);

    if !w.state.new_iface_state.ip_dhcp {
        let [ip, mask, gw, ipv6, domain, dns, ntp] = Layout::vertical(vec![
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
            Constraint::Length(3),
        ])
        .areas(input_rect);

        w.update_layout("ipv4", ip);
        w.update_layout("mask", mask);
        w.update_layout("gw", gw);
        w.update_layout("ipv6", ipv6);
        w.update_layout("domain", domain);
        w.update_layout("dns", dns);
        w.update_layout("ntp", ntp);
    }
}
fn update_proxy_layout(w: &mut Window<IpDialogState>, rect: &Rect) {
    debug!("update_proxy_layout");
    let [spinner_rect, input_rect] =
        Layout::vertical(vec![Constraint::Length(1), Constraint::Fill(1)]).areas(*rect);

    w.update_layout("proxy_spinner", spinner_rect);

    match w.state.new_iface_state.proxy_type {
        ProxyType::None => {}
        ProxyType::Manual => {
            let [http, https, ftp, socks, certificate] = Layout::vertical(vec![
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
                Constraint::Length(3),
            ])
            .areas(input_rect);

            let [cert_str, upload_button] =
                Layout::horizontal(vec![Constraint::Fill(1), Constraint::Length(10)])
                    .flex(Flex::End)
                    .areas(certificate);

            w.update_layout("http", http);
            w.update_layout("https", https);
            w.update_layout("ftp", ftp);
            w.update_layout("socks", socks);
            w.update_layout("certificate", cert_str);
            w.update_layout("upload", upload_button);
        } // This is not supported yet but let's keep it here for future use
          // ProxyType::Pac => {
          //     let [pac_file_area] = Layout::vertical(vec![Constraint::Length(3)]).areas(input_rect);
          //     let [pac_url, upload] =
          //         Layout::horizontal(vec![Constraint::Fill(1), Constraint::Length(10)])
          //             .flex(Flex::SpaceBetween)
          //             .areas(pac_file_area);
          //     w.update_layout("pac_file", pac_url);
          //     w.update_layout("upload", upload);
          // }
          // ProxyType::Wad => {}
    }
}

fn update_current_layout(w: &mut Window<IpDialogState>, rect: &Rect) {
    match w.state.selected_tab.as_str() {
        "IP" => {
            update_ip_layout(w, rect);
        }
        "Proxy" => {
            update_proxy_layout(w, rect);
        }
        _ => {}
    }
}

fn ip_dialog_layout(w: &mut Window<IpDialogState>, rect: &Rect, _model: &Rc<Model>) {
    debug!("ip_dialog_layout. selected tab: {}", w.state.selected_tab);
    w.clear_layout();

    let rect = centered_rect(40, 80, *rect);
    let content_with_buttons = rect.inner(Margin {
        horizontal: 1,
        vertical: 1,
    });

    w.update_layout("frame", rect);

    // split content are
    let [dialog_content, buttons] =
        Layout::vertical(vec![Constraint::Fill(1), Constraint::Length(3)])
            .flex(Flex::End)
            .areas(content_with_buttons);

    // split dialog content area. Top - Tab widget
    let [tabs, dialog_content_rect] =
        Layout::vertical(vec![Constraint::Length(3), Constraint::Fill(1)]).areas(dialog_content);
    w.update_layout("tabs", tabs);

    update_current_layout(w, &dialog_content_rect);

    // buttons
    let [ok, cancel] = Layout::horizontal(vec![Constraint::Length(6), Constraint::Length(10)])
        .flex(Flex::End)
        .areas(buttons);
    w.update_layout("ok", ok);
    w.update_layout("cancel", cancel);
}

fn ip_dialog_render(
    w: &mut Window<IpDialogState>,
    _rect: &Rect,
    frame: &mut Frame<'_>,
    _model: &Rc<Model>,
) {
    // render frame
    let frame_rect = w.get_layout("frame");

    // clear area under the dialog
    let clear = Clear {};
    frame.render_widget(clear, frame_rect);

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Double)
        .border_style(Style::default().fg(Color::White))
        .style(Style::default().bg(Color::Black))
        .title(w.state.new_iface_state.iface_name.as_str());

    frame.render_widget(block, frame_rect);
}

fn on_key_event(w: &mut Window<IpDialogState>, key: KeyEvent) -> Option<Action> {
    debug!("ip_dialog: on_key_event");

    if key.code == KeyCode::Esc {
        return Some(Action::new(&w.name, UiActions::DismissDialog));
    }

    Some(Action::new(
        "tabs",
        w.get_widget_mut("tabs").unwrap().handle_key_event(key)?,
    ))
}

fn on_child_ui_action(
    w: &mut Window<IpDialogState>,
    source: &String,
    action: &UiActions,
) -> Option<Action> {
    debug!("on_child_ui_action: {}:{:?}", source, action);
    match action {
        UiActions::TabChanged(old_tab, selected_tab) => {
            save_restore_ft_state(w, old_tab, selected_tab);
            Some(Action::new(source, UiActions::Redraw))
        }
        UiActions::SpinBox { selected } => match source.as_str() {
            "ip_spinner" => {
                w.state.new_iface_state.ip_dhcp = *selected == 0;
                update_tab_order(w);
                Some(Action::new(source, UiActions::Redraw))
            }
            "proxy_spinner" => {
                w.state.new_iface_state.proxy_type = match *selected {
                    0 => ProxyType::None,
                    1 => ProxyType::Manual,
                    // 2 => ProxyType::Pac,
                    _ => ProxyType::None,
                };
                update_tab_order(w);
                Some(Action::new(source, UiActions::Redraw))
            }
            _ => None,
        },
        UiActions::ButtonClicked(name) => match name.as_str() {
            "cancel" => Some(Action::new(&w.name, UiActions::DismissDialog)),
            "ok" => Some(Action::new(
                &w.name,
                UiActions::AppAction(MonActions::NetworkInterfaceUpdated(
                    w.state.old_iface_state.clone(),
                    w.state.new_iface_state.clone(),
                )),
            )),
            _ => None,
        },
        UiActions::Input { text } => {
            match source.as_str() {
                "ipv4" => w.state.new_iface_state.ipv4 = text.clone(),
                "ipv6" => w.state.new_iface_state.ipv6 = text.clone(),
                "mask" => w.state.new_iface_state.mask = text.clone(),
                "gw" => w.state.new_iface_state.gw = text.clone(),
                "dns" => w.state.new_iface_state.dns = text.clone(),
                "domain" => w.state.new_iface_state.domain = text.clone(),
                "http" => w.state.new_iface_state.proxy_http = parse_proxy_url(text, "http"),
                "https" => w.state.new_iface_state.proxy_https = parse_proxy_url(text, "https"),
                "ftp" => w.state.new_iface_state.proxy_ftp = parse_proxy_url(text, "ftp"),
                "socks" => w.state.new_iface_state.proxy_socks = parse_proxy_url(text, "socks"),
                "ntp" => w.state.new_iface_state.ntp = text.clone(),
                _ => {}
            }
            None
        }
        _ => None,
    }
}

fn save_restore_ft_state(w: &mut Window<IpDialogState>, old_tab: &str, selected_tab: &String) {
    // save FocusTracker state for the old tab
    w.state
        .focus_tarcker_state
        .insert(old_tab.to_owned(), w.get_focused_view());

    w.state.selected_tab = selected_tab.clone();

    // restore FocusTracker state for the new tab
    update_tab_order(w);

    // and the focused view
    let focus_tracker_state = w.state.focus_tarcker_state.get(selected_tab);
    if let Some(focus_tracker_state) = focus_tracker_state {
        w.set_focused_view(*focus_tracker_state);
    }
}

fn update_tab_order(w: &mut Window<IpDialogState>) {
    let new_tab_order = w
        .state
        .get_current_tab_order()
        .iter()
        .map(|x| x.to_string())
        .collect::<Vec<String>>();
    w.set_focus_tracker_tab_order(new_tab_order);
}

impl From<&NetworkInterfaceStatus> for IpDialogState {
    fn from(iface: &NetworkInterfaceStatus) -> Self {
        // take only the first ipv4  and ipv6 address
        // TODO: per Milan, we may get local IPs on interfaces
        // need to find out how to filter them out
        // but those are just to fill the dialog, so it's not a big deal
        // user will change them anyway
        let ipv4 = iface
            .ipv4
            .as_ref()
            .and_then(|ipv4: &Vec<std::net::Ipv4Addr>| ipv4.first().cloned())
            .map(|addr| addr.to_string())
            .unwrap_or_default();

        let ipv6 = iface
            .ipv6
            .as_ref()
            .and_then(|ipv6: &Vec<std::net::Ipv6Addr>| ipv6.first().cloned())
            .map(|addr| addr.to_string())
            .unwrap_or_default();

        let proxy_type = match iface.proxy_config {
            ProxyConfig::None => ProxyType::None,
            ProxyConfig::Manual { .. } => ProxyType::Manual,
            // ProxyConfig::Pac { .. } => ProxyType::Pac,
            // ProxyConfig::Wad { .. } => ProxyType::Wad,
            _ => ProxyType::None,
        };

        let proxy_url = if let ProxyConfig::Wad { url, .. } = &iface.proxy_config {
            url.to_string()
        } else {
            "".to_string()
        };

        let pac_file = if let ProxyConfig::Pac { url, .. } = &iface.proxy_config {
            url.to_string()
        } else {
            "".to_string()
        };

        let mut proxy_ftp = None;
        let mut proxy_http = None;
        let mut proxy_https = None;
        let mut proxy_socks = None;

        if let ProxyConfig::Manual {
            ftp,
            http,
            https,
            socks,
        } = &iface.proxy_config
        {
            proxy_ftp = ftp
                .as_ref()
                .and_then(|p| Url::parse(&format!("ftp://{}", p.to_url())).ok());
            proxy_http = http
                .as_ref()
                .and_then(|p| Url::parse(&format!("http://{}", p.to_url())).ok());
            proxy_https = https
                .as_ref()
                .and_then(|p| Url::parse(&format!("https://{}", p.to_url())).ok());
            proxy_socks = socks
                .as_ref()
                .and_then(|p| Url::parse(&format!("socks://{}", p.to_url())).ok());
        }

        // convert to comma separated string
        let dns = iface
            .dns
            .iter()
            .flatten()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(",");

        // same for NTP
        let ntp = iface
            .ntp_servers
            .iter()
            .flatten()
            .map(|ip| ip.to_string())
            .collect::<Vec<String>>()
            .join(",");

        let domain = iface.domain.clone().unwrap_or_default();

        let new_iface_state = InterfaceState {
            iface_name: iface.name.clone(),
            ip_dhcp: iface.is_dhcp,
            ipv4: ipv4.clone(),
            ipv6: ipv6.clone(),
            proxy_type,
            mask: iface
                .subnet
                .map(|ip| ip.netmask().to_string())
                .unwrap_or_default(),
            gw: iface
                .routes
                .as_ref()
                .map(|ip| {
                    ip.iter()
                        .map(|ip| ip.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                })
                .unwrap_or_default(),
            proxy_url,
            proxy_certificate: "".to_string(),
            pac_file,
            domain,
            dns,
            ntp,
            proxy_ftp,
            proxy_http,
            proxy_https,
            proxy_socks,
        };

        let old_iface_state = new_iface_state.clone();

        IpDialogState {
            selected_tab: "IP".to_string(),
            focus_tarcker_state: HashMap::new(),
            new_iface_state,
            old_iface_state,
        }
    }
}

pub fn create_ip_dialog(iface: &NetworkInterfaceStatus) -> impl IWindow {
    let state = IpDialogState::from(iface);

    Window::builder("IP configuration")
        .with_layout(ip_dialog_layout)
        .with_render(ip_dialog_render)
        .with_on_child_ui_action(on_child_ui_action)
        .with_on_key_event(on_key_event)
        .with_on_init(on_init)
        .with_state(state)
        .build()
        .unwrap()
}
