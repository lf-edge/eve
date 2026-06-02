// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Cross-language contract gate: deserialize the canonical JSON emitted by the
//! Go `monitorapi` package (pkg/pillar/types/monitorapi/testdata) into the
//! generated Rust types, verify typed access, and confirm Rust re-serializes to
//! the same wire shape. Go owns the fixtures; this side must agree.

use super::monitorapi::*;
use std::net::IpAddr;
use std::path::PathBuf;

fn fixture(name: &str) -> String {
    // Fixtures live in the Go contract package, reachable in-repo.
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../pillar/types/monitorapi/testdata")
        .join(name);
    std::fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "read {} ({e}); run `go generate ./types/monitorapi/...` first",
            path.display()
        )
    })
}

#[test]
fn static_ip_parses_into_real_types() {
    let cfg: StaticIpConfig = serde_json::from_str(&fixture("static_ip_valid.json")).unwrap();
    assert_eq!(cfg.ip, "192.0.2.10".parse::<IpAddr>().unwrap());
    assert_eq!(cfg.subnet.prefix_len(), 24);
    assert!(cfg.subnet.contains(&cfg.ip)); // typed in-subnet check
    assert!(cfg.dns_servers.iter().any(IpAddr::is_ipv6));
}

#[test]
fn static_ip_wire_format_matches_go() {
    let cfg: StaticIpConfig = serde_json::from_str(&fixture("static_ip_valid.json")).unwrap();
    let rust: serde_json::Value =
        serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
    let go: serde_json::Value = serde_json::from_str(&fixture("static_ip_valid.json")).unwrap();
    assert_eq!(rust, go, "Rust wire format diverged from Go");
}

#[test]
fn proxy_union_roundtrips() {
    let p: ProxySettings = serde_json::from_str(&fixture("proxy_manual.json")).unwrap();
    match &p {
        ProxySettings::Manual { servers, .. } => {
            assert_eq!(servers[0].scheme, ProxyScheme::Https);
            assert_eq!(servers[0].port, 8080);
        }
        other => panic!("expected Manual, got {other:?}"),
    }
    let again: ProxySettings =
        serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
    assert_eq!(p, again);

    let none: ProxySettings = serde_json::from_str(&fixture("proxy_none.json")).unwrap();
    assert_eq!(none, ProxySettings::None);
}

#[test]
fn network_proxy_embeds_union() {
    let np: NetworkProxy = serde_json::from_str(&fixture("network_proxy.json")).unwrap();
    assert_eq!(np.port, "eth0");
    assert!(matches!(np.proxy, ProxySettings::Manual { .. }));
}

#[test]
fn network_status_nests_vlans_and_cellular() {
    let ns: NetworkStatus = serde_json::from_str(&fixture("network_status.json")).unwrap();
    assert_eq!(ns.dpc_key, "manual");
    assert_eq!(ns.interfaces.len(), 2);

    let eth0 = &ns.interfaces[0];
    assert_eq!(eth0.name, "eth0");
    assert!(matches!(eth0.media, NetworkMedia::Ethernet));
    assert!(eth0.network.is_dhcp);
    assert_eq!(eth0.network.subnet.unwrap().prefix_len(), 24);
    assert!(matches!(eth0.network.proxy, ProxySettings::Manual { .. }));
    // VLAN nested under its parent.
    assert_eq!(eth0.vlans.len(), 1);
    assert_eq!(eth0.vlans[0].id, 100);
    assert_eq!(eth0.vlans[0].label, "office");

    let wwan = &ns.interfaces[1];
    match &wwan.media {
        NetworkMedia::Cellular { operator, sims, rats, .. } => {
            assert_eq!(operator, "Verizon");
            assert_eq!(rats, &vec!["LTE".to_string()]);
            assert_eq!(sims[0].apn, "vzwinternet");
        }
        other => panic!("expected Cellular, got {other:?}"),
    }
}

#[test]
fn small_messages_parse() {
    let a: AppsList = serde_json::from_str(&fixture("apps_list.json")).unwrap();
    assert_eq!(a.instances.len(), 2);
    assert_eq!(a.instances[0].name, "nginx");
    assert_eq!(a.instances[0].state, SwState::Running);
    assert_eq!(a.instances[1].state, SwState::Broken);
    assert_eq!(a.instances[1].error, "image pull failed");
    let c: TuiConfig = serde_json::from_str(&fixture("tui_config.json")).unwrap();
    assert_eq!(c.log_level, "debug");
    let d: DownloaderStatus = serde_json::from_str(&fixture("downloader_status.json")).unwrap();
    assert_eq!(d.progress, 42);
    assert_eq!(d.name, "image.qcow2");
    assert_eq!(d.state, SwState::Downloading);
}

#[test]
fn set_interface_config_parses() {
    // Exercises a struct carrying two internally-tagged unions (IP + Proxy).
    let s: SetInterfaceConfig = serde_json::from_str(&fixture("set_interface_config.json")).unwrap();
    assert_eq!(s.iface, "eth0");
    assert_eq!(s.domain, "example.com");
    assert_eq!(s.ntp, vec!["pool.ntp.org".to_string()]);
    match s.ip {
        IpMode::Static { config } => {
            assert_eq!(config.ip.to_string(), "192.0.2.10");
            assert_eq!(config.subnet.to_string(), "192.0.2.0/24");
        }
        other => panic!("expected Static, got {other:?}"),
    }
    match s.proxy {
        ProxySettings::Manual { servers, .. } => {
            assert_eq!(servers[0].scheme, ProxyScheme::Http);
            assert_eq!(servers[0].host, "proxy");
            assert_eq!(servers[0].port, 8080);
        }
        other => panic!("expected Manual, got {other:?}"),
    }
}

#[test]
fn vault_status_locked() {
    let v: VaultStatus = serde_json::from_str(&fixture("vault_status.json")).unwrap();
    match v {
        VaultStatus::Locked { error, mismatching_pcrs } => {
            assert_eq!(error, "Vault key unavailable");
            assert_eq!(mismatching_pcrs, vec![0, 7]);
        }
        other => panic!("expected Locked, got {other:?}"),
    }
}

#[test]
fn device_status_parses() {
    let d: DeviceStatus = serde_json::from_str(&fixture("device_status.json")).unwrap();
    assert_eq!(d.node_name, "edge-node-01");
    assert_eq!(d.serial, "ABC123XYZ");
    assert!(d.onboarded && !d.node_uuid.is_nil());
    assert!(matches!(d.attest_state, AttestState::Complete));
    assert!(matches!(d.device_state, DeviceState::Online));
    assert!(matches!(d.boot_reason, BootReason::RebootCmd));
    assert!(matches!(d.config_status, ConfigGetStatus::Success));
    assert!(matches!(d.vault, VaultStatus::Unlocked { tpm_used: true }));
}
