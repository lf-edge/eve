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
    let s: AppSummary = serde_json::from_str(&fixture("app_summary.json")).unwrap();
    assert_eq!((s.running, s.error), (5, 2));
    let c: TuiConfig = serde_json::from_str(&fixture("tui_config.json")).unwrap();
    assert_eq!(c.log_level, "debug");
    let l: LedBlinkCounter = serde_json::from_str(&fixture("led_blink_counter.json")).unwrap();
    assert_eq!(l.blink_counter, 4);
}

#[test]
fn downloader_and_zedagent_parse() {
    let d: DownloaderStatus = serde_json::from_str(&fixture("downloader_status.json")).unwrap();
    assert_eq!(d.progress, 42);
    assert_eq!(d.name, "image.qcow2");
    let z: ZedAgentStatus = serde_json::from_str(&fixture("zed_agent_status.json")).unwrap();
    assert!(matches!(z.attest_state, AttestState::Complete));
    assert!(matches!(z.device_state, DeviceState::Online));
    assert!(matches!(z.boot_reason, BootReason::RebootCmd));
    assert!(matches!(z.config_status, ConfigGetStatus::Success));
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
fn node_status_parses() {
    let n: NodeStatus = serde_json::from_str(&fixture("node_status.json")).unwrap();
    assert_eq!(n.node_name, "edge-node-01");
    assert_eq!(n.serial, "ABC123XYZ");
    assert!(n.onboarded);
    assert!(!n.node_uuid.is_nil());
}

#[test]
fn onboarding_status_parses() {
    let o: OnboardingStatus = serde_json::from_str(&fixture("onboarding_status.json")).unwrap();
    assert_eq!(
        o.device_uuid.to_string(),
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8"
    );
    assert_eq!(o.hardware_model, "QEMU Standard PC");
}
