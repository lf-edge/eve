// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::path::PathBuf;
use uuid::Uuid;

use crate::tcg::{
    tcg_events::TcgEfiVariableEvent,
    tcg_tpmlog::{Digest, TcgRawTpmEvent, TcgTpmEventType},
};

use super::tpmlog::TpmEvent;

// Helper to create EFI variable boot events
fn mock_boot_order_event(order: &[u16], is_type_2: bool) -> TcgRawTpmEvent {
    let efi_var = TcgEfiVariableEvent {
        vendor_guid: Uuid::parse_str("8BE4DF61-93CA-11D2-AA0D-00E098032B8C").unwrap(), // EFI_GLOBAL_VARIABLE_GUID
        unicode_name: "BootOrder".to_string(),
        variable_data: order
            .iter()
            .flat_map(|v| v.to_le_bytes().to_vec())
            .collect(),
    };

    let event_data = efi_var.serialize();

    if is_type_2 {
        mock_tcg_tpm_event(1, TcgTpmEventType::EfiVariableBoot2, &event_data)
    } else {
        mock_tcg_tpm_event(1, TcgTpmEventType::EfiVariableBoot, &event_data)
    }
}

// fn moc_boot_variables_set1

fn moc_boot_event(index: u16, is_type_2: bool) -> TcgRawTpmEvent {
    let efi_var = TcgEfiVariableEvent {
        vendor_guid: Uuid::parse_str("8BE4DF61-93CA-11D2-AA0D-00E098032B8C").unwrap(), // EFI_GLOBAL_VARIABLE_GUID
        unicode_name: format!("Boot{:04X}", index),
        variable_data: index.to_le_bytes().to_vec(),
    };

    let event_data = efi_var.serialize();

    if is_type_2 {
        mock_tcg_tpm_event(1, TcgTpmEventType::EfiVariableBoot2, &event_data)
    } else {
        mock_tcg_tpm_event(1, TcgTpmEventType::EfiVariableBoot, &event_data)
    }
}

fn mock_pcr14_event(file: &str, exists: bool, hash: Option<&str>) -> TcgRawTpmEvent {
    let event_data = if let Some(hash) = hash {
        format!("file:{} exist:{} content-hash:{}", file, exists, hash)
    } else {
        format!("file:{} exist:{}", file, exists)
    };
    mock_tcg_tpm_event(14, TcgTpmEventType::EfiAction, &event_data)
}

fn mock_ipl_event(pcr: u32, data: &[u8]) -> TcgRawTpmEvent {
    // convert to null-terminated ASCII string
    let data = data
        .iter()
        .chain(std::iter::once(&0u8))
        .copied()
        .collect::<Vec<_>>();
    mock_tcg_tpm_event(pcr, TcgTpmEventType::IPL, &data)
}

// Helper to create mock events
fn mock_tcg_tpm_event<T>(pcr: u32, event_type: TcgTpmEventType, data: &T) -> TcgRawTpmEvent
where
    T: AsRef<[u8]> + ?Sized,
{
    TcgRawTpmEvent {
        pcr_index: pcr,
        event_type,
        digests: vec![Digest::new_sha256(data.as_ref())], // Fixed digests
        event_data: data.as_ref().to_vec(),
    }
}

fn get_test_data_path(data: &str) -> PathBuf {
    let manifest_dir =
        std::env::var("CARGO_MANIFEST_DIR").expect("Failed to find CARGO_MANIFEST_DIR");
    let test_data_path = std::path::Path::new(&manifest_dir).join("test_data");
    test_data_path.join(data)
}

#[test]
fn test_try_from_tpm_event_footfs_event() {
    let tpm_event = mock_ipl_event(
        13,
        b"squash4 b6dd08d6bc197ea4417bcbc844ecdbe173af97504555d64014380a968aae9c43",
    );
    let rootfs_measurement_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();

    match rootfs_measurement_event {
        TpmEvent::MeasureRoot { rootfs, hash } => {
            assert_eq!(rootfs, "squash4");
            assert_eq!(
                hash,
                "b6dd08d6bc197ea4417bcbc844ecdbe173af97504555d64014380a968aae9c43"
            );
        }
        _ => panic!("Invalid rootfs event"),
    }
}

#[test]
fn test_try_from_tpm_event_action_config() {
    let tpm_event = mock_pcr14_event(
        "/config/authorized_keys",
        true,
        Some("61e3c4e3aaee97c87c12d4dfbd699b11007e3a5900b02d53f18d978f31cfcaf8"),
    );

    let action_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();

    match action_event {
        TpmEvent::MeasureConfig { file, hash, exists } => {
            assert_eq!(file, "/config/authorized_keys");
            assert_eq!(
                hash,
                "61e3c4e3aaee97c87c12d4dfbd699b11007e3a5900b02d53f18d978f31cfcaf8"
            );
            assert!(exists);
        }
        _ => panic!("Invalid action event"),
    }
}

#[test]
fn test_try_from_tpm_event_action_config_not_exist() {
    let tpm_event = mock_pcr14_event("/config/authorized_keys", false, None);

    let action_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();

    match action_event {
        TpmEvent::MeasureConfig { file, hash, exists } => {
            assert_eq!(file, "/config/authorized_keys");
            assert_eq!(hash, "");
            assert!(!exists);
        }
        _ => panic!("Invalid action event"),
    }
}

#[test]
fn test_try_from_tpm_event_action_config_not_exist_hash() {
    let tpm_event = mock_pcr14_event(
        "/config/authorized_keys",
        false,
        Some("61e3c4e3aaee97c87c12d4dfbd699b11007e3a5900b02d53f18d978f31cfcaf8"),
    );

    // should fail because hash is not empty
    let action_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]);
    match action_event {
        Ok(_) => panic!("must fail"),
        Err(e) => assert_eq!(
            e.to_string(),
            "Invalid TpmEvent::MeasureConfig: hash is not empty for exist:false"
        ),
    }
}

#[test]
fn test_try_from_tpm_event_action_config_exist_no_hash() {
    let tpm_event = mock_pcr14_event("/config/authorized_keys", true, None);

    // should fail because hash is not empty
    let action_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();
    match action_event {
        TpmEvent::MeasureConfig { file, hash, exists } => {
            assert_eq!(file, "/config/authorized_keys");
            assert_eq!(hash, "");
            assert!(exists);
        }
        _ => panic!("Invalid action event"),
    }
}

#[test]
fn test_try_from_grub_event_cmd() {
    let tpm_event = mock_ipl_event(8, b"grub_cmd export dom0_flavor_tweaks");

    let grub_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();

    match grub_event {
        TpmEvent::GrubCmd { cmd, params } => {
            assert_eq!(cmd, "export");
            assert_eq!(params, "dom0_flavor_tweaks");
        }
        _ => panic!("Invalid grub event"),
    }
}
#[test]
fn test_try_from_grub_event_kernel_cmdline() {
    let tpm_event = mock_ipl_event(
        8,
        b"grub_kernel_cmdline /boot/kernel console=ttyS0 console=hvc0 root=PARTUUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30052 dom0_mem=640M,\
        max:800M dom0_max_vcpus=1 dom0_vcpus_pin eve_mem=520M,max:650M eve_max_vcpus=1 ctrd_mem=320M,max:400M ctrd_max_vcpus=1 \
        change=500 clocksource=tsc clocksource_failover=xen pcie_acs_override=downstream,multifunction crashkernel=2G-16G:128M,16G-128G:256M,128G-:512M \
        rootdelay=3 linuxkit.unified_cgroup_hierarchy=0 panic=120 rfkill.default_state=0 split_lock_detect=off test",
    );

    let grub_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();

    match grub_event {
        TpmEvent::GrubKernelCmdline(cmd) => {
            assert_eq!(cmd,"/boot/kernel console=ttyS0 console=hvc0 root=PARTUUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30052 dom0_mem=640M,max:800M \
                dom0_max_vcpus=1 dom0_vcpus_pin eve_mem=520M,max:650M eve_max_vcpus=1 ctrd_mem=320M,max:400M \
                ctrd_max_vcpus=1 change=500 clocksource=tsc clocksource_failover=xen pcie_acs_override=downstream,multifunction \
                crashkernel=2G-16G:128M,16G-128G:256M,128G-:512M rootdelay=3 linuxkit.unified_cgroup_hierarchy=0 panic=120 rfkill.default_state=0 \
                split_lock_detect=off test" );
        }
        _ => panic!("Invalid grub event"),
    }
}

#[test]
fn test_try_from_grub_event_linuxefi() {
    let tpm_event = mock_ipl_event(
        8,
        b"grub_linuxefi /boot/vmlinuz-5.4.0-104-generic root=PARTUUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30052 ro quiet splash vt.handoff=7",
    );

    let grub_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();

    match grub_event {
        TpmEvent::GrubLinuxEfi(cmd) => {
            assert_eq!(cmd,"/boot/vmlinuz-5.4.0-104-generic root=PARTUUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30052 ro quiet splash vt.handoff=7" );
        }
        _ => panic!("Invalid grub event"),
    }
}
#[test]
fn test_try_from_grub_event_generic() {
    let tpm_event = mock_ipl_event(8, b"invalid_event data");

    let grub_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]);

    match grub_event {
        Ok(TpmEvent::GrubGenericEvent(event, data)) => {
            assert_eq!(event, "invalid_event");
            assert_eq!(data, "data");
        }
        Ok(e) => panic!("Invalid grub event: {:?}", e),
        Err(e) => panic!("must not fail: {}", e),
    }
}
#[test]
fn test_try_from_grub_event_invalid_pcr() {
    let tpm_event = mock_ipl_event(1, b"grub_cmd export dom0_flavor_tweaks");

    let grub_event = TpmEvent::try_from_tcg_event(&tpm_event, &vec![]).unwrap();
    assert!(matches!(grub_event, TpmEvent::RawEvent(..)))
}
