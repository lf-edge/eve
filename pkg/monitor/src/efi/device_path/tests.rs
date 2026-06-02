// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use crate::efi::device_path::media::{PartitionSignature, PartitionType};

use super::DevicePath;

#[test]
fn text_device_path_efi_spec_p312() {
    let path = DevicePath::new()
        .acpi_acpi(0x0A03, 0x0)
        .hw_pci(0, 0x19)
        .msg_mac_addr("AA:11:22:33:44:55".parse().unwrap(), 0x1)
        .msg_ipv4(
            "192.168.0.1".parse().unwrap(),
            "192.168.0.100".parse().unwrap(),
            0,
            3260,
            true,
            6,
            "1.1.1.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        )
        .msg_i_scsi(
            0x800,
            0x1,
            0x0,
            "iqn.1991-05.com.microsoft:iscsitarget-iscsidisk-target",
        )
        .media_hdd(
            1,
            0x22,
            0x2710000,
            PartitionSignature::Guid(uuid::uuid!("15E39A00-1DD2-1000-8D7F-00A0C92408FC")),
            PartitionType::Gpt,
        );
    assert_eq!(
        path.nodes[0].to_bytes(),
        vec![0x02, 0x01, 0x0C, 0x0, 0xd0, 0x41, 0x03, 0x0a, 0x00, 0x00, 0x00, 0x00]
    );
    assert_eq!(
        path.nodes[1].to_bytes(),
        vec![0x01, 0x01, 0x06, 0x0, 0x00, 0x19]
    );
    assert_eq!(
        path.nodes[2].to_bytes(),
        vec![
            0x03, 0x0b, 0x25, 0x00, //size
            0xAA, 0x11, 0x22, 0x33, 0x44, 0x55, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0, 0, 0, 0, 0, 0, 0, // padded mac address
            0x1
        ]
    );
    assert_eq!(
        path.nodes[3].to_bytes(),
        vec![
            0x03, 0x0c, 0x1b, 0x0, 0xc0, 0xA8, 0x00, 0x01, 0xC0, 0xA8, 0x00, 0x64, 0x00, 0x00,
            0xbc, 0x0c, 0x6, 0x0, 1, 0x1, 0x1, 0x1, 0x1, 0xff, 0xff, 0xff, 0
        ]
    );
    assert_eq!(
        path.nodes[4].to_bytes(),
        vec![
            0x03, 0x13, 0x49, 0x0, 0x00, 0x0, 0x0, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0x1, 0x0, 0x69,
            0x71, 0x6E, 0x2E, 0x31, 0x39, 0x39, 0x31, 0x2D, 0x30, 0x35, 0x2E, 0x63, 0x6F, 0x6D,
            0x2E, 0x6D, 0x69, 0x63, 0x72, 0x6F, 0x73, 0x6F, 0x66, 0x74, 0x3a, 0x69, 0x73, 0x63,
            0x73, 0x69, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x2D, 0x69, 0x73, 0x63, 0x73, 0x69,
            0x64, 0x69, 0x73, 0x6B, 0x2D, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x0
        ]
    );
    assert_eq!(
        path.nodes[5].to_bytes(),
        vec![
            0x04, 0x1, 0x2A, 0x00, 0x1, 0x00, 0x00, 0x00, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x71, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x9A, 0xE3, 0x15, 0xD2,
            0x1D, 0x00, 0x10, 0x8D, 0x7F, 0x00, 0xA0, 0xC9, 0x24, 0x08, 0xFC, 0x2, 0x2
        ]
    );
}

#[test]
fn test_device_path_display() {
    let path = DevicePath::new()
        .acpi_acpi(0x0A03, 0x0)
        .hw_pci(0, 0x19)
        .msg_mac_addr("AA:11:22:33:44:55".parse().unwrap(), 0x1)
        .msg_ipv4(
            "192.168.0.1".parse().unwrap(),
            "192.168.0.100".parse().unwrap(),
            0,
            3260,
            true,
            6,
            "1.1.1.1".parse().unwrap(),
            "255.255.255.0".parse().unwrap(),
        )
        .msg_i_scsi(
            0x800,
            0x1,
            0x0,
            "iqn.1991-05.com.microsoft:iscsitarget-iscsidisk-target",
        )
        .media_hdd(
            1,
            0x22,
            0x2710000,
            PartitionSignature::Guid(uuid::uuid!("15E39A00-1DD2-1000-8D7F-00A0C92408FC")),
            PartitionType::Gpt,
        );
    let display = path.display(false);
    println!("{}", display);
}

#[test]
fn test_uri_empty() {
    // Test empty URI (length = 4, no data)
    let path = DevicePath::new()
        .acpi_acpi(0x0A03, 0x0)
        .hw_pci(0, 0x1F)
        .msg_mac_addr("38:F7:CD:C5:97:0B".parse().unwrap(), 0x0)
        .msg_ipv4(
            "0.0.0.0".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
            0,
            0,
            false,
            0,
            "0.0.0.0".parse().unwrap(),
            "0.0.0.0".parse().unwrap(),
        )
        .msg_uri("");

    let display = path.display(false);
    assert!(display.contains("Uri()"));

    // Check that the Uri node serializes correctly (length = 4, no data)
    let uri_node_bytes = path.nodes[4].to_bytes();
    assert_eq!(uri_node_bytes[0], 0x03); // Messaging type
    assert_eq!(uri_node_bytes[1], 24); // Uri subtype
    assert_eq!(uri_node_bytes[2], 4); // Length low byte
    assert_eq!(uri_node_bytes[3], 0); // Length high byte
    assert_eq!(uri_node_bytes.len(), 4); // No additional data
}

#[test]
fn test_uri_with_content() {
    // Test URI with content
    let uri_string = "http://example.com/boot.img";
    let path = DevicePath::new()
        .acpi_acpi(0x0A03, 0x0)
        .hw_pci(0, 0x1F)
        .msg_mac_addr("38:F7:CD:C5:97:0B".parse().unwrap(), 0x0)
        .msg_uri(uri_string);

    let display = path.display(false);
    assert!(display.contains(&format!("Uri({})", uri_string)));

    // Check that the Uri node serializes correctly
    let uri_node_bytes = path.nodes[3].to_bytes();
    assert_eq!(uri_node_bytes[0], 0x03); // Messaging type
    assert_eq!(uri_node_bytes[1], 24); // Uri subtype
    let expected_length = 4 + uri_string.len();
    assert_eq!(uri_node_bytes[2], (expected_length & 0xFF) as u8);
    assert_eq!(uri_node_bytes[3], ((expected_length >> 8) & 0xFF) as u8);

    // Check the URI data
    let uri_data = &uri_node_bytes[4..];
    assert_eq!(uri_data, uri_string.as_bytes());
}

#[test]
fn test_sas_vendor_messaging() {
    // Test SAS (vendor-defined messaging type with GUID)
    // SAS Address: 0x5000c5001e9b5678
    // LUN: 0x0000000000000001
    // Device Topology: 0x0000
    // Drive Topology: 0x0001
    let sas_address = [0x78, 0x56, 0x9b, 0x1e, 0x00, 0xc5, 0x00, 0x50];
    let lun = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let path = DevicePath::new()
        .acpi_acpi(0x0A03, 0x0)
        .hw_pci(0, 0x1F)
        .msg_sas(sas_address, lun, 0x0000, 0x0001);

    let display = path.display(false);
    assert!(display.contains("SAS("));
    // SAS address should be uppercase hex with 0x prefix
    assert!(display.contains("0x78569B1E00C50050"));
    // LUN should be uppercase hex with 0x prefix
    assert!(display.contains("0x0100000000000000"));

    // Check that the SAS node serializes correctly
    let sas_node_bytes = path.nodes[2].to_bytes();
    assert_eq!(sas_node_bytes[0], 0x03); // Messaging type
    assert_eq!(sas_node_bytes[1], 10); // Vendor subtype
    assert_eq!(sas_node_bytes[2], 44); // Length low byte (44 bytes total: 4 header + 40 data)
    assert_eq!(sas_node_bytes[3], 0); // Length high byte

    // Check GUID: d487ddb4-008b-11d9-afdc-001083ffca4d
    // EFI GUIDs are stored with mixed endianness (first 3 fields little-endian, rest big-endian)
    let expected_guid = uuid::uuid!("d487ddb4-008b-11d9-afdc-001083ffca4d");
    let (d1, d2, d3, d4) = expected_guid.as_fields();
    let mut expected_guid_bytes = Vec::new();
    expected_guid_bytes.extend_from_slice(&d1.to_le_bytes());
    expected_guid_bytes.extend_from_slice(&d2.to_le_bytes());
    expected_guid_bytes.extend_from_slice(&d3.to_le_bytes());
    expected_guid_bytes.extend_from_slice(d4);
    assert_eq!(&sas_node_bytes[4..20], expected_guid_bytes.as_slice());

    // Check reserved (4 bytes)
    assert_eq!(&sas_node_bytes[20..24], &[0, 0, 0, 0]);

    // Check SAS address
    assert_eq!(&sas_node_bytes[24..32], &sas_address);

    // Check LUN
    assert_eq!(&sas_node_bytes[32..40], &lun);

    // Check device topology (2 bytes little-endian)
    assert_eq!(&sas_node_bytes[40..42], &[0x00, 0x00]);

    // Check drive topology (2 bytes little-endian)
    assert_eq!(&sas_node_bytes[42..44], &[0x01, 0x00]);

    // Total length should be 44 bytes (4 header + 40 data)
    assert_eq!(sas_node_bytes.len(), 44);
}

#[test]
fn test_sas_ex_messaging() {
    // Test SASEx (standard messaging subtype 22)
    // SAS Address: 0x5000c5001e9b5678
    // Reserved: 8 bytes (zeros)
    // LUN: 0x0000000000000001
    // Device Topology Info: 0x0000
    // RTP: 0x0001
    let sas_address = [0x78, 0x56, 0x9b, 0x1e, 0x00, 0xc5, 0x00, 0x50];
    let lun = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let path = DevicePath::new()
        .acpi_acpi(0x0A03, 0x0)
        .hw_pci(0, 0x1F)
        .msg_sas_ex(sas_address, lun, 0x0000, 0x0001);

    let display = path.display(false);
    assert!(display.contains("SasEx("));
    // SAS address should be uppercase hex with 0x prefix
    assert!(display.contains("0x78569B1E00C50050"));
    // LUN should be uppercase hex with 0x prefix
    assert!(display.contains("0x0100000000000000"));

    // Check that the SASEx node serializes correctly
    let sas_ex_node_bytes = path.nodes[2].to_bytes();
    assert_eq!(sas_ex_node_bytes[0], 0x03); // Messaging type
    assert_eq!(sas_ex_node_bytes[1], 22); // SASEx subtype
    assert_eq!(sas_ex_node_bytes[2], 32); // Length low byte (32 bytes total: 4 header + 28 data)
    assert_eq!(sas_ex_node_bytes[3], 0); // Length high byte

    // Check SAS address (8 bytes at offset 4-12)
    assert_eq!(&sas_ex_node_bytes[4..12], &sas_address);

    // Check reserved (8 bytes at offset 12-20, should be zeros)
    assert_eq!(&sas_ex_node_bytes[12..20], &[0u8; 8]);

    // Check LUN (8 bytes at offset 20-28)
    assert_eq!(&sas_ex_node_bytes[20..28], &lun);

    // Check device topology info (2 bytes at offset 28-30)
    assert_eq!(&sas_ex_node_bytes[28..30], &[0x00, 0x00]);

    // Check RTP (2 bytes at offset 30-32)
    assert_eq!(&sas_ex_node_bytes[30..32], &[0x01, 0x00]);

    // Total length should be 32 bytes (4 header + 28 data)
    assert_eq!(sas_ex_node_bytes.len(), 32);

    // Verify the length field is correct (32 bytes)
    let length = u16::from_le_bytes([sas_ex_node_bytes[2], sas_ex_node_bytes[3]]);
    assert_eq!(length, 32);
}

#[test]
fn test_sas_round_trip() {
    // Test that SAS node can be serialized and deserialized correctly
    let sas_address = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let lun = [0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let path = DevicePath::new()
        .msg_sas(sas_address, lun, 0x0002, 0x0003)
        .end();

    // Serialize to bytes
    let bytes = path.to_bytes();

    // Deserialize back
    let parsed_path = DevicePath::try_from(bytes.as_slice()).unwrap();

    // Check display matches
    assert_eq!(path.display(false), parsed_path.display(false));
}

#[test]
fn test_sas_ex_round_trip() {
    // Test that SASEx node can be serialized and deserialized correctly
    let sas_address = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let lun = [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let path = DevicePath::new()
        .msg_sas_ex(sas_address, lun, 0x0002, 0x0003)
        .end();

    // Serialize to bytes
    let bytes = path.to_bytes();

    // Deserialize back
    let parsed_path = DevicePath::try_from(bytes.as_slice()).unwrap();

    // Check display matches
    assert_eq!(path.display(false), parsed_path.display(false));
}

#[test]
fn test_sas_topology_no_info() {
    // Test SAS with no topology information (device_topology low 4 bits = 0)
    let sas_address = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let lun = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let path = DevicePath::new()
        .msg_sas(sas_address, lun, 0x0000, 0x0000)
        .end();

    let display = path.display(false);
    // Should show just SAS address when LUN is 0 and no topology
    assert!(display.contains("SAS(0x1122334455667788)/"));
}

#[test]
fn test_sas_topology_with_lun() {
    // Test SAS with LUN but no topology information
    let sas_address = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let lun = [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];

    let path = DevicePath::new()
        .msg_sas(sas_address, lun, 0x0000, 0x0000)
        .end();

    let display = path.display(false);
    // Should show both SAS address and LUN when LUN is non-zero
    assert!(display.contains("SAS(0x1122334455667788,0x0100000000000000)/"));
}

#[test]
fn test_sas_topology_sas_internal() {
    // Test SAS with topology information - SAS Internal device
    // Bits 0:3 = 1 (topology info present)
    // Bits 4:5 = 0 (SAS Internal)
    let sas_address = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let lun = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let device_topology = 0x0001; // Topology info present, SAS Internal

    let path = DevicePath::new()
        .msg_sas(sas_address, lun, device_topology, 0x0000)
        .end();

    let display = path.display(false);
    assert!(display.contains("SAS(0x1122334455667788,SAS)/"));
}

#[test]
fn test_sas_topology_sata_internal() {
    // Test SAS with topology information - SATA Internal device
    // Bits 0:3 = 1 (topology info present)
    // Bits 4:5 = 1 (SATA Internal)
    let sas_address = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
    let lun = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    let device_topology = 0x0011; // Topology info present, SATA Internal

    let path = DevicePath::new()
        .msg_sas(sas_address, lun, device_topology, 0x0000)
        .end();

    let display = path.display(false);
    assert!(display.contains("SAS(0x1122334455667788,SATA)/"));
}

#[test]
fn test_sasex_topology_with_device_info() {
    // Test SASEx with topology information present
    let sas_address = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22];
    let lun = [0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
    // Bits 0:3 = 1 (topology info present), Bits 4:5 = 0 (SAS device)
    let device_topology_info = 0x0001;
    let rtp = 0x1234;

    let path = DevicePath::new()
        .msg_sas_ex(sas_address, lun, device_topology_info, rtp)
        .end();

    let display = path.display(false);
    assert!(display.contains("SasEx(0xAABBCCDDEEFF1122,0x0500000000000000,SAS,0x1234)/"));
}
