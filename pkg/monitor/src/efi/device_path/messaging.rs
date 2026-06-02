// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use macaddr::MacAddr;
use num_enum::{FromPrimitive, IntoPrimitive};
use std::{
    io::Read,
    net::{Ipv4Addr, Ipv6Addr},
};

use super::{
    traits::{DevicePathReadEx, DevicePathWriteEx, NodeExpectedLength},
    Node, NodeTypeValidator, PathNodeTrait,
};

#[cfg(test)]
use super::DevicePathType;

#[derive(Debug, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum DevicePathSubTypeMessaging {
    Atapi = 0x1,
    Scsi = 0x2,
    FiberChannel = 0x3,
    FiberChannelEx = 21,
    //IEEE1394 = 0x4,
    Usb = 0x5,
    Sata = 18,
    UsbWwid = 0x10,
    Lun = 17,
    UsbClass = 15,
    I2O = 6,
    MacAddr = 11,
    IpV4 = 12,
    IpV6 = 13,
    IScsi = 19,
    Vlan = 20,
    // InfinitiBand = 9, 48
    // Uart = 14, 19
    Vendor = 10,
    // Following are specific Vendor GUID structs
    // UartFlowControl = 10, 24, DEVICE_PATH_MESSAGING_UART_FLOW_CONTROL
    // SAS = 10, 44, d487ddb4-008b-11d9-afdc-001083ffca4d
    // -- end of vendor structs --
    SasEx = 22,
    Nvme = 23,
    Uri = 24,
    Ufs = 25,
    Sd = 26,
    // Bluetooth = 27, 10
    // Wireless = 28, 36
    EMMC = 29,
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl NodeTypeValidator for DevicePathSubTypeMessaging {
    fn expected_length(&self) -> NodeExpectedLength {
        match self {
            DevicePathSubTypeMessaging::Atapi => NodeExpectedLength::Exact(8),
            DevicePathSubTypeMessaging::Scsi => NodeExpectedLength::Exact(8),
            DevicePathSubTypeMessaging::FiberChannel => NodeExpectedLength::Exact(24),
            DevicePathSubTypeMessaging::FiberChannelEx => NodeExpectedLength::Exact(24),
            //DevicePathSubTypeMessaging::IEEE1394 => NodeExpectedLength::Exact(16),
            DevicePathSubTypeMessaging::Usb => NodeExpectedLength::Exact(6),
            DevicePathSubTypeMessaging::Sata => NodeExpectedLength::Exact(10),
            DevicePathSubTypeMessaging::UsbWwid => NodeExpectedLength::Min(10),
            DevicePathSubTypeMessaging::Lun => NodeExpectedLength::Exact(5),
            DevicePathSubTypeMessaging::UsbClass => NodeExpectedLength::Exact(11),
            DevicePathSubTypeMessaging::I2O => NodeExpectedLength::Exact(8),
            DevicePathSubTypeMessaging::MacAddr => NodeExpectedLength::Exact(37),
            DevicePathSubTypeMessaging::IpV4 => NodeExpectedLength::Exact(27),
            DevicePathSubTypeMessaging::IpV6 => NodeExpectedLength::Exact(60),
            DevicePathSubTypeMessaging::IScsi => NodeExpectedLength::Min(38),
            DevicePathSubTypeMessaging::Vlan => NodeExpectedLength::Exact(6),
            DevicePathSubTypeMessaging::Vendor => NodeExpectedLength::Min(20), // 4 header + 16 GUID + min data
            DevicePathSubTypeMessaging::SasEx => NodeExpectedLength::Exact(32), // 4 header + 28 data (8+8+2+2+8)
            DevicePathSubTypeMessaging::Nvme => NodeExpectedLength::Exact(16),
            DevicePathSubTypeMessaging::Uri => NodeExpectedLength::Min(4),
            DevicePathSubTypeMessaging::Ufs => NodeExpectedLength::Exact(6),
            DevicePathSubTypeMessaging::Sd => NodeExpectedLength::Exact(5),
            DevicePathSubTypeMessaging::EMMC => NodeExpectedLength::Exact(5),
            DevicePathSubTypeMessaging::Unknown(_) => NodeExpectedLength::Min(4),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum MessagingNode {
    Atapi {
        primary: bool,
        slave: bool,
        lun: u16,
    },
    Scsi {
        target: u16,
        lun: u16,
    },
    FiberChannel {
        wwn: u64,
        lun: u64,
    },
    FiberChannelEx {
        //FIXME: must be 8 byte arrays
        wwn: u64,
        lun: u64,
    },
    Sata {
        hba_port: u16,
        port_multiplier_port: u16,
        lun: u16,
    },
    Usb {
        parent_port_number: u8,
        usb_interface: u8,
    },
    UsbWwid {
        interface_number: u16,
        vendor_id: u16,
        product_id: u16,
        serial: Vec<u8>,
    },
    Lun(u8),
    UsbClass {
        vendor_id: u16,
        product_id: u16,
        device_class: u8,
        device_subclass: u8,
        device_protocol: u8,
    },
    MacAddr {
        mac_addr: MacAddr,
        if_type: u8,
    },
    IpV4 {
        local_ip: Ipv4Addr,
        remote_ip: Ipv4Addr,
        local_port: u16,
        remote_port: u16,
        protocol: u16,
        is_static: bool,
        gw: Ipv4Addr,
        mask: Ipv4Addr,
    },
    IpV6 {
        local_ip: Ipv6Addr,
        remote_ip: Ipv6Addr,
        local_port: u16,
        remote_port: u16,
        protocol: u16,
        origin: u8,
        prefix_len: u8,
        gw: Ipv6Addr,
    },
    Vlan {
        vlan_id: u16,
    },
    IScsi {
        protocol: u16,
        options: u16,
        lun: u64,
        group_tag: u16,
        target: String,
    },
    Sd {
        slot: u8,
    },
    EMMC {
        slot: u8,
    },
    Vendor {
        guid: uuid::Uuid,
        vendor_data: Vec<u8>,
    },
    Sas {
        sas_address: [u8; 8],
        lun: [u8; 8],
        device_topology: u16,
        drive_topology: u16,
    },
    SasEx {
        sas_address: [u8; 8],
        reserved: [u8; 8],
        lun: [u8; 8],
        device_topology_info: u16,
        rtp: u16,
    },
    Nvme {
        namespace_id: u32,
        namespace_uuid: u64,
    },
    I2O {
        tid: u32,
    },
    Uri {
        uri: String,
    },
    Ufs {
        pun: u8,
        lun: u8,
    },
    Unknown(Node),
}

impl PathNodeTrait for MessagingNode {
    type Subtype = DevicePathSubTypeMessaging;

    fn get_generic_name(&self) -> &'static str {
        "MessagingPath"
    }

    #[cfg(test)]
    fn get_efi_type(&self) -> DevicePathType {
        DevicePathType::Messaging
    }

    fn get_efi_sub_type(&self) -> Self::Subtype {
        match self {
            MessagingNode::Atapi { .. } => DevicePathSubTypeMessaging::Atapi,
            MessagingNode::Scsi { .. } => DevicePathSubTypeMessaging::Scsi,
            MessagingNode::FiberChannel { .. } => DevicePathSubTypeMessaging::FiberChannel,
            MessagingNode::FiberChannelEx { .. } => DevicePathSubTypeMessaging::FiberChannelEx,
            MessagingNode::Sata { .. } => DevicePathSubTypeMessaging::Sata,
            MessagingNode::Usb { .. } => DevicePathSubTypeMessaging::Usb,
            MessagingNode::UsbWwid { .. } => DevicePathSubTypeMessaging::UsbWwid,
            MessagingNode::Lun(_) => DevicePathSubTypeMessaging::Lun,
            MessagingNode::UsbClass { .. } => DevicePathSubTypeMessaging::UsbClass,
            MessagingNode::MacAddr { .. } => DevicePathSubTypeMessaging::MacAddr,
            MessagingNode::IpV4 { .. } => DevicePathSubTypeMessaging::IpV4,
            MessagingNode::IpV6 { .. } => DevicePathSubTypeMessaging::IpV6,
            MessagingNode::Vlan { .. } => DevicePathSubTypeMessaging::Vlan,
            MessagingNode::IScsi { .. } => DevicePathSubTypeMessaging::IScsi,
            MessagingNode::Sd { .. } => DevicePathSubTypeMessaging::Sd,
            MessagingNode::EMMC { .. } => DevicePathSubTypeMessaging::EMMC,
            MessagingNode::Vendor { .. } => DevicePathSubTypeMessaging::Vendor,
            MessagingNode::Sas { .. } => DevicePathSubTypeMessaging::Vendor,
            MessagingNode::SasEx { .. } => DevicePathSubTypeMessaging::SasEx,
            MessagingNode::Nvme { .. } => DevicePathSubTypeMessaging::Nvme,
            MessagingNode::I2O { .. } => DevicePathSubTypeMessaging::I2O,
            MessagingNode::Uri { .. } => DevicePathSubTypeMessaging::Uri,
            MessagingNode::Ufs { .. } => DevicePathSubTypeMessaging::Ufs,
            MessagingNode::Unknown(node) => DevicePathSubTypeMessaging::Unknown(node.node_sub_type),
        }
    }
    fn display(&self, display_only: bool) -> String {
        match self {
            MessagingNode::Atapi {
                primary,
                slave,
                lun,
            } => display_atapi(display_only, primary, slave, lun),
            MessagingNode::Scsi { target, lun } => {
                format!("Scsi({},{})", target, lun)
            }
            MessagingNode::FiberChannel { wwn, lun } => {
                format!("Fibre({},{})", wwn, lun)
            }
            MessagingNode::FiberChannelEx { wwn, lun } => {
                format!("FibreEx({},{})", wwn, lun)
            }
            MessagingNode::Sata {
                hba_port,
                port_multiplier_port,
                lun,
            } => {
                format!("Sata({},{},{})", hba_port, port_multiplier_port, lun)
            }
            MessagingNode::Usb {
                parent_port_number,
                usb_interface,
            } => {
                format!("Usb({},{})", parent_port_number, usb_interface)
            }
            MessagingNode::Lun(lun) => format!("Lun({})", lun),
            MessagingNode::UsbClass {
                vendor_id,
                product_id,
                device_class,
                device_subclass,
                device_protocol,
            } => display_usb_class(
                vendor_id,
                product_id,
                device_class,
                device_subclass,
                device_protocol,
            ),
            MessagingNode::MacAddr { mac_addr, if_type } => {
                format!("MAC({},{})", mac_addr, if_type)
            }
            MessagingNode::IpV4 {
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                is_static,
                gw,
                mask,
            } => display_ip_v4(
                display_only,
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                is_static,
                gw,
                mask,
            ),
            MessagingNode::IpV6 {
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                origin,
                prefix_len,
                gw,
            } => display_ipv6(
                display_only,
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                origin,
                prefix_len,
                gw,
            ),
            MessagingNode::Vlan { vlan_id } => format!("Vlan({})", vlan_id),
            MessagingNode::IScsi {
                protocol: _,
                options: _,
                lun,
                group_tag,
                target,
            } => {
                if display_only {
                    format!("iSCSI({})", target)
                } else {
                    format!(
                        "iSCSI({},{},{})",
                        target,
                        group_tag,
                        hex::encode(lun.to_be_bytes())
                    )
                }
            }
            MessagingNode::Sd { slot } => format!("Sd({})", slot),
            MessagingNode::EMMC { slot } => format!("EMMC({})", slot),
            MessagingNode::Vendor { guid, vendor_data } => {
                format!("VenMsg({},{})", guid, hex::encode(vendor_data))
            }
            MessagingNode::Sas {
                sas_address,
                lun,
                device_topology,
                drive_topology: _,
            } => {
                // Decode topology information from device_topology field
                // Bits 0:3 = More Information field
                let more_info = device_topology & 0x0F;

                if more_info == 0 {
                    // Case 1: No topology information
                    if *lun == [0, 0, 0, 0, 0, 0, 0, 0] {
                        format!("SAS(0x{})", hex::encode_upper(sas_address))
                    } else {
                        format!(
                            "SAS(0x{},0x{})",
                            hex::encode_upper(sas_address),
                            hex::encode_upper(lun)
                        )
                    }
                } else {
                    // Case 2: Topology information is present
                    // Bits 4:5 = Device Type (0=SAS Internal, 1=SATA Internal, 2=SAS External, 3=SATA External)
                    let device_type = (device_topology >> 4) & 0x03;
                    let device_str = match device_type {
                        0 | 2 => "SAS",
                        1 | 3 => "SATA",
                        _ => "Unknown",
                    };

                    if *lun == [0, 0, 0, 0, 0, 0, 0, 0] {
                        format!("SAS(0x{},{})", hex::encode_upper(sas_address), device_str)
                    } else {
                        format!(
                            "SAS(0x{},0x{},{})",
                            hex::encode_upper(sas_address),
                            hex::encode_upper(lun),
                            device_str
                        )
                    }
                }
            }
            MessagingNode::SasEx {
                sas_address,
                reserved: _,
                lun,
                device_topology_info,
                rtp,
            } => {
                // Display SAS Address as 8 byte array in hex format
                // byte 0 first (left) to byte 7 last (right)
                let sas_addr_str = hex::encode_upper(sas_address);
                let lun_str = hex::encode_upper(lun);

                // Decode topology information
                let more_info = device_topology_info & 0x0F;

                if more_info == 0 {
                    // No topology information
                    format!(
                        "SasEx(0x{},0x{},0x{:x},0x{:x})",
                        sas_addr_str, lun_str, device_topology_info, rtp
                    )
                } else {
                    // Topology information is present
                    let device_type = (device_topology_info >> 4) & 0x03;
                    let device_str = match device_type {
                        0 | 2 => "SAS",
                        1 | 3 => "SATA",
                        _ => "NoTopology",
                    };
                    format!(
                        "SasEx(0x{},0x{},{},0x{:x})",
                        sas_addr_str, lun_str, device_str, rtp
                    )
                }
            }
            MessagingNode::Nvme {
                namespace_id,
                namespace_uuid,
            } => format!("Nvme({},{})", namespace_id, namespace_uuid),
            MessagingNode::Unknown(node) => format!(
                "{}({},{})",
                self.get_generic_name(),
                node.node_sub_type,
                node.data.as_ref().map_or("null".to_string(), hex::encode)
            ),
            MessagingNode::UsbWwid {
                interface_number,
                vendor_id,
                product_id,
                serial: _, //TODO: decode serial
            } => format!(
                "UsbWwid({},{},{},WWID)",
                vendor_id, product_id, interface_number,
            ),
            MessagingNode::I2O { tid } => format!("I2O({})", tid),
            MessagingNode::Uri { uri } => {
                if uri.is_empty() {
                    "Uri()".to_string()
                } else {
                    format!("Uri({})", uri)
                }
            }
            MessagingNode::Ufs { pun, lun } => {
                format!("UFS({},{})", pun, lun)
            }
        }
    }

    fn get_data(&self) -> Option<Vec<u8>> {
        match self {
            MessagingNode::Atapi {
                primary,
                slave,
                lun,
            } => {
                let mut data = Vec::new();
                data.push(if *primary { 0 } else { 1 });
                data.push(if *slave { 1 } else { 0 });
                data.extend_from_slice(&lun.to_le_bytes());
                Some(data)
            }
            MessagingNode::Scsi { target, lun } => {
                let mut data = Vec::new();
                data.extend_from_slice(&target.to_le_bytes());
                data.extend_from_slice(&lun.to_le_bytes());
                Some(data)
            }
            MessagingNode::FiberChannel { wwn, lun } => {
                let mut data = Vec::new();
                data.extend_from_slice(&0u32.to_le_bytes());
                data.extend_from_slice(&wwn.to_le_bytes());
                data.extend_from_slice(&lun.to_le_bytes());
                Some(data)
            }
            MessagingNode::FiberChannelEx { wwn, lun } => {
                let mut data = Vec::new();
                data.extend_from_slice(&0u32.to_le_bytes());
                data.extend_from_slice(&wwn.to_le_bytes());
                data.extend_from_slice(&lun.to_le_bytes());
                Some(data)
            }
            MessagingNode::Sata {
                hba_port,
                port_multiplier_port,
                lun,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&hba_port.to_le_bytes());
                data.extend_from_slice(&port_multiplier_port.to_le_bytes());
                data.extend_from_slice(&lun.to_le_bytes());
                Some(data)
            }
            MessagingNode::Usb {
                parent_port_number,
                usb_interface,
            } => {
                let mut data = Vec::new();
                data.push(*parent_port_number);
                data.push(*usb_interface);
                Some(data)
            }
            MessagingNode::Lun(lun) => Some(vec![*lun]),
            MessagingNode::UsbClass {
                vendor_id,
                product_id,
                device_class,
                device_subclass,
                device_protocol,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&vendor_id.to_le_bytes());
                data.extend_from_slice(&product_id.to_le_bytes());
                data.push(*device_class);
                data.push(*device_subclass);
                data.push(*device_protocol);
                Some(data)
            }
            MessagingNode::MacAddr { mac_addr, if_type } => {
                let mut data = vec![0; 32];
                if mac_addr.is_v6() {
                    data[0..6].copy_from_slice(&mac_addr.as_bytes());
                } else {
                    data[0..8].copy_from_slice(&mac_addr.as_bytes());
                }
                data.push(*if_type);
                Some(data)
            }
            MessagingNode::IpV4 {
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                is_static,
                gw,
                mask,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&local_ip.octets());
                data.extend_from_slice(&remote_ip.octets());
                data.extend_from_slice(&local_port.to_le_bytes());
                data.extend_from_slice(&remote_port.to_le_bytes());
                data.extend_from_slice(&protocol.to_le_bytes());
                data.push(if *is_static { 1 } else { 0 });
                data.extend_from_slice(&gw.octets());
                data.extend_from_slice(&mask.octets());
                Some(data)
            }
            MessagingNode::IpV6 {
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                origin,
                prefix_len,
                gw,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&local_ip.octets());
                data.extend_from_slice(&remote_ip.octets());
                data.extend_from_slice(&local_port.to_le_bytes());
                data.extend_from_slice(&remote_port.to_le_bytes());
                data.extend_from_slice(&protocol.to_le_bytes());
                data.push(*origin);
                data.push(*prefix_len);
                data.extend_from_slice(&gw.octets());
                Some(data)
            }
            MessagingNode::Vlan { vlan_id } => Some(vlan_id.to_le_bytes().to_vec()),
            MessagingNode::IScsi {
                protocol,
                options,
                lun,
                group_tag,
                target,
            } => {
                let mut data = Vec::new();
                let mut cursor = std::io::Cursor::new(&mut data);
                cursor.write_u16::<LittleEndian>(*protocol).ok()?;
                cursor.write_u16::<LittleEndian>(*options).ok()?;
                cursor.write_u64::<LittleEndian>(*lun).ok()?;
                cursor.write_u16::<LittleEndian>(*group_tag).ok()?;
                cursor.write_as_null_terminated_ascii(target).ok()?;

                Some(data)
            }
            MessagingNode::Sd { slot } => Some(vec![*slot]),
            MessagingNode::EMMC { slot } => Some(vec![*slot]),
            MessagingNode::Vendor { guid, vendor_data } => {
                let mut data = Vec::new();
                data.write_efi_guid(guid).ok()?;
                data.extend_from_slice(vendor_data);
                Some(data)
            }
            MessagingNode::Sas {
                sas_address,
                lun,
                device_topology,
                drive_topology,
            } => {
                // SAS vendor-defined messaging node with specific GUID
                // Total: 44 bytes (4 header + 16 GUID + 4 reserved + 8 SAS addr + 8 LUN + 2 device + 2 drive)
                const SAS_GUID: uuid::Uuid = uuid::uuid!("d487ddb4-008b-11d9-afdc-001083ffca4d");
                let mut data = Vec::new();
                data.write_efi_guid(&SAS_GUID).ok()?;
                data.extend_from_slice(&[0u8; 4]); // 4 bytes reserved
                data.extend_from_slice(sas_address);
                data.extend_from_slice(lun);
                data.extend_from_slice(&device_topology.to_le_bytes());
                data.extend_from_slice(&drive_topology.to_le_bytes());
                Some(data)
            }
            MessagingNode::SasEx {
                sas_address,
                reserved,
                lun,
                device_topology_info,
                rtp,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(sas_address);
                data.extend_from_slice(reserved);
                data.extend_from_slice(lun);
                data.extend_from_slice(&device_topology_info.to_le_bytes());
                data.extend_from_slice(&rtp.to_le_bytes());
                Some(data)
            }
            MessagingNode::Nvme {
                namespace_id,
                namespace_uuid,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&namespace_id.to_le_bytes());
                data.extend_from_slice(&namespace_uuid.to_le_bytes());
                Some(data)
            }
            MessagingNode::I2O { tid } => Some(tid.to_le_bytes().to_vec()),
            MessagingNode::Uri { uri } => {
                if uri.is_empty() {
                    None
                } else {
                    Some(uri.as_bytes().to_vec())
                }
            }
            MessagingNode::Ufs { pun, lun } => {
                let mut data = Vec::new();
                data.push(*pun);
                data.push(*lun);
                Some(data)
            }
            MessagingNode::Unknown(node) => node.data.clone(),
            MessagingNode::UsbWwid {
                interface_number,
                vendor_id,
                product_id,
                serial,
            } => {
                let mut data = Vec::new();
                data.extend_from_slice(&interface_number.to_le_bytes());
                data.extend_from_slice(&vendor_id.to_le_bytes());
                data.extend_from_slice(&product_id.to_le_bytes());
                data.extend_from_slice(serial);
                Some(data)
            }
        }
    }
}

fn ata_controller_display(primary: bool) -> &'static str {
    if primary {
        "Primary"
    } else {
        "Secondary"
    }
}

fn ata_drive_display(slave: bool) -> &'static str {
    if slave {
        "Slave"
    } else {
        "Master"
    }
}

fn display_atapi(display_only: bool, primary: &bool, slave: &bool, lun: &u16) -> String {
    if display_only {
        format!("Ata({})", lun)
    } else {
        format!(
            "Ata({},{},{})",
            ata_controller_display(*primary),
            ata_drive_display(*slave),
            lun
        )
    }
}

fn usb_class_to_string(class: u8) -> &'static str {
    match class {
        1 => "UsbAudio",
        2 => "UsbCDCControl",
        3 => "UsbHID",
        6 => "UsbImage",
        7 => "UsbPrinter",
        8 => "UsbMassStorage",
        9 => "UsbHub",
        10 => "UsbCDCData",
        11 => "UsbSmartCard",
        14 => "UsbVideo",
        220 => "UsbDiagnostic",
        224 => "UsbWireless",
        _ => "UsbClass",
    }
}

fn usb_class254_subclass_to_string(sub_class: u8) -> &'static str {
    match sub_class {
        1 => "UsbDeviceFirmwareUpdate",
        2 => "UsbIrdaBridge",
        3 => "UsbTestAndMeasurement",
        _ => "",
    }
}

fn display_usb_class(
    vendor_id: &u16,
    product_id: &u16,
    device_class: &u8,
    device_subclass: &u8,
    device_protocol: &u8,
) -> String {
    match device_class {
        254 => match device_subclass {
            1 | 2 | 3 => {
                let name = usb_class254_subclass_to_string(*device_subclass);
                format!("{}({},{},{})", name, vendor_id, product_id, device_protocol)
            }
            _ => format!(
                "UsbClass({},{},{},{},{})",
                vendor_id, product_id, device_class, device_subclass, device_protocol
            ),
        },
        1 | 2 | 3 | 6 | 7 | 8 | 9 | 10 | 11 | 14 | 220 | 224 => {
            let class = usb_class_to_string(*device_class);
            format!(
                "{}({},{},{},{})",
                class, vendor_id, product_id, device_subclass, device_protocol
            )
        }
        _ => format!(
            "UsbClass({},{},{},{},{})",
            vendor_id, product_id, device_class, device_subclass, device_protocol
        ),
    }
}

fn display_ipv6(
    display_only: bool,
    local_ip: &Ipv6Addr,
    remote_ip: &Ipv6Addr,
    local_port: &u16,
    remote_port: &u16,
    protocol: &u16,
    origin: &u8,
    prefix_len: &u8,
    gw: &Ipv6Addr,
) -> String {
    if display_only {
        format!("IPv6({})", remote_ip)
    } else {
        let protocol = match protocol {
            0x06 => "TCP".to_string(),
            0x11 => "UDP".to_string(),
            _ => protocol.to_string(),
        };
        let origin = match origin {
            0 => "Static".to_string(),
            1 => "StatelessAutoConfigure".to_string(),
            2 => "StatefulAutoConfigure".to_string(),
            _ => origin.to_string(),
        };
        format!(
            "IPv6({}:{},{},{},{}:{},{},{})",
            remote_ip, remote_port, protocol, origin, local_ip, local_port, gw, prefix_len
        )
    }
}

fn display_ip_v4(
    display_only: bool,
    local_ip: &Ipv4Addr,
    remote_ip: &Ipv4Addr,
    local_port: &u16,
    remote_port: &u16,
    protocol: &u16,
    is_static: &bool,
    gw: &Ipv4Addr,
    mask: &Ipv4Addr,
) -> String {
    if display_only {
        format!("IPv4({})", remote_ip)
    } else {
        let protocol = match protocol {
            0x06 => "TCP".to_string(),
            0x11 => "UDP".to_string(),
            _ => protocol.to_string(),
        };
        let is_static = if *is_static { "Static" } else { "DHCP" };
        format!(
            "IPv4({}:{},{},{},{}:{},{},{})",
            remote_ip, remote_port, protocol, is_static, local_ip, local_port, gw, mask
        )
    }
}

// FIXME: there is a note somewhere in the UEFI spec saying that MAC must be exactly
// 6 byte depends on the interface type but I cannot find this place again :)
fn parse_mac(padded_mac: [u8; 32]) -> Result<MacAddr> {
    // Check if the array is a 6-byte MAC followed by all zeros
    if padded_mac[6..].iter().all(|&b| b == 0) {
        let mac_bytes: [u8; 6] = padded_mac[0..6].try_into()?;
        MacAddr::try_from(mac_bytes).context("invalid 6-byte mac address")
    }
    // Check if it's an 8-byte EUI-64 followed by all zeros
    else if padded_mac[8..].iter().all(|&b| b == 0) {
        let mac_bytes: [u8; 8] = padded_mac[0..8].try_into()?;
        MacAddr::try_from(mac_bytes).context("invalid 8-byte mac address")
    }
    // Neither case matches
    else {
        Err(anyhow!(
            "Unexpected number of padding 0s parsing MAC address"
        ))
    }
}

impl TryFrom<&Node> for MessagingNode {
    type Error = anyhow::Error;

    fn try_from(value: &Node) -> Result<Self, Self::Error> {
        let subtype = DevicePathSubTypeMessaging::from_primitive(value.node_sub_type);
        subtype.validate_length(value.node_length)?;

        // For Unknown and Uri types, handle specially as they can have node_length == 4
        match subtype {
            DevicePathSubTypeMessaging::Unknown(_) => {
                // Unknown nodes can have no data if node_length == 4
                return Ok(MessagingNode::Unknown(value.clone()));
            }
            DevicePathSubTypeMessaging::Uri => {
                // Uri can be empty (length == 4) per RFC 3986 / UEFI spec
                if value.node_length == 4 {
                    return Ok(MessagingNode::Uri { uri: String::new() });
                }
                // URI is stored as ASCII string (not null-terminated, length-delimited)
                let data = value.data.as_ref().ok_or_else(|| {
                    anyhow!("Node data is None but node_length is {}", value.node_length)
                })?;
                // RFC 3986 URIs are ASCII (with percent-encoding for non-ASCII)
                let uri = String::from_utf8(data.clone())
                    .context("Invalid ASCII/UTF-8 in URI - URIs must be RFC 3986 compliant")?;
                return Ok(MessagingNode::Uri { uri });
            }
            _ => {
                // All other known node types require data
                let data = value.data.as_ref().ok_or_else(|| {
                    anyhow!("Node data is None but node_length is {}", value.node_length)
                })?;
                let mut cursor = std::io::Cursor::new(data);

                parse_known_messaging_node(&mut cursor, subtype)
            }
        }
    }
}

fn parse_known_messaging_node(
    cursor: &mut std::io::Cursor<&Vec<u8>>,
    subtype: DevicePathSubTypeMessaging,
) -> Result<MessagingNode> {
    match subtype {
        DevicePathSubTypeMessaging::Atapi => {
            let primary = cursor.read_u8()? == 0;
            let slave = cursor.read_u8()? == 1;
            let lun = cursor.read_u16::<LittleEndian>()?;
            Ok(MessagingNode::Atapi {
                primary,
                slave,
                lun,
            })
        }
        DevicePathSubTypeMessaging::Scsi => {
            let target = cursor.read_u16::<LittleEndian>()?;
            let lun = cursor.read_u16::<LittleEndian>()?;
            Ok(MessagingNode::Scsi { target, lun })
        }
        DevicePathSubTypeMessaging::FiberChannel => {
            let _reserved = cursor.read_u32::<LittleEndian>()?;
            // those are not just u64
            let wwn = cursor.read_u64::<LittleEndian>()?;
            let lun = cursor.read_u64::<LittleEndian>()?;
            Ok(MessagingNode::FiberChannel { wwn, lun })
        }
        DevicePathSubTypeMessaging::FiberChannelEx => {
            let _reserved = cursor.read_u32::<LittleEndian>()?;
            // those are not just u64
            let wwn = cursor.read_u64::<LittleEndian>()?;
            let lun = cursor.read_u64::<LittleEndian>()?;
            // let boot_lun = cursor.read_u64::<LittleEndian>?;
            Ok(MessagingNode::FiberChannelEx { wwn, lun })
        }
        DevicePathSubTypeMessaging::Sata => {
            let hba_port = cursor.read_u16::<LittleEndian>()?;
            let port_multiplier_port = cursor.read_u16::<LittleEndian>()?;
            let lun = cursor.read_u16::<LittleEndian>()?;
            Ok(MessagingNode::Sata {
                hba_port,
                port_multiplier_port,
                lun,
            })
        }
        DevicePathSubTypeMessaging::Usb => {
            let parent_port_number = cursor.read_u8()?;
            let usb_interface = cursor.read_u8()?;
            Ok(MessagingNode::Usb {
                parent_port_number,
                usb_interface,
            })
        }
        DevicePathSubTypeMessaging::Lun => {
            let lun = cursor.read_u8()?;
            Ok(MessagingNode::Lun(lun))
        }
        DevicePathSubTypeMessaging::UsbClass => {
            let vendor_id = cursor.read_u16::<LittleEndian>()?;
            let product_id = cursor.read_u16::<LittleEndian>()?;
            let device_class = cursor.read_u8()?;
            let device_subclass = cursor.read_u8()?;
            let device_protocol = cursor.read_u8()?;
            Ok(MessagingNode::UsbClass {
                vendor_id,
                product_id,
                device_class,
                device_subclass,
                device_protocol,
            })
        }
        DevicePathSubTypeMessaging::UsbWwid => {
            let interface_number = cursor.read_u16::<LittleEndian>()?;
            let vendor_id = cursor.read_u16::<LittleEndian>()?;
            let product_id = cursor.read_u16::<LittleEndian>()?;
            let mut serial = Vec::new();
            _ = cursor.read_to_end(&mut serial)?;
            Ok(MessagingNode::UsbWwid {
                interface_number,
                vendor_id,
                product_id,
                serial,
            })
        }
        DevicePathSubTypeMessaging::MacAddr => {
            let mut mac_addr = [0; 32];
            cursor.read_exact(&mut mac_addr)?;
            let if_type = cursor.read_u8()?;
            let mac_addr = parse_mac(mac_addr)?;
            Ok(MessagingNode::MacAddr { mac_addr, if_type })
        }
        DevicePathSubTypeMessaging::IpV4 => {
            let local_ip = Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?);
            let remote_ip = Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?);
            let local_port = cursor.read_u16::<LittleEndian>()?;
            let remote_port = cursor.read_u16::<LittleEndian>()?;
            let protocol = cursor.read_u16::<LittleEndian>()?;
            let is_static = cursor.read_u8()? == 1;
            let gw = Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?);
            let mask = Ipv4Addr::from(cursor.read_u32::<LittleEndian>()?);
            Ok(MessagingNode::IpV4 {
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                is_static,
                gw,
                mask,
            })
        }
        DevicePathSubTypeMessaging::IpV6 => {
            let local_ip = Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?);
            let remote_ip = Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?);
            let local_port = cursor.read_u16::<LittleEndian>()?;
            let remote_port = cursor.read_u16::<LittleEndian>()?;
            let protocol = cursor.read_u16::<LittleEndian>()?;
            let origin = cursor.read_u8()?;
            let prefix_len = cursor.read_u8()?;
            let gw = Ipv6Addr::from(cursor.read_u128::<LittleEndian>()?);
            Ok(MessagingNode::IpV6 {
                local_ip,
                remote_ip,
                local_port,
                remote_port,
                protocol,
                origin,
                prefix_len,
                gw,
            })
        }
        DevicePathSubTypeMessaging::IScsi => {
            let protocol = cursor.read_u16::<LittleEndian>()?;
            let options = cursor.read_u16::<LittleEndian>()?;
            let lun = cursor.read_u64::<LittleEndian>()?;
            let group_tag = cursor.read_u16::<LittleEndian>()?;
            // FIXME: it is unclear from the spec whether it is ucs16 or ascii
            let target = cursor.read_null_terminated_ascii_to_string()?;
            Ok(MessagingNode::IScsi {
                protocol,
                options,
                lun,
                group_tag,
                target,
            })
        }
        DevicePathSubTypeMessaging::Vlan => {
            let vlan_id = cursor.read_u16::<LittleEndian>()?;
            Ok(MessagingNode::Vlan { vlan_id })
        }
        DevicePathSubTypeMessaging::I2O => {
            let i2o_path_id = cursor.read_u32::<LittleEndian>()?;
            Ok(MessagingNode::I2O { tid: i2o_path_id })
        }
        DevicePathSubTypeMessaging::Nvme => {
            let namespace_id = cursor.read_u32::<LittleEndian>()?;
            let namespace_uuid = cursor.read_u64::<LittleEndian>()?;
            Ok(MessagingNode::Nvme {
                namespace_id,
                namespace_uuid,
            })
        }
        DevicePathSubTypeMessaging::Sd => {
            let slot = cursor.read_u8()?;
            Ok(MessagingNode::Sd { slot })
        }
        DevicePathSubTypeMessaging::EMMC => {
            let slot = cursor.read_u8()?;
            Ok(MessagingNode::EMMC { slot })
        }
        DevicePathSubTypeMessaging::Vendor => {
            let guid = cursor.read_efi_guid()?;
            let mut vendor_data = Vec::new();
            cursor.read_to_end(&mut vendor_data)?;

            // Check if this is a known vendor GUID (SAS)
            const SAS_GUID: uuid::Uuid = uuid::uuid!("d487ddb4-008b-11d9-afdc-001083ffca4d");
            if guid == SAS_GUID && vendor_data.len() == 24 {
                // Parse as SAS device path (24 bytes after GUID)
                let mut sas_cursor = std::io::Cursor::new(&vendor_data);
                let _reserved1 = sas_cursor.read_u32::<LittleEndian>()?;
                let mut sas_address = [0u8; 8];
                let mut lun = [0u8; 8];
                sas_cursor.read_exact(&mut sas_address)?;
                sas_cursor.read_exact(&mut lun)?;
                let device_topology = sas_cursor.read_u16::<LittleEndian>()?;
                let drive_topology = sas_cursor.read_u16::<LittleEndian>()?;
                Ok(MessagingNode::Sas {
                    sas_address,
                    lun,
                    device_topology,
                    drive_topology,
                })
            } else {
                // Generic vendor messaging node
                Ok(MessagingNode::Vendor { guid, vendor_data })
            }
        }
        DevicePathSubTypeMessaging::SasEx => {
            let mut sas_address = [0u8; 8];
            let mut reserved = [0u8; 8];
            let mut lun = [0u8; 8];
            cursor.read_exact(&mut sas_address)?;
            cursor.read_exact(&mut reserved)?;
            cursor.read_exact(&mut lun)?;
            let device_topology_info = cursor.read_u16::<LittleEndian>()?;
            let rtp = cursor.read_u16::<LittleEndian>()?;
            Ok(MessagingNode::SasEx {
                sas_address,
                reserved,
                lun,
                device_topology_info,
                rtp,
            })
        }
        DevicePathSubTypeMessaging::Ufs => {
            let pun = cursor.read_u8()?;
            let lun = cursor.read_u8()?;
            Ok(MessagingNode::Ufs { pun, lun })
        }
        DevicePathSubTypeMessaging::Uri => {
            unreachable!(
                "Uri type should be handled in try_from before calling parse_known_messaging_node"
            )
        }
        DevicePathSubTypeMessaging::Unknown(_) => {
            unreachable!("Unknown type should be handled in try_from before calling parse_known_messaging_node")
        }
    }
}
