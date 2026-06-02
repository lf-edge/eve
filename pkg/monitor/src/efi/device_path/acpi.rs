// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt};
use num_enum::{FromPrimitive, IntoPrimitive};
use std::io::Cursor;

use super::{
    traits::{DevicePathReadEx, NodeExpectedLength, NodeTypeValidator},
    Node, PathNodeTrait,
};

#[cfg(test)]
use super::DevicePathType;

#[derive(Debug, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum DevicePathSubTypeAcpi {
    Acpi = 0x1,
    ExpandedAcpi = 0x2,
    Adr = 0x3,
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl NodeTypeValidator for DevicePathSubTypeAcpi {
    fn expected_length(&self) -> NodeExpectedLength {
        match self {
            DevicePathSubTypeAcpi::Acpi => NodeExpectedLength::Exact(12),
            DevicePathSubTypeAcpi::ExpandedAcpi => NodeExpectedLength::Min(19),
            DevicePathSubTypeAcpi::Adr => NodeExpectedLength::Min(8),
            DevicePathSubTypeAcpi::Unknown(_) => NodeExpectedLength::Min(4),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum AcpiNode {
    Acpi(u32, u32),
    AcpiExpanded(u32, u32, u32, String, String, String),
    AcpiAdr(u32, Option<Vec<u32>>),
    Unknown(Node),
}

impl PathNodeTrait for AcpiNode {
    type Subtype = DevicePathSubTypeAcpi;
    fn get_generic_name(&self) -> &'static str {
        "AcpiPath"
    }

    #[cfg(test)]
    fn get_efi_type(&self) -> DevicePathType {
        DevicePathType::Acpi
    }

    fn get_efi_sub_type(&self) -> DevicePathSubTypeAcpi {
        match self {
            AcpiNode::Acpi(..) => DevicePathSubTypeAcpi::Acpi,
            AcpiNode::AcpiExpanded(..) => DevicePathSubTypeAcpi::ExpandedAcpi,
            AcpiNode::AcpiAdr(..) => DevicePathSubTypeAcpi::Adr,
            AcpiNode::Unknown(node) => DevicePathSubTypeAcpi::Unknown(node.node_sub_type),
        }
    }

    fn get_data(&self) -> Option<Vec<u8>> {
        match self {
            AcpiNode::Acpi(hid, uid) => {
                let mut data = Vec::new();
                data.extend_from_slice(&hid.to_le_bytes());
                data.extend_from_slice(&uid.to_le_bytes());
                Some(data)
            }
            AcpiNode::AcpiExpanded(hid, uid, cid, hid_str, uid_str, cid_str) => {
                let mut data = Vec::new();
                data.extend_from_slice(&hid.to_le_bytes());
                data.extend_from_slice(&uid.to_le_bytes());
                data.extend_from_slice(&cid.to_le_bytes());
                data.extend_from_slice(hid_str.as_bytes());
                data.push(0);
                data.extend_from_slice(uid_str.as_bytes());
                data.push(0);
                data.extend_from_slice(cid_str.as_bytes());
                data.push(0);
                Some(data)
            }
            AcpiNode::AcpiAdr(hid, adrs) => {
                let mut data = Vec::new();
                data.extend_from_slice(&hid.to_le_bytes());
                data.push(adrs.as_ref().unwrap().len() as u8);
                for adr in adrs.as_ref().unwrap() {
                    data.extend_from_slice(&adr.to_le_bytes());
                }
                Some(data)
            }
            AcpiNode::Unknown(node) => node.data.clone(),
        }
    }

    fn display(&self, _display_only: bool) -> String {
        match self {
            AcpiNode::Acpi(hid, uid) => eisa_id_to_acpi_device_path_string(*hid, *uid)
                .map_or(format!("Acpi({:#X},{:#X})", hid, uid), |s| {
                    format!("{}({:#X})", s, uid)
                }),
            AcpiNode::AcpiExpanded(..) => self.display_as_unknown(),
            AcpiNode::AcpiAdr(..) => self.display_as_unknown(),
            AcpiNode::Unknown(node) => format!(
                "{}({},{})",
                self.get_generic_name(),
                node.node_sub_type,
                node.data.as_ref().map_or("null".to_string(), hex::encode)
            ),
        }
    }
}

impl TryFrom<&Node> for AcpiNode {
    type Error = anyhow::Error;

    fn try_from(node: &Node) -> std::result::Result<Self, Self::Error> {
        let subtype = DevicePathSubTypeAcpi::from_primitive(node.node_sub_type);
        subtype.validate_length(node.node_length)?;

        match subtype {
            DevicePathSubTypeAcpi::Unknown(_) => {
                // Unknown nodes can have no data if node_length == 4
                Ok(AcpiNode::Unknown(node.clone()))
            }
            _ => {
                // All known node types require data
                let data = node.data.as_ref().ok_or_else(|| {
                    anyhow!("Node data is None but node_length is {}", node.node_length)
                })?;
                let mut cursor = Cursor::new(data);

                match subtype {
                    DevicePathSubTypeAcpi::Acpi => {
                        let hid = cursor.read_u32::<LittleEndian>()?;
                        let uid = cursor.read_u32::<LittleEndian>()?;
                        Ok(AcpiNode::Acpi(hid, uid))
                    }
                    DevicePathSubTypeAcpi::ExpandedAcpi => {
                        let hid = cursor.read_u32::<LittleEndian>()?;
                        let uid = cursor.read_u32::<LittleEndian>()?;
                        let cid = cursor.read_u32::<LittleEndian>()?;
                        let hid_str = cursor.read_null_terminated_ascii_to_string()?;
                        let uid_str = cursor.read_null_terminated_ascii_to_string()?;
                        let cid_str = cursor.read_null_terminated_ascii_to_string()?;
                        Ok(AcpiNode::AcpiExpanded(
                            hid, uid, cid, hid_str, uid_str, cid_str,
                        ))
                    }
                    DevicePathSubTypeAcpi::Adr => {
                        let hid = cursor.read_u32::<LittleEndian>()?;
                        let count = cursor.read_u8()?;
                        let mut adrs = Vec::new();
                        for _ in 0..count {
                            adrs.push(cursor.read_u32::<LittleEndian>()?);
                        }
                        Ok(AcpiNode::AcpiAdr(hid, Some(adrs)))
                    }
                    DevicePathSubTypeAcpi::Unknown(_) => {
                        unreachable!("Unknown type already handled above")
                    }
                }
            }
        }
    }
}

fn eisa_id_to_acpi_device_path_string(hid: u32, _uid: u32) -> Option<&'static str> {
    match hid >> 16 {
        0x0A03 => Some("PciRoot"),
        0x0A08 => Some("PcieRoot"),
        0x0604 => Some("Floppy"),
        0x0301 => Some("Keyboard"),
        0x0501 => Some("Serial"),
        0x0401 => Some("ParallelPort"),
        _ => None,
    }
}
