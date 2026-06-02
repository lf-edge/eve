// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use num_enum::{FromPrimitive, IntoPrimitive};
use std::io::{Cursor, Read, Write};
use strum::Display;

// EFE partition type
// DISK_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30050
// EFI_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30051
// IMGA_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30052
// IMGB_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30053
// CONF_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30054
// PERSIST_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30059
// INSTALLER_UUID=ad6871ee-31f9-4cf3-9e09-6f7a25c30060

use super::{
    traits::{DevicePathReadEx, DevicePathWriteEx, NodeExpectedLength, NodeTypeValidator},
    Node, PathNodeTrait,
};

#[cfg(test)]
use super::DevicePathType;

#[derive(Debug, Display, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum NodeSubTypeMedia {
    HardDrive = 0x1,
    CdromElTorito = 0x2,
    Vendor = 0x3,
    FilePath = 0x4,
    MediaProtocol = 0x5,
    // Following 2 types are not defined in UEFI 2.8 specification. See
    // Platform Initialization (PI) Specification  Volume 1:  Pre-EFI Initialization Core Interface
    // 8.3 Firmware File Media Device Path,
    FwVolFile = 0x6,
    FwVol = 0x7,
    RelativeOffsetRange = 0x8,
    RamDisk = 0x9,
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl NodeTypeValidator for NodeSubTypeMedia {
    fn expected_length(&self) -> NodeExpectedLength {
        match self {
            NodeSubTypeMedia::HardDrive => NodeExpectedLength::Exact(42),
            NodeSubTypeMedia::CdromElTorito => NodeExpectedLength::Exact(24),
            NodeSubTypeMedia::Vendor => NodeExpectedLength::Min(20),
            NodeSubTypeMedia::FilePath => NodeExpectedLength::Min(4),
            NodeSubTypeMedia::MediaProtocol => NodeExpectedLength::Exact(20),
            NodeSubTypeMedia::FwVolFile => NodeExpectedLength::Exact(20),
            NodeSubTypeMedia::FwVol => NodeExpectedLength::Exact(20),
            NodeSubTypeMedia::RelativeOffsetRange => NodeExpectedLength::Exact(24),
            NodeSubTypeMedia::RamDisk => NodeExpectedLength::Exact(38),
            NodeSubTypeMedia::Unknown(_) => NodeExpectedLength::Min(4),
        }
    }
}

#[derive(Debug, PartialEq, Clone, IntoPrimitive, FromPrimitive)]
#[repr(u8)]
pub enum PartitionType {
    Mbr = 0x1,
    Gpt = 0x2,
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl From<&PartitionType> for u8 {
    fn from(val: &PartitionType) -> Self {
        match val {
            PartitionType::Mbr => 0x1,
            PartitionType::Gpt => 0x2,
            PartitionType::Unknown(value) => *value,
        }
    }
}

impl std::fmt::Display for PartitionType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionType::Mbr => write!(f, "MBR"),
            PartitionType::Gpt => write!(f, "GPT"),
            PartitionType::Unknown(value) => write!(f, "{:02x}", value),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum PartitionSignature {
    None,
    Mbr(u16),
    Guid(uuid::Uuid),
}

impl std::fmt::Display for PartitionSignature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PartitionSignature::None => write!(f, ""),
            PartitionSignature::Mbr(value) => write!(f, "{:04x}", value),
            PartitionSignature::Guid(value) => {
                write!(f, "{}", value.as_hyphenated().to_string().to_lowercase())
            }
        }
    }
}

impl PartitionSignature {
    fn new(kind: u8, value: &[u8; 16]) -> Self {
        if kind == 1 {
            PartitionSignature::Mbr(u16::from_le_bytes([value[0], value[1]]))
        } else if kind == 2 {
            let mut cursor = Cursor::new(value);
            // we have enough data so we can unwrap
            let guid = cursor.read_efi_guid().unwrap();
            PartitionSignature::Guid(guid)
        } else {
            PartitionSignature::None
        }
    }
    fn serialize(&self) -> Vec<u8> {
        // all values must be padded to 16 bytes
        let mut data = Vec::new();
        match self {
            PartitionSignature::None => {
                data.write_all(&[0; 16]).unwrap();
            }
            PartitionSignature::Mbr(value) => {
                data.write_u16::<LittleEndian>(*value).unwrap();
                data.write_all(&[0; 14]).unwrap();
            }
            PartitionSignature::Guid(value) => {
                data.write_efi_guid(value).unwrap();
            }
        }
        data
    }
    fn signature_format(&self) -> u8 {
        match self {
            PartitionSignature::None => 0,
            PartitionSignature::Mbr(_) => 1,
            PartitionSignature::Guid(_) => 2,
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum MediaNode {
    HardDrive {
        partition_number: u32,
        partition_start: u64,
        partition_size: u64,
        signature: PartitionSignature,
        partition_format: PartitionType,
    },
    CdRom {
        boot_entry: u32,
        partition_start: u64,
        partition_size: u64,
    },
    Vendor {
        guid: uuid::Uuid,
        vendor_data: Vec<u8>,
    },
    FilePath(String),
    FvFile(uuid::Uuid),
    Fv(uuid::Uuid),
    Unknown(Node),
}

impl PathNodeTrait for MediaNode {
    type Subtype = NodeSubTypeMedia;

    fn get_generic_name(&self) -> &'static str {
        "MediaPath"
    }

    #[cfg(test)]
    fn get_efi_type(&self) -> DevicePathType {
        DevicePathType::Media
    }

    fn get_efi_sub_type(&self) -> Self::Subtype {
        match self {
            MediaNode::HardDrive { .. } => NodeSubTypeMedia::HardDrive,
            MediaNode::CdRom { .. } => NodeSubTypeMedia::CdromElTorito,
            MediaNode::Vendor { .. } => NodeSubTypeMedia::Vendor,
            MediaNode::FilePath(_) => NodeSubTypeMedia::FilePath,
            MediaNode::FvFile(_) => NodeSubTypeMedia::FwVolFile,
            MediaNode::Fv(_) => NodeSubTypeMedia::FwVol,
            MediaNode::Unknown(node) => NodeSubTypeMedia::Unknown(node.node_sub_type),
        }
    }
    fn display(&self, display: bool) -> String {
        match self {
            MediaNode::HardDrive {
                partition_number,
                partition_start,
                partition_size,
                signature,
                partition_format,
            } => {
                if display || *partition_number == 0 {
                    format!(
                        "HD({},{},{})",
                        partition_number, partition_format, signature
                    )
                } else {
                    format!(
                        "HD({},{},{},{},{})",
                        partition_number,
                        partition_format,
                        signature,
                        partition_start,
                        partition_size
                    )
                }
            }
            MediaNode::CdRom {
                boot_entry,
                partition_start,
                partition_size,
            } => {
                if display {
                    format!(
                        "CdRom({},{},{})",
                        boot_entry, partition_start, partition_size
                    )
                } else {
                    "CdRom".to_string()
                }
            }
            MediaNode::Vendor { guid, vendor_data } => {
                if display {
                    format!("Vendor({},{:?})", guid, hex::encode_upper(vendor_data))
                } else {
                    "Vendor".to_string()
                }
            }
            MediaNode::FilePath(path) => {
                // UEFI spec 2.6, 9.3.6.4 File Path Media Device Path
                // Rules for Path Name conversion:
                // • When concatenating two Path Names, ensure that the resulting string does not contain a double-
                // separator "\\". If it does, convert that double-separator to a single-separator.
                // • In the case where a Path Name which has no end separator is being concatenated to a Path Name
                // with no beginning separator, a separator will need to be inserted between the Path Names.
                // • Single file path nodes with no directory path data are presumed to have their files located in the
                // root directory of the device.

                // remove leading and trailing slashes and reconstruct the path later
                // in DevicePathDisplay::display but maybe other day. We only use this for displaying
                // let path = path.trim_matches('\\');
                // path.to_string()

                path.clone()
            }
            MediaNode::FvFile(guid) => {
                format!("FvFile({})", guid.hyphenated().to_string().to_uppercase())
            }
            MediaNode::Fv(guid) => {
                format!("Fv({})", guid.hyphenated().to_string().to_uppercase())
            }
            MediaNode::Unknown(node) => format!(
                "{}({},{})",
                self.get_generic_name(),
                node.node_sub_type,
                node.data.as_ref().map_or("null".to_string(), hex::encode)
            ),
        }
    }

    fn get_data(&self) -> Option<Vec<u8>> {
        match self {
            MediaNode::HardDrive {
                partition_number,
                partition_start,
                partition_size,
                signature,
                partition_format,
            } => {
                let mut data = Vec::new();
                data.write_u32::<LittleEndian>(*partition_number).unwrap();
                data.write_u64::<LittleEndian>(*partition_start).unwrap();
                data.write_u64::<LittleEndian>(*partition_size).unwrap();
                data.extend_from_slice(&signature.serialize());
                let partition_format: u8 = partition_format.into();
                data.push(partition_format);
                data.push(signature.signature_format());
                Some(data)
            }
            MediaNode::CdRom {
                boot_entry,
                partition_start,
                partition_size,
            } => {
                let mut data = Vec::new();
                data.write_u32::<LittleEndian>(*boot_entry).unwrap();
                data.write_u64::<LittleEndian>(*partition_start).unwrap();
                data.write_u64::<LittleEndian>(*partition_size).unwrap();
                Some(data)
            }
            MediaNode::Vendor { guid, vendor_data } => {
                let mut data = Vec::new();
                data.write_efi_guid(guid).ok()?;
                data.write_all(vendor_data).ok()?;
                Some(data)
            }
            MediaNode::FilePath(path) => {
                let mut data = Vec::new();
                data.write_as_null_terminated_ucs16(path).ok()?;
                Some(data)
            }
            MediaNode::FvFile(guid) => {
                let mut data = Vec::new();
                data.write_efi_guid(guid).ok()?;
                Some(data)
            }
            MediaNode::Fv(guid) => {
                let mut data = Vec::new();
                data.write_efi_guid(guid).ok()?;
                Some(data)
            }
            MediaNode::Unknown(node) => node.data.clone(),
        }
    }
}

impl TryFrom<&Node> for MediaNode {
    type Error = anyhow::Error;

    fn try_from(node: &Node) -> std::result::Result<Self, Self::Error> {
        let subtype = NodeSubTypeMedia::from_primitive(node.node_sub_type);

        subtype.validate_length(node.node_length)?;

        match subtype {
            NodeSubTypeMedia::Unknown(_)
            | NodeSubTypeMedia::RelativeOffsetRange
            | NodeSubTypeMedia::RamDisk
            | NodeSubTypeMedia::MediaProtocol => {
                // Unknown nodes can have no data if node_length == 4
                Ok(MediaNode::Unknown(node.clone()))
            }
            _ => {
                // All known node types require data
                let data = node.data.as_ref().ok_or_else(|| {
                    anyhow!("Node data is None but node_length is {}", node.node_length)
                })?;
                let mut cursor = Cursor::new(data);

                match subtype {
                    NodeSubTypeMedia::HardDrive => {
                        let partition_number = cursor.read_u32::<LittleEndian>()?;
                        let partition_start = cursor.read_u64::<LittleEndian>()?;
                        let partition_size = cursor.read_u64::<LittleEndian>()?;
                        let mut signature = [0; 16];
                        cursor.read_exact(&mut signature)?;
                        let partition_format = cursor.read_u8()?;
                        let signature_type = cursor.read_u8()?;
                        Ok(MediaNode::HardDrive {
                            partition_number,
                            partition_start,
                            partition_size,
                            signature: PartitionSignature::new(signature_type, &signature),
                            partition_format: PartitionType::from(partition_format),
                        })
                    }
                    NodeSubTypeMedia::CdromElTorito => Ok(MediaNode::CdRom {
                        boot_entry: cursor.read_u32::<LittleEndian>()?,
                        partition_start: cursor.read_u64::<LittleEndian>()?,
                        partition_size: cursor.read_u64::<LittleEndian>()?,
                    }),
                    NodeSubTypeMedia::Vendor => {
                        let mut vendor_data = Vec::new();
                        let guid = cursor.read_efi_guid()?;
                        let _data_size = cursor.read_to_end(&mut vendor_data)?;
                        Ok(MediaNode::Vendor { guid, vendor_data })
                    }
                    NodeSubTypeMedia::FilePath => Ok(MediaNode::FilePath(
                        cursor.read_null_terminated_ucs16_to_string()?,
                    )),
                    NodeSubTypeMedia::FwVolFile => Ok(MediaNode::FvFile(cursor.read_efi_guid()?)),
                    NodeSubTypeMedia::FwVol => Ok(MediaNode::Fv(cursor.read_efi_guid()?)),
                    NodeSubTypeMedia::RelativeOffsetRange
                    | NodeSubTypeMedia::RamDisk
                    | NodeSubTypeMedia::MediaProtocol
                    | NodeSubTypeMedia::Unknown(_) => {
                        unreachable!("Unknown types already handled above")
                    }
                }
            }
        }
    }
}
