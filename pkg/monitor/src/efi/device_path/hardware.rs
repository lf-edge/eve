// Copyright (c) 2025-2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context};
use byteorder::{LittleEndian, ReadBytesExt};
use num_enum::{FromPrimitive, IntoPrimitive};
use std::io::{Cursor, Read};

use super::{
    traits::{NodeExpectedLength, NodeTypeValidator},
    Node, PathNodeTrait,
};

#[cfg(test)]
use super::DevicePathType;

#[derive(Debug, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum DevicePathSubTypeHardware {
    Pci = 0x1,
    PCCARD = 0x2,
    MemoryMapped = 0x3,
    Vendor = 0x4,
    Controller = 0x5,
    BMC = 0x6,
    #[num_enum(catch_all)]
    Unknown(u8),
}

impl NodeTypeValidator for DevicePathSubTypeHardware {
    fn expected_length(&self) -> NodeExpectedLength {
        match self {
            DevicePathSubTypeHardware::Pci => NodeExpectedLength::Exact(6),
            DevicePathSubTypeHardware::PCCARD => NodeExpectedLength::Exact(5),
            DevicePathSubTypeHardware::MemoryMapped => NodeExpectedLength::Exact(24),
            DevicePathSubTypeHardware::Vendor => NodeExpectedLength::Min(20),
            DevicePathSubTypeHardware::Controller => NodeExpectedLength::Exact(8),
            DevicePathSubTypeHardware::BMC => NodeExpectedLength::Exact(13),
            DevicePathSubTypeHardware::Unknown(_) => NodeExpectedLength::Min(4),
        }
    }
}

#[derive(Debug, PartialEq, Clone)]
pub(crate) enum HardwareNode {
    Pci {
        function: u8,
        device: u8,
    },
    PCCARD {
        function: u8,
    },
    MemoryMapped {
        memory_type: u32,
        start_address: u64,
        end_address: u64,
    },
    Vendor {
        guid: uuid::Uuid,
        data: Vec<u8>,
    },
    Controller {
        controller: u32,
    },
    BMC {
        interface: u8,
        base_address: u64,
    },

    Unknown(Node),
}

impl PathNodeTrait for HardwareNode {
    type Subtype = DevicePathSubTypeHardware;

    fn get_generic_name(&self) -> &'static str {
        "HardwarePath"
    }

    #[cfg(test)]
    fn get_efi_type(&self) -> DevicePathType {
        DevicePathType::Hardware
    }

    fn get_efi_sub_type(&self) -> Self::Subtype {
        match self {
            HardwareNode::Pci { .. } => DevicePathSubTypeHardware::Pci,
            HardwareNode::PCCARD { .. } => DevicePathSubTypeHardware::PCCARD,
            HardwareNode::MemoryMapped { .. } => DevicePathSubTypeHardware::MemoryMapped,
            HardwareNode::Vendor { .. } => DevicePathSubTypeHardware::Vendor,
            HardwareNode::Controller { .. } => DevicePathSubTypeHardware::Controller,
            HardwareNode::BMC { .. } => DevicePathSubTypeHardware::BMC,
            HardwareNode::Unknown(node) => DevicePathSubTypeHardware::Unknown(node.node_sub_type),
        }
    }
    fn display(&self, _display_only: bool) -> String {
        match self {
            HardwareNode::Pci { function, device } => format!("Pci({:#X},{:#X})", device, function),
            HardwareNode::PCCARD { function } => format!("PcCard({:#X})", function),
            HardwareNode::MemoryMapped {
                memory_type,
                start_address,
                end_address,
            } => format!(
                "MemoryMapped({:#X},{:#X},{:#X})",
                memory_type, start_address, end_address
            ),
            HardwareNode::Vendor { guid, data } => {
                format!("VenHw({},{})", guid, hex::encode(data))
            }
            HardwareNode::Controller { controller } => format!("Ctrl({:#X})", controller),
            HardwareNode::BMC {
                interface,
                base_address,
            } => format!("BMC({},{:#X})", interface, base_address),
            HardwareNode::Unknown(node) => format!(
                "HardwarePath({},{})",
                node.node_sub_type,
                node.data.as_ref().map_or("null".to_string(), hex::encode)
            ),
        }
    }

    fn get_data(&self) -> Option<Vec<u8>> {
        match self {
            HardwareNode::Pci { function, device } => Some(vec![*function, *device]),
            HardwareNode::PCCARD { function } => Some(vec![*function]),
            HardwareNode::MemoryMapped {
                memory_type,
                start_address,
                end_address,
            } => {
                let mut data = Vec::with_capacity(24);
                data.extend_from_slice(&memory_type.to_le_bytes());
                data.extend_from_slice(&start_address.to_le_bytes());
                data.extend_from_slice(&end_address.to_le_bytes());
                Some(data)
            }
            HardwareNode::Vendor {
                guid,
                data: vendor_data,
            } => {
                let mut data = Vec::with_capacity(20);
                data.extend_from_slice(guid.as_bytes());
                data.extend_from_slice(vendor_data.as_slice());
                Some(data)
            }
            HardwareNode::Controller { controller } => Some(controller.to_le_bytes().to_vec()),
            HardwareNode::BMC {
                interface,
                base_address,
            } => {
                let mut data = Vec::with_capacity(13);
                data.push(*interface);
                data.extend_from_slice(&base_address.to_le_bytes());
                Some(data)
            }
            HardwareNode::Unknown(node) => node.data.clone(),
        }
    }
}

impl TryFrom<&Node> for HardwareNode {
    type Error = anyhow::Error;

    fn try_from(node: &Node) -> std::result::Result<Self, Self::Error> {
        let subtype = DevicePathSubTypeHardware::from_primitive(node.node_sub_type);
        subtype.validate_length(node.node_length)?;

        match subtype {
            DevicePathSubTypeHardware::Unknown(_) => {
                // Unknown nodes can have no data if node_length == 4
                Ok(HardwareNode::Unknown(node.clone()))
            }
            _ => {
                // All known node types require data
                let data = node.data.as_ref().ok_or_else(|| {
                    anyhow!("Node data is None but node_length is {}", node.node_length)
                })?;
                let mut cursor = Cursor::new(data);

                match subtype {
                    DevicePathSubTypeHardware::Pci => Ok(HardwareNode::Pci {
                        function: cursor.read_u8().context("error reading function")?,
                        device: cursor.read_u8().context("error reading function")?,
                    }),
                    DevicePathSubTypeHardware::PCCARD => Ok(HardwareNode::PCCARD {
                        function: cursor
                            .read_u8()
                            .context("error reading function for PCCARD")?,
                    }),
                    DevicePathSubTypeHardware::MemoryMapped => Ok(HardwareNode::MemoryMapped {
                        memory_type: cursor
                            .read_u32::<LittleEndian>()
                            .context("error reading memory type")?,
                        start_address: cursor
                            .read_u64::<LittleEndian>()
                            .context("error reading start address")?,
                        end_address: cursor
                            .read_u64::<LittleEndian>()
                            .context("error reading end address")?,
                    }),
                    DevicePathSubTypeHardware::Vendor => {
                        let mut uuid_buffer: Vec<u8> = Vec::with_capacity(16);
                        let mut vendor_data = Vec::new();
                        cursor.read_exact(&mut uuid_buffer)?;
                        let guid = uuid::Uuid::from_slice(&uuid_buffer)?;
                        let _data_size = cursor.read_to_end(&mut vendor_data)?;
                        Ok(HardwareNode::Vendor {
                            guid,
                            data: vendor_data,
                        })
                    }
                    DevicePathSubTypeHardware::Controller => Ok(HardwareNode::Controller {
                        controller: cursor.read_u32::<LittleEndian>()?,
                    }),
                    DevicePathSubTypeHardware::BMC => Ok(HardwareNode::BMC {
                        interface: cursor.read_u8()?,
                        base_address: cursor.read_u64::<LittleEndian>()?,
                    }),
                    DevicePathSubTypeHardware::Unknown(_) => {
                        unreachable!("Unknown type already handled above")
                    }
                }
            }
        }
    }
}
